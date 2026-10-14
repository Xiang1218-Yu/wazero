package wazero

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/require"
)

// encULEB128 encodes v as unsigned LEB128.
func encULEB128(v uint32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			out = append(out, b|0x80)
		} else {
			out = append(out, b)
			break
		}
	}
	return out
}

func rawSection(id byte, payload []byte) []byte {
	out := []byte{id}
	out = append(out, encULEB128(uint32(len(payload)))...)
	return append(out, payload...)
}

func rawCustom(name string, payload []byte) []byte {
	content := append(encULEB128(uint32(len(name))), []byte(name)...)
	content = append(content, payload...)
	return rawSection(0, content)
}

// indexTestBinary builds a valid module exporting "answer" (i32 -> const 42)
// with custom sections interleaved between the regular ones, including a
// duplicate name and the spec "name" section.
//
//	ordinal 0: alpha [1 2]           (before type)
//	ordinal 1: name  (module "mymod") (between type and function)
//	ordinal 2: dup   "first"          (between function and export)
//	ordinal 3: dup   "second"         (between export and code)
//	ordinal 4: beta  "0123456789"     (after code)
var testWasmHeader = []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

func indexTestBinary() []byte {
	var bin []byte
	bin = append(bin, testWasmHeader...)
	bin = append(bin, rawCustom("alpha", []byte{1, 2})...)
	// type: one () -> i32
	bin = append(bin, rawSection(1, []byte{0x01, 0x60, 0x00, 0x01, 0x7f})...)
	// name section: subsection 0 (module name) = "mymod"
	bin = append(bin, rawCustom("name", []byte{0x00, 0x06, 0x05, 'm', 'y', 'm', 'o', 'd'})...)
	// function: one func of type 0
	bin = append(bin, rawSection(3, []byte{0x01, 0x00})...)
	bin = append(bin, rawCustom("dup", []byte("first"))...)
	// export "answer" func 0
	bin = append(bin, rawSection(7, []byte{0x01, 0x06, 'a', 'n', 's', 'w', 'e', 'r', 0x00, 0x00})...)
	bin = append(bin, rawCustom("dup", []byte("second"))...)
	// code: one body with no locals, i32.const 42, end
	bin = append(bin, rawSection(10, []byte{0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b})...)
	bin = append(bin, rawCustom("beta", []byte("0123456789"))...)
	return bin
}

func indexTestRuntime(t *testing.T, config RuntimeConfig) (Runtime, CompiledModule) {
	t.Helper()
	r := NewRuntimeWithConfig(context.Background(), config)
	c, err := r.CompileModule(context.Background(), indexTestBinary())
	if err != nil {
		r.Close(context.Background())
		t.Fatalf("CompileModule: %v", err)
	}
	return r, c
}

func TestCustomSectionIndex_DisabledByDefault(t *testing.T) {
	r := NewRuntime(context.Background())
	defer r.Close(context.Background())
	c, err := r.CompileModule(context.Background(), indexTestBinary())
	require.NoError(t, err)
	require.Nil(t, c.CustomSectionIndex())

	// Enabling then passing nil keeps it disabled.
	cfg := NewRuntimeConfig().WithCustomSectionIndex(NewCustomSectionIndexConfig()).WithCustomSectionIndex(nil)
	r2 := NewRuntimeWithConfig(context.Background(), cfg)
	defer r2.Close(context.Background())
	c2, err := r2.CompileModule(context.Background(), indexTestBinary())
	require.NoError(t, err)
	require.Nil(t, c2.CustomSectionIndex())
}

func TestCustomSectionIndex_OrderAndSelection(t *testing.T) {
	r, c := indexTestRuntime(t, NewRuntimeConfigInterpreter().
		WithCustomSectionIndex(NewCustomSectionIndexConfig()))
	defer r.Close(context.Background())
	idx := c.CustomSectionIndex()
	require.NotNil(t, idx)
	require.Equal(t, 5, idx.Len())
	require.Equal(t, "mymod", c.Name())

	all := idx.Sections()
	want := []struct {
		name string
		ord  int
		len  int
	}{
		{"alpha", 0, 2}, {"name", 1, 8}, {"dup", 2, 5}, {"dup", 3, 6}, {"beta", 4, 10},
	}
	for i, w := range want {
		require.Equal(t, w.name, all[i].Name())
		require.Equal(t, w.ord, all[i].Ordinal())
		require.Equal(t, w.len, all[i].Length())
	}

	// Duplicates preserved by name.
	dups := idx.SectionsByName("dup")
	require.Equal(t, 2, len(dups))
	require.Equal(t, 2, dups[0].Ordinal())
	require.Equal(t, 3, dups[1].Ordinal())
	first, err := idx.ReadAll(dups[0])
	require.NoError(t, err)
	require.Equal(t, "first", string(first))
	second, err := idx.ReadAll(dups[1])
	require.NoError(t, err)
	require.Equal(t, "second", string(second))

	// Ordinal lookup.
	s0, err := idx.Section(0)
	require.NoError(t, err)
	require.Equal(t, "alpha", s0.Name())
	if _, err := idx.Section(42); !errors.Is(err, ErrCustomSectionNotFound) {
		t.Fatalf("Section(42) err = %v", err)
	}

	// Length selection: name payload is 8, dup second is 6, beta is 10.
	inRange, err := idx.SectionsByLength(6, 10)
	require.NoError(t, err)
	require.Equal(t, []int{1, 3, 4}, ordinals(inRange))
	if _, err := idx.SectionsByLength(9, 2); !errors.Is(err, ErrCustomSectionInvalidArgument) {
		t.Fatalf("inverted range err = %v", err)
	}

	// Digest selection (default SHA-256).
	betaSum := sha256.Sum256([]byte("0123456789"))
	byDigest := idx.SectionsByDigest(betaSum[:])
	require.Equal(t, 1, len(byDigest))
	require.Equal(t, 4, byDigest[0].Ordinal())

	// Filter composition: name + min length.
	found := idx.Find(CustomSectionFilter{MatchName: true, Name: "dup", MinLength: 6})
	require.Equal(t, []int{3}, ordinals(found))
	found = idx.Find(CustomSectionFilter{MatchOrdinal: true, Ordinal: 1})
	require.Equal(t, []int{1}, ordinals(found))
	found = idx.Find(CustomSectionFilter{Digest: betaSum[:]})
	require.Equal(t, []int{4}, ordinals(found))
}

func TestCustomSectionIndex_ReadersAreIndependent(t *testing.T) {
	r, c := indexTestRuntime(t, NewRuntimeConfigInterpreter().
		WithCustomSectionIndex(NewCustomSectionIndexConfig()))
	defer r.Close(context.Background())
	idx := c.CustomSectionIndex()

	beta := idx.SectionsByName("beta")[0]

	// Two independent readers, separate positions.
	rd1, err := idx.Open(beta)
	require.NoError(t, err)
	defer rd1.Close()
	rd2, err := idx.Open(beta)
	require.NoError(t, err)
	defer rd2.Close()

	head := make([]byte, 3)
	_, err = io.ReadFull(rd1, head)
	require.NoError(t, err)
	require.Equal(t, "012", string(head))

	all2, err := io.ReadAll(rd2)
	require.NoError(t, err)
	require.Equal(t, "0123456789", string(all2))

	// Mutating caller buffers cannot corrupt other readers.
	for i := range all2 {
		all2[i] = 'X'
	}
	_, err = rd1.Seek(0, io.SeekStart)
	require.NoError(t, err)
	again, err := io.ReadAll(rd1)
	require.NoError(t, err)
	require.Equal(t, "0123456789", string(again))

	// ReadAll / ReadRange return independent copies.
	full1, err := idx.ReadAll(beta)
	require.NoError(t, err)
	full1[0] = 0
	full2, err := idx.ReadAll(beta)
	require.NoError(t, err)
	require.Equal(t, "0123456789", string(full2))

	piece, err := idx.ReadRange(beta, 4, 3)
	require.NoError(t, err)
	require.Equal(t, "456", string(piece))
	tail, err := idx.ReadRange(beta, 7, -1)
	require.NoError(t, err)
	require.Equal(t, "789", string(tail))

	if _, err := idx.ReadRange(beta, 9, 9); !errors.Is(err, ErrCustomSectionRange) {
		t.Fatalf("out of range: %v", err)
	}
	if _, err := idx.ReadRange(beta, -1, 1); !errors.Is(err, ErrCustomSectionRange) {
		t.Fatalf("negative offset: %v", err)
	}

	// A closed reader is unusable; closing it does not affect the store.
	require.NoError(t, rd1.Close())
	if _, err := rd1.Read(make([]byte, 1)); !errors.Is(err, ErrCustomSectionReaderClosed) {
		t.Fatalf("closed reader: %v", err)
	}
	_, err = idx.ReadAll(beta)
	require.NoError(t, err)
}

type testDecoder struct {
	version uint32
	fail    bool
	mutate  bool
	calls   int
}

func (d *testDecoder) Version() uint32 { return d.version }

func (d *testDecoder) DecodeCustomSection(meta CustomSectionMeta, payload []byte) (any, error) {
	d.calls++
	if d.fail {
		return nil, errors.New("decode boom")
	}
	if d.mutate {
		for i := range payload {
			payload[i] = 0
		}
	}
	return string(payload) + "@" + meta.Name, nil
}

func TestCustomSectionIndex_TypedDecoder(t *testing.T) {
	alphaDec := &testDecoder{version: 3}
	cfg, err := NewCustomSectionIndexConfig().RegisterDecoder("alpha", alphaDec)
	require.NoError(t, err)
	r, c := indexTestRuntime(t, NewRuntimeConfigInterpreter().WithCustomSectionIndex(cfg))
	defer r.Close(context.Background())
	idx := c.CustomSectionIndex()

	res, err := idx.Decode(idx.SectionsByName("alpha")[0])
	require.NoError(t, err)
	require.Equal(t, uint32(3), res.DecoderVersion)
	require.Equal(t, "\x01\x02@alpha", res.Value)
	require.Equal(t, 0, res.Ordinal)
	require.Equal(t, 2, res.Length)
	require.Equal(t, 1, alphaDec.calls)

	// Sections without a decoder.
	if _, err := idx.Decode(idx.SectionsByName("beta")[0]); !errors.Is(err, ErrCustomSectionDecoderNotFound) {
		t.Fatalf("Decode unknown: %v", err)
	}

	// Decoder that mutates its private copy cannot corrupt later reads or
	// decodes.
	mutating := &testDecoder{mutate: true}
	cfg2, err := NewCustomSectionIndexConfig().RegisterDecoder("beta", mutating)
	require.NoError(t, err)
	r2, c2 := indexTestRuntime(t, NewRuntimeConfigInterpreter().WithCustomSectionIndex(cfg2))
	defer r2.Close(context.Background())
	idx2 := c2.CustomSectionIndex()
	_, err = idx2.Decode(idx2.SectionsByName("beta")[0])
	require.NoError(t, err)
	raw, err := idx2.ReadAll(idx2.SectionsByName("beta")[0])
	require.NoError(t, err)
	require.Equal(t, "0123456789", string(raw))
}

func TestCustomSectionIndex_DecodeFailureIsTransient(t *testing.T) {
	failing := &testDecoder{fail: true}
	cfg, err := NewCustomSectionIndexConfig().RegisterDecoder("beta", failing)
	require.NoError(t, err)
	r, c := indexTestRuntime(t, NewRuntimeConfigInterpreter().WithCustomSectionIndex(cfg))
	defer r.Close(context.Background())
	idx := c.CustomSectionIndex()
	beta := idx.SectionsByName("beta")[0]

	_, err = idx.Decode(beta)
	require.Error(t, err)
	_, err = idx.Decode(beta)
	require.Error(t, err)
	require.Equal(t, 2, failing.calls, "second attempt re-invokes decoder")
	// The index and raw reads keep working.
	raw, err := idx.ReadAll(beta)
	require.NoError(t, err)
	require.Equal(t, "0123456789", string(raw))
}

func TestCustomSectionIndex_LimitsAndMalformed(t *testing.T) {
	t.Run("per section limit", func(t *testing.T) {
		cfg := NewCustomSectionIndexConfig().WithMaxSectionBytes(4)
		r := NewRuntimeWithConfig(context.Background(), NewRuntimeConfigInterpreter().WithCustomSectionIndex(cfg))
		defer r.Close(context.Background())
		_, err := r.CompileModule(context.Background(), indexTestBinary())
		require.ErrorIs(t, err, ErrCustomSectionTooLarge)
	})
	t.Run("total limit", func(t *testing.T) {
		cfg := NewCustomSectionIndexConfig().WithMaxTotalBytes(10)
		r := NewRuntimeWithConfig(context.Background(), NewRuntimeConfigInterpreter().WithCustomSectionIndex(cfg))
		defer r.Close(context.Background())
		_, err := r.CompileModule(context.Background(), indexTestBinary())
		require.ErrorIs(t, err, ErrCustomSectionTotalLimit)
	})
	t.Run("section count limit", func(t *testing.T) {
		cfg := NewCustomSectionIndexConfig().WithMaxSections(3)
		r := NewRuntimeWithConfig(context.Background(), NewRuntimeConfigInterpreter().WithCustomSectionIndex(cfg))
		defer r.Close(context.Background())
		_, err := r.CompileModule(context.Background(), indexTestBinary())
		require.ErrorIs(t, err, ErrCustomSectionCountLimit)
	})
	t.Run("malicious declared length", func(t *testing.T) {
		// Custom section declares a ~4GiB payload but the module ends right
		// after the name. Compilation must fail without large allocation.
		var bin []byte
		bin = append(bin, testWasmHeader...)
		bin = append(bin, 0x00)
		bin = append(bin, 0xff, 0xff, 0xff, 0xff, 0x0f) // section size = MaxUint32
		bin = append(bin, 0x04, 'n', 'o', 'p', 'e')
		bin = append(bin, 0x01)
		r := NewRuntimeWithConfig(context.Background(), NewRuntimeConfigInterpreter().
			WithCustomSectionIndex(NewCustomSectionIndexConfig()))
		defer r.Close(context.Background())
		_, err := r.CompileModule(context.Background(), bin)
		require.ErrorIs(t, err, ErrCustomSectionMalformedLength)
	})
	t.Run("malicious declared name length", func(t *testing.T) {
		// Section size and name length both claim ~4GiB but the module ends
		// immediately. This must fail before any name-sized allocation.
		var bin []byte
		bin = append(bin, testWasmHeader...)
		bin = append(bin, 0x00)
		bin = append(bin, 0xff, 0xff, 0xff, 0xff, 0x0f) // section size = MaxUint32
		bin = append(bin, 0xff, 0xff, 0xff, 0xff, 0x0f) // name size = MaxUint32
		bin = append(bin, 0x00)
		r := NewRuntimeWithConfig(context.Background(), NewRuntimeConfigInterpreter().
			WithCustomSectionIndex(NewCustomSectionIndexConfig()))
		defer r.Close(context.Background())
		_, err := r.CompileModule(context.Background(), bin)
		require.ErrorIs(t, err, ErrCustomSectionMalformedLength)
	})
}

func TestCustomSectionIndex_UnknownPolicy(t *testing.T) {
	t.Run("reject unknown", func(t *testing.T) {
		cfg := NewCustomSectionIndexConfig().
			WithUnknownCustomSections(RejectUnknownCustomSections)
		r := NewRuntimeWithConfig(context.Background(), NewRuntimeConfigInterpreter().WithCustomSectionIndex(cfg))
		defer r.Close(context.Background())
		_, err := r.CompileModule(context.Background(), indexTestBinary())
		require.ErrorIs(t, err, ErrCustomSectionUnknown)
	})
	t.Run("reject with all decoders", func(t *testing.T) {
		cfg := NewCustomSectionIndexConfig().
			WithUnknownCustomSections(RejectUnknownCustomSections)
		var err error
		for _, name := range []string{"alpha", "dup", "beta"} {
			cfg, err = cfg.RegisterDecoder(name, &testDecoder{})
			require.NoError(t, err)
		}
		r, c := indexTestRuntime(t, NewRuntimeConfigInterpreter().WithCustomSectionIndex(cfg))
		defer r.Close(context.Background())
		// "name" is always indexed; alpha/dup/beta decoders registered.
		require.Equal(t, 5, c.CustomSectionIndex().Len())
	})
}

func TestCustomSectionIndex_SkipUnknown(t *testing.T) {
	cfg, err := NewCustomSectionIndexConfig().
		WithUnknownCustomSections(SkipUnknownCustomSections).
		RegisterDecoder("beta", &testDecoder{})
	require.NoError(t, err)
	r, c := indexTestRuntime(t, NewRuntimeConfigInterpreter().WithCustomSectionIndex(cfg))
	defer r.Close(context.Background())
	idx := c.CustomSectionIndex()

	// Only "name" (known spec section) and "beta" (registered) are indexed.
	require.Equal(t, 2, idx.Len())
	nameSec, err := idx.Section(1)
	require.NoError(t, err)
	require.Equal(t, "name", nameSec.Name())
	betaSec, err := idx.Section(4)
	require.NoError(t, err)
	require.Equal(t, "beta", betaSec.Name())
	if _, err := idx.Section(0); !errors.Is(err, ErrCustomSectionNotFound) {
		t.Fatalf("skipped ordinal 0: %v", err)
	}
	if _, err := idx.Section(2); !errors.Is(err, ErrCustomSectionNotFound) {
		t.Fatalf("skipped ordinal 2: %v", err)
	}
	// Module still compiled and executes normally.
	mod, err := r.InstantiateModule(context.Background(), c, NewModuleConfig().WithName("m"))
	require.NoError(t, err)
	defer mod.Close(context.Background())
	res, err := mod.ExportedFunction("answer").Call(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(42), res[0])
}

func TestCustomSectionIndex_RegisterDuplicateDecoder(t *testing.T) {
	cfg, err := NewCustomSectionIndexConfig().RegisterDecoder("x", &testDecoder{})
	require.NoError(t, err)
	_, err = cfg.RegisterDecoder("x", &testDecoder{})
	require.ErrorIs(t, err, ErrCustomSectionDuplicateDecoder)
	// Original config is unaffected (immutability).
	_, err = cfg.RegisterDecoder("y", &testDecoder{})
	require.NoError(t, err)

	// Nil decoder.
	if _, err := NewCustomSectionIndexConfig().RegisterDecoder("z", nil); err == nil {
		t.Fatal("expected error for nil decoder")
	}
}

func TestCustomSectionIndex_CompiledModuleClose(t *testing.T) {
	r, c := indexTestRuntime(t, NewRuntimeConfigInterpreter().
		WithCustomSectionIndex(NewCustomSectionIndexConfig()))
	idx := c.CustomSectionIndex()
	sec := idx.SectionsByName("beta")[0]
	reader, err := idx.Open(sec)
	require.NoError(t, err)

	require.NoError(t, c.Close(context.Background()))
	defer r.Close(context.Background())

	if _, err := idx.ReadAll(sec); !errors.Is(err, ErrCustomSectionIndexClosed) {
		t.Fatalf("read after close: %v", err)
	}
	if _, err := idx.Decode(sec); !errors.Is(err, ErrCustomSectionIndexClosed) {
		t.Fatalf("decode after close: %v", err)
	}
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, ErrCustomSectionIndexClosed) {
		t.Fatalf("reader after close: %v", err)
	}
	// Close is idempotent.
	require.NoError(t, c.Close(context.Background()))
}

func TestCustomSectionIndex_RuntimeClose(t *testing.T) {
	r, c := indexTestRuntime(t, NewRuntimeConfigInterpreter().
		WithCustomSectionIndex(NewCustomSectionIndexConfig()))
	idx := c.CustomSectionIndex()
	sec := idx.SectionsByName("beta")[0]
	reader, err := idx.Open(sec)
	require.NoError(t, err)

	require.NoError(t, r.Close(context.Background()))

	if _, err := idx.ReadAll(sec); !errors.Is(err, ErrCustomSectionIndexClosed) {
		t.Fatalf("read after runtime close: %v", err)
	}
	if _, err := reader.Seek(0, io.SeekStart); !errors.Is(err, ErrCustomSectionIndexClosed) {
		t.Fatalf("seek after runtime close: %v", err)
	}
}

func TestCustomSectionIndex_ConcurrentReads(t *testing.T) {
	r, c := indexTestRuntime(t, NewRuntimeConfigInterpreter().
		WithCustomSectionIndex(NewCustomSectionIndexConfig()))
	defer r.Close(context.Background())
	idx := c.CustomSectionIndex()

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, sec := range idx.Sections() {
				rd, err := idx.Open(sec)
				if err != nil {
					t.Error(err)
					return
				}
				data, err := io.ReadAll(rd)
				if err != nil {
					t.Error(err)
					return
				}
				again, err := idx.ReadAll(sec)
				if err != nil || !bytes.Equal(data, again) {
					t.Errorf("concurrent mismatch")
				}
				rd.Close()
			}
		}()
	}
	wg.Wait()
}

func TestCustomSectionIndex_EngineParityAndExecution(t *testing.T) {
	configs := []struct {
		name string
		cfg  RuntimeConfig
	}{
		{"interpreter", NewRuntimeConfigInterpreter()},
		{"compiler", NewRuntimeConfigCompiler()},
	}
	bin := indexTestBinary()
	for _, tc := range configs {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "compiler" && !platform.CompilerSupported() {
				t.Skip("compiler not supported")
			}
			for _, enableIndex := range []bool{false, true} {
				cfg := tc.cfg
				if enableIndex {
					cfg = cfg.WithCustomSectionIndex(NewCustomSectionIndexConfig())
				}
				r := NewRuntimeWithConfig(context.Background(), cfg)
				c, err := r.CompileModule(context.Background(), bin)
				require.NoError(t, err)

				// Execution result is identical regardless of the index.
				mod, err := r.InstantiateModule(context.Background(), c, NewModuleConfig().WithName("m"))
				require.NoError(t, err)
				res, err := mod.ExportedFunction("answer").Call(context.Background())
				require.NoError(t, err)
				require.Equal(t, uint64(42), res[0])

				if enableIndex {
					idx := c.CustomSectionIndex()
					require.NotNil(t, idx)
					require.Equal(t, 5, idx.Len())
					// Name section still decoded normally.
					require.Equal(t, "mymod", c.Name())
					mod.Close(context.Background())
				} else {
					require.Nil(t, c.CustomSectionIndex())
					mod.Close(context.Background())
				}
				require.NoError(t, r.Close(context.Background()))
			}
		})
	}
}

func TestCustomSectionIndex_LegacyCustomSectionsUnchanged(t *testing.T) {
	bin := indexTestBinary()
	collect := func(enableIndex, storeSections, dwarf bool) []struct {
		name string
		data []byte
	} {
		cfg := NewRuntimeConfigInterpreter()
		if !dwarf {
			cfg = cfg.WithDebugInfoEnabled(false)
		}
		if storeSections {
			cfg = cfg.WithCustomSections(true)
		}
		if enableIndex {
			cfg = cfg.WithCustomSectionIndex(NewCustomSectionIndexConfig())
		}
		r := NewRuntimeWithConfig(context.Background(), cfg)
		defer r.Close(context.Background())
		c, err := r.CompileModule(context.Background(), bin)
		require.NoError(t, err)
		var out []struct {
			name string
			data []byte
		}
		for _, cs := range c.CustomSections() {
			out = append(out, struct {
				name string
				data []byte
			}{cs.Name(), cs.Data()})
		}
		return out
	}

	// Index on/off must yield identical legacy CustomSections output.
	for _, dwarf := range []bool{true, false} {
		off := collect(false, false, dwarf)
		on := collect(true, false, dwarf)
		require.Equal(t, len(off), len(on))
		for i := range off {
			require.Equal(t, off[i].name, on[i].name)
			require.Equal(t, off[i].data, on[i].data)
		}
	}

	// With both legacy store and index enabled.
	both := collect(true, true, true)
	legacy := collect(false, true, true)
	require.Equal(t, len(legacy), len(both))
	for i := range legacy {
		require.Equal(t, legacy[i].name, both[i].name)
		require.Equal(t, legacy[i].data, both[i].data)
	}

	// No debug, no legacy storage: CustomSections stays empty even with the
	// index enabled.
	empty := collect(true, false, false)
	require.Equal(t, 0, len(empty))
}

func TestCustomSectionIndex_SharedCacheRuntimeIndependence(t *testing.T) {
	cache := NewCompilationCache()
	defer cache.Close(context.Background())
	cfg := NewRuntimeConfigInterpreter().
		WithCompilationCache(cache).
		WithCustomSectionIndex(NewCustomSectionIndexConfig())

	r1 := NewRuntimeWithConfig(context.Background(), cfg)
	c1, err := r1.CompileModule(context.Background(), indexTestBinary())
	require.NoError(t, err)

	r2 := NewRuntimeWithConfig(context.Background(), cfg)
	c2, err := r2.CompileModule(context.Background(), indexTestBinary())
	require.NoError(t, err)

	// Closing r1 (and its compiled module) must not invalidate r2's index.
	require.NoError(t, r1.Close(context.Background()))
	if _, err := c1.CustomSectionIndex().ReadAll(c1.CustomSectionIndex().Sections()[0]); !errors.Is(err, ErrCustomSectionIndexClosed) {
		t.Fatalf("closed runtime index: %v", err)
	}
	data, err := c2.CustomSectionIndex().ReadAll(c2.CustomSectionIndex().Sections()[0])
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2}, data)

	require.NoError(t, r2.Close(context.Background()))
}

func ordinals(sections []IndexedCustomSection) []int {
	out := make([]int, len(sections))
	for i, s := range sections {
		out[i] = s.Ordinal()
	}
	return out
}

func TestCustomSectionIndex_RefFromAnotherIndexRejected(t *testing.T) {
	r1, c1 := indexTestRuntime(t, NewRuntimeConfigInterpreter().
		WithCustomSectionIndex(NewCustomSectionIndexConfig()))
	defer r1.Close(context.Background())
	r2, c2 := indexTestRuntime(t, NewRuntimeConfigInterpreter().
		WithCustomSectionIndex(NewCustomSectionIndexConfig()))
	defer r2.Close(context.Background())

	foreign := c1.CustomSectionIndex().SectionsByName("beta")[0]
	if _, err := c2.CustomSectionIndex().ReadAll(foreign); !errors.Is(err, ErrCustomSectionNotFound) {
		t.Fatalf("foreign ref: %v", err)
	}
	if _, err := c2.CustomSectionIndex().Open(foreign); !errors.Is(err, ErrCustomSectionNotFound) {
		t.Fatalf("foreign ref open: %v", err)
	}
	if _, err := c2.CustomSectionIndex().Decode(foreign); !errors.Is(err, ErrCustomSectionNotFound) {
		t.Fatalf("foreign ref decode: %v", err)
	}
}
