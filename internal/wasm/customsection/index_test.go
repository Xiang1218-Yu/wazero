package customsection_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tetratelabs/wazero/internal/wasm/customsection"
)

func newTestBuilder(t *testing.T, cfg customsection.Config) *customsection.Builder {
	t.Helper()
	b, err := customsection.NewBuilder(cfg, nil)
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	return b
}

// ingestPayload ingests one section carrying payload directly.
func ingestPayload(t *testing.T, b *customsection.Builder, name string, payload []byte, known bool) int {
	t.Helper()
	_, ordinal, indexed, err := b.Ingest(bytes.NewReader(payload), name, uint32(len(payload)), known)
	if err != nil {
		t.Fatalf("Ingest(%q): %v", name, err)
	}
	if !indexed {
		t.Fatalf("Ingest(%q): expected indexed=true", name)
	}
	return ordinal
}

func TestBuilder_OrderAndDuplicates(t *testing.T) {
	b := newTestBuilder(t, customsection.Config{})

	p0 := []byte("aaa")
	p1 := []byte("bbbb")
	p2 := []byte("cc") // duplicate name "dup"
	p3 := []byte("")   // empty payload

	o0 := ingestPayload(t, b, "a", p0, false)
	o1 := ingestPayload(t, b, "name", p1, true)
	o2 := ingestPayload(t, b, "dup", p2, false)
	o3 := ingestPayload(t, b, "dup", []byte("ddd3"), false)
	o4 := ingestPayload(t, b, "", p3, false) // empty name is valid

	if []int{o0, o1, o2, o3, o4}[0] != 0 || o4 != 4 {
		t.Fatalf("ordinals not sequential: %d %d %d %d %d", o0, o1, o2, o3, o4)
	}

	s := b.Build()
	if s.Len() != 5 {
		t.Fatalf("Len = %d", s.Len())
	}

	all := s.All()
	wantNames := []string{"a", "name", "dup", "dup", ""}
	for i, e := range all {
		if e.Name() != wantNames[i] {
			t.Fatalf("entry %d name = %q, want %q", i, e.Name(), wantNames[i])
		}
		if e.Ordinal() != i {
			t.Fatalf("entry %d ordinal = %d", i, e.Ordinal())
		}
	}

	dups := s.ByName("dup")
	if len(dups) != 2 {
		t.Fatalf("duplicate sections: got %d", len(dups))
	}
	if dups[0].Ordinal() != 2 || dups[1].Ordinal() != 3 {
		t.Fatalf("duplicate ordinals: %d, %d", dups[0].Ordinal(), dups[1].Ordinal())
	}

	if got := s.ByName("missing"); got != nil {
		t.Fatalf("missing name should return nil, got %d", len(got))
	}
}

func TestStore_DigestDefaultSHA256(t *testing.T) {
	b := newTestBuilder(t, customsection.Config{})
	payload := []byte("digest-me")
	ord := ingestPayload(t, b, "x", payload, false)
	s := b.Build()

	sum := sha256.Sum256(payload)
	e, err := s.EntryByOrdinal(ord)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(e.Digest(), sum[:]) {
		t.Fatalf("digest mismatch")
	}
	byDigest := s.ByDigest(sum[:])
	if len(byDigest) != 1 || byDigest[0].Ordinal() != ord {
		t.Fatalf("ByDigest returned %v", byDigest)
	}
	// Digest returns a copy.
	d1 := e.Digest()
	d1[0] ^= 0xff
	if bytes.Equal(e.Digest(), d1) {
		t.Fatal("Digest must return an independent copy")
	}
}

func TestStore_CustomDigest(t *testing.T) {
	cfg := customsection.Config{NewHash: func() hash.Hash { return &fixedHash{} }}
	b := newTestBuilder(t, cfg)
	ord := ingestPayload(t, b, "x", []byte("hello"), false)
	s := b.Build()
	e, err := s.EntryByOrdinal(ord)
	if err != nil {
		t.Fatal(err)
	}
	if string(e.Digest()) != "fixed" {
		t.Fatalf("custom digest = %q", e.Digest())
	}
}

type fixedHash struct{ sum []byte }

func (f *fixedHash) Write(p []byte) (int, error) { return len(p), nil }
func (f *fixedHash) Sum(b []byte) []byte         { return append(b, []byte("fixed")...) }
func (f *fixedHash) Reset()                      {}
func (f *fixedHash) Size() int                   { return 5 }
func (f *fixedHash) BlockSize() int              { return 1 }

func TestStore_ByLength(t *testing.T) {
	b := newTestBuilder(t, customsection.Config{})
	ingestPayload(t, b, "a", []byte{1}, false)
	ingestPayload(t, b, "b", []byte{1, 2}, false)
	ingestPayload(t, b, "c", make([]byte, 10), false)
	s := b.Build()

	got, err := s.ByLength(2, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("ByLength: %v", got)
	}
	if _, err := s.ByLength(-1, 0); !errors.Is(err, customsection.ErrInvalidArgument) {
		t.Fatalf("negative min: %v", err)
	}
	if _, err := s.ByLength(5, 2); !errors.Is(err, customsection.ErrInvalidArgument) {
		t.Fatalf("inverted range: %v", err)
	}
}

func TestStore_ReadAllAndRange_IndependentCopies(t *testing.T) {
	b := newTestBuilder(t, customsection.Config{})
	payload := []byte("0123456789")
	ord := ingestPayload(t, b, "x", payload, false)
	s := b.Build()

	full, err := s.CopyAll(ord)
	if err != nil {
		t.Fatal(err)
	}
	if string(full) != "0123456789" {
		t.Fatalf("full = %q", full)
	}
	for i := range full {
		full[i] = 0xff // mutate: must not corrupt the store
	}
	again, err := s.CopyAll(ord)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != "0123456789" {
		t.Fatalf("store corrupted by mutation: %q", again)
	}

	half, err := s.CopyRange(ord, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(half) != "2345" {
		t.Fatalf("range = %q", half)
	}

	for _, tc := range []struct {
		off, n int64
	}{
		{-1, 1}, {0, 11}, {10, 1}, {11, 0}, {5, 1 << 40},
	} {
		if _, err := s.CopyRange(ord, tc.off, tc.n); !errors.Is(err, customsection.ErrRange) {
			t.Fatalf("CopyRange(%d,%d) = %v, want ErrRange", tc.off, tc.n, err)
		}
	}

	if _, err := s.EntryByOrdinal(99); !errors.Is(err, customsection.ErrNotFound) {
		t.Fatalf("ordinal lookup: %v", err)
	}
}

func TestReader_IndependenceSeekAndRepeat(t *testing.T) {
	b := newTestBuilder(t, customsection.Config{})
	payload := []byte("abcdef")
	ord := ingestPayload(t, b, "x", payload, false)
	s := b.Build()

	r1, err := s.OpenReader(ord)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.OpenReader(ord)
	if err != nil {
		t.Fatal(err)
	}

	buf1 := make([]byte, 3)
	if n, _ := io.ReadFull(r1, buf1); n != 3 || string(buf1) != "abc" {
		t.Fatalf("r1 first read: %q", buf1)
	}
	// r2 must be unaffected by r1's position.
	buf2 := make([]byte, 6)
	if n, _ := io.ReadFull(r2, buf2); n != 6 || string(buf2) != "abcdef" {
		t.Fatalf("r2 read: %q", buf2)
	}
	// Mutating a caller buffer cannot affect another reader.
	for i := range buf2 {
		buf2[i] = 0
	}
	if pos, err := r1.Seek(0, io.SeekStart); err != nil || pos != 0 {
		t.Fatalf("seek: %d %v", pos, err)
	}
	if n, _ := io.ReadFull(r1, make([]byte, 6)); n != 6 {
		t.Fatalf("repeat read after seek: %d", n)
	} else {
		// Re-read into a fresh buffer to verify content.
	}
	r1.Seek(0, io.SeekStart)
	check := make([]byte, 6)
	io.ReadFull(r1, check)
	if string(check) != "abcdef" {
		t.Fatalf("content after other reader mutation: %q", check)
	}

	// Seek bounds.
	if _, err := r1.Seek(-1, io.SeekStart); !errors.Is(err, customsection.ErrRange) {
		t.Fatalf("negative seek: %v", err)
	}
	if _, err := r1.Seek(1, io.SeekEnd); !errors.Is(err, customsection.ErrRange) {
		t.Fatalf("seek past end: %v", err)
	}
	if pos, err := r1.Seek(0, io.SeekEnd); err != nil || pos != 6 {
		t.Fatalf("seek end: %d %v", pos, err)
	}
	if _, err := r1.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("EOF: %v", err)
	}

	// ReadAt does not move the reader.
	at := make([]byte, 2)
	if n, err := r2.ReadAt(at, 1); err != nil || n != 2 || string(at) != "bc" {
		t.Fatalf("ReadAt: %d %q %v", n, at, err)
	}

	if err := r1.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r1.Read(make([]byte, 1)); !errors.Is(err, customsection.ErrReaderClosed) {
		t.Fatalf("read after reader close: %v", err)
	}
	if _, err := r1.Seek(0, io.SeekStart); !errors.Is(err, customsection.ErrReaderClosed) {
		t.Fatalf("seek after reader close: %v", err)
	}
	if err := r1.Close(); err != nil { // idempotent
		t.Fatal(err)
	}
	// Closing one reader leaves the other and the store usable.
	if _, err := s.CopyAll(ord); err != nil {
		t.Fatalf("store affected by reader close: %v", err)
	}
}

type stubDecoder struct {
	version uint32
	fail    bool
	panicV  bool
	calls   int
}

func (d *stubDecoder) Version() uint32 { return d.version }
func (d *stubDecoder) Decode(meta customsection.Meta, payload []byte) (any, error) {
	d.calls++
	if d.panicV {
		panic("boom")
	}
	if d.fail {
		return nil, fmt.Errorf("decoder failure")
	}
	return string(payload) + ":" + meta.Name, nil
}

func TestStore_Decode(t *testing.T) {
	dec := &stubDecoder{version: 7}
	b := newTestBuilder(t, customsection.Config{Decoders: map[string]customsection.Decoder{"x": dec}})
	ord := ingestPayload(t, b, "x", []byte("hello"), false)
	ingestPayload(t, b, "unknown", []byte("raw"), false)
	s := b.Build()

	res, err := s.Decode(ord)
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "hello:x" || res.DecoderVersion != 7 {
		t.Fatalf("decode result: %#v", res)
	}

	// Unknown section: raw reads work, Decode does not.
	if _, err := s.Decode(1); !errors.Is(err, customsection.ErrDecoderNotFound) {
		t.Fatalf("unknown decode: %v", err)
	}
	if data, err := s.CopyAll(1); err != nil || string(data) != "raw" {
		t.Fatalf("raw read of unknown: %q %v", data, err)
	}
}

func TestStore_DecodeFailureNotCachedAndPanic(t *testing.T) {
	failing := &stubDecoder{fail: true}
	b := newTestBuilder(t, customsection.Config{Decoders: map[string]customsection.Decoder{"y": failing}})
	ord := ingestPayload(t, b, "y", []byte("p"), false)
	s := b.Build()

	for i := 0; i < 2; i++ {
		_, err := s.Decode(ord)
		var de *customsection.DecodeError
		if !errors.As(err, &de) || de.Name != "y" || de.Ordinal != ord {
			t.Fatalf("decode call %d: %v", i, err)
		}
	}
	if failing.calls != 2 {
		t.Fatalf("decoder invoked %d times, failures must not be cached", failing.calls)
	}
	// Raw reads remain usable after decode failures.
	if data, err := s.CopyAll(ord); err != nil || string(data) != "p" {
		t.Fatalf("raw read after failed decode: %q %v", data, err)
	}

	panicking := &stubDecoder{panicV: true}
	bp := newTestBuilder(t, customsection.Config{Decoders: map[string]customsection.Decoder{"z": panicking}})
	op := ingestPayload(t, bp, "z", []byte("q"), false)
	sp := bp.Build()
	if _, err := sp.Decode(op); !errors.Is(err, customsection.ErrDecoderPanic) {
		t.Fatalf("panic decode: %v", err)
	}
	if _, err := sp.CopyAll(op); err != nil {
		t.Fatalf("raw read after panic: %v", err)
	}
}

func TestBuilder_MaliciousLengthNoAllocation(t *testing.T) {
	b := newTestBuilder(t, customsection.Config{})
	// Reader has only 3 bytes left, section claims 4 GiB-1.
	r := bytes.NewReader([]byte{1, 2, 3})
	_, _, _, err := b.Ingest(r, "evil", ^uint32(0)-1, false)
	if !errors.Is(err, customsection.ErrMalformedLength) {
		t.Fatalf("got %v, want ErrMalformedLength", err)
	}
	if r.Len() != 3 {
		t.Fatalf("reader should be untouched, len=%d", r.Len())
	}
}

func TestBuilder_PerSectionLimit(t *testing.T) {
	b := newTestBuilder(t, customsection.Config{MaxSectionBytes: 4})
	payload := bytes.NewReader(make([]byte, 5))
	_, _, _, err := b.Ingest(payload, "x", 5, false)
	if !errors.Is(err, customsection.ErrSectionTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestBuilder_TotalLimit(t *testing.T) {
	// Only the total is set; the default per-section limit clamps down to it.
	b := newTestBuilder(t, customsection.Config{MaxTotalBytes: 5})
	ingestPayload(t, b, "a", make([]byte, 3), false)
	r := bytes.NewReader(make([]byte, 3))
	_, _, _, err := b.Ingest(r, "b", 3, false)
	if !errors.Is(err, customsection.ErrTotalSizeLimit) {
		t.Fatalf("got %v", err)
	}
	if r.Len() != 3 {
		t.Fatalf("reader untouched on limit: %d", r.Len())
	}
}

func TestBuilder_CountLimit(t *testing.T) {
	b := newTestBuilder(t, customsection.Config{MaxSections: 2})
	ingestPayload(t, b, "a", nil, false)
	ingestPayload(t, b, "b", nil, false)
	_, _, _, err := b.Ingest(bytes.NewReader(nil), "c", 0, false)
	if !errors.Is(err, customsection.ErrSectionCountLimit) {
		t.Fatalf("got %v", err)
	}
}

func TestBuilder_UnknownPolicies(t *testing.T) {
	// Skip: only registered names get indexed; bytes are still consumed.
	t.Run("skip consumes bytes", func(t *testing.T) {
		b := newTestBuilder(t, customsection.Config{
			UnknownPolicy: customsection.UnknownPolicySkip,
			Decoders:      map[string]customsection.Decoder{"keep": &stubDecoder{}},
		})
		// First section unknown: 2 bytes skipped. Second registered: 3 bytes.
		r := bytes.NewReader(append([]byte{1, 2}, []byte{3, 4, 5}...))
		_, ord0, indexed, err := b.Ingest(r, "unknown", 2, false)
		if err != nil || indexed {
			t.Fatalf("skip ingest: indexed=%v err=%v", indexed, err)
		}
		_, ord1, indexed, err := b.Ingest(r, "keep", 3, false)
		if err != nil || !indexed {
			t.Fatalf("registered ingest: indexed=%v err=%v", indexed, err)
		}
		s := b.Build()
		if s.Len() != 1 {
			t.Fatalf("Len=%d", s.Len())
		}
		if _, err := s.EntryByOrdinal(ord0); !errors.Is(err, customsection.ErrNotFound) {
			t.Fatalf("skipped ordinal: %v", err)
		}
		e, err := s.EntryByOrdinal(ord1)
		if err != nil || e.Name() != "keep" {
			t.Fatalf("registered entry: %#v %v", e, err)
		}
	})

	t.Run("reject", func(t *testing.T) {
		b := newTestBuilder(t, customsection.Config{
			UnknownPolicy: customsection.UnknownPolicyReject,
			Decoders:      map[string]customsection.Decoder{"keep": &stubDecoder{}},
		})
		_, _, _, err := b.Ingest(bytes.NewReader([]byte{1}), "nope", 1, false)
		if !errors.Is(err, customsection.ErrUnknownSection) {
			t.Fatalf("got %v", err)
		}
		// "name" is always accepted.
		if _, _, indexed, err := b.Ingest(bytes.NewReader([]byte{1}), "name", 1, true); err != nil || !indexed {
			t.Fatalf("name section under reject: %v %v", indexed, err)
		}
	})

	t.Run("keep default", func(t *testing.T) {
		b := newTestBuilder(t, customsection.Config{})
		ord := ingestPayload(t, b, "unknown", []byte{1}, false)
		s := b.Build()
		if _, err := s.EntryByOrdinal(ord); err != nil {
			t.Fatal(err)
		}
	})
}

func TestConfig_Validation(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  customsection.Config
	}{
		{"per section over int", customsection.Config{MaxSectionBytes: 1 << 40}},
		{"total over int", customsection.Config{MaxTotalBytes: 1 << 40}},
		{"negative count", customsection.Config{MaxSections: -1}},
		{"bad policy", customsection.Config{UnknownPolicy: 99}},
		{"nil hash factory result", customsection.Config{NewHash: func() hash.Hash { return nil }}},
		{"nil decoder", customsection.Config{Decoders: map[string]customsection.Decoder{"x": nil}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := customsection.NewBuilder(tc.cfg, nil); !errors.Is(err, customsection.ErrInvalidConfig) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestStore_CloseLifecycle(t *testing.T) {
	b := newTestBuilder(t, customsection.Config{})
	ord := ingestPayload(t, b, "x", []byte("hello"), false)
	s := b.Build()

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil { // idempotent
		t.Fatal(err)
	}
	for _, tc := range []func() error{
		func() error { _, e := s.EntryByOrdinal(ord); return e },
		func() error { _, e := s.CopyAll(ord); return e },
		func() error { _, e := s.OpenReader(ord); return e },
		func() error { _, e := s.Decode(ord); return e },
	} {
		if err := tc(); !errors.Is(err, customsection.ErrClosed) {
			t.Fatalf("got %v, want ErrClosed", err)
		}
	}
	if got := s.ByName("x"); got != nil {
		t.Fatalf("ByName after close: %v", got)
	}
}

func TestStore_ReaderAfterStoreClose(t *testing.T) {
	b := newTestBuilder(t, customsection.Config{})
	ord := ingestPayload(t, b, "x", []byte("hello"), false)
	s := b.Build()
	r, err := s.OpenReader(ord)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, customsection.ErrClosed) {
		t.Fatalf("reader read after store close: %v", err)
	}
	if _, err := r.Seek(0, io.SeekStart); !errors.Is(err, customsection.ErrClosed) {
		t.Fatalf("reader seek after store close: %v", err)
	}
}

func TestStore_RuntimeClosed(t *testing.T) {
	var runtimeClosed atomic.Uint64
	b, err := customsection.NewBuilder(customsection.Config{}, &runtimeClosed)
	if err != nil {
		t.Fatal(err)
	}
	ord := ingestPayload(t, b, "x", []byte("hi"), false)
	s := b.Build()

	if _, err := s.CopyAll(ord); err != nil {
		t.Fatalf("before runtime close: %v", err)
	}
	runtimeClosed.Store(1) // simulate Runtime.Close
	if _, err := s.CopyAll(ord); !errors.Is(err, customsection.ErrClosed) {
		t.Fatalf("after runtime close: %v", err)
	}
}

func TestStore_ConcurrentReads(t *testing.T) {
	b := newTestBuilder(t, customsection.Config{})
	var ordinals []int
	for i := 0; i < 8; i++ {
		payload := bytes.Repeat([]byte{byte('a' + i)}, 100)
		ordinals = append(ordinals, ingestPayload(t, b, fmt.Sprintf("s%d", i), payload, false))
	}
	s := b.Build()

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, ord := range ordinals {
				r, err := s.OpenReader(ord)
				if err != nil {
					t.Error(err)
					return
				}
				data, err := io.ReadAll(r)
				if err != nil {
					t.Error(err)
					return
				}
				e, err := s.EntryByOrdinal(ord)
				if err != nil {
					t.Error(err)
					return
				}
				want := bytes.Repeat([]byte{data[0]}, 100)
				if !bytes.Equal(data, want) || e.Length() != 100 {
					t.Errorf("concurrent read mismatch for ordinal %d", ord)
				}
			}
		}()
	}
	wg.Wait()
}
