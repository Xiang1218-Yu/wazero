package boundary_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tetratelabs/wazero/internal/testing/require"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	boundary "github.com/tetratelabs/wazero/experimental/boundary"
	wasi "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/internal/leb128"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/binaryencoding"
	"github.com/tetratelabs/wazero/internal/wasm"
	"github.com/tetratelabs/wazero/sys"
)

// i32Const emits a signed-LEB128 encoded i32.const instruction.
func i32Const(v uint32) []byte {
	out := []byte{wasm.OpcodeI32Const}
	return append(out, leb128.EncodeInt32(int32(v))...)
}

// ---------------------------------------------------------------------------
// test doubles
// ---------------------------------------------------------------------------

type seqReader struct {
	mu     sync.Mutex
	calls  int
	data   []byte
	offset int
}

func (r *seqReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.offset >= len(r.data) {
		for i := range p {
			p[i] = 0
		}
		return len(p), nil
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

type trackingWriter struct {
	mu    sync.Mutex
	calls int
	buf   bytes.Buffer
}

func (w *trackingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	return w.buf.Write(p)
}

// ---------------------------------------------------------------------------
// guest module:
//   run    -> i32: calls env.answer, random_get, clock_time_get, fd_write
//   trap: unreachable
//   doexit: proc_exit(42)
// ---------------------------------------------------------------------------

func boundaryGuestBinary(t *testing.T) []byte {
	const (
		i32 = wasm.ValueTypeI32
		i64 = wasm.ValueTypeI64
	)
	m := &wasm.Module{
		TypeSection: []wasm.FunctionType{
			{Results: []wasm.ValueType{i32}},                                               // 0 run/answer
			{Params: []wasm.ValueType{i32, i32}, Results: []wasm.ValueType{i32}},           // 1 random_get
			{Params: []wasm.ValueType{i32, i64, i32}, Results: []wasm.ValueType{i32}},      // 2 clock_time_get
			{Params: []wasm.ValueType{i32, i32, i32, i32}, Results: []wasm.ValueType{i32}}, // 3 fd_write
			{Params: []wasm.ValueType{i32}},                                                // 4 proc_exit
			{},                                                                             // 5 ()->()
		},
		ImportSection: []wasm.Import{
			{Module: "wasi_snapshot_preview1", Name: "random_get", Type: wasm.ExternTypeFunc, DescFunc: 1},
			{Module: "wasi_snapshot_preview1", Name: "clock_time_get", Type: wasm.ExternTypeFunc, DescFunc: 2},
			{Module: "wasi_snapshot_preview1", Name: "fd_write", Type: wasm.ExternTypeFunc, DescFunc: 3},
			{Module: "wasi_snapshot_preview1", Name: "proc_exit", Type: wasm.ExternTypeFunc, DescFunc: 4},
			{Module: "env", Name: "answer", Type: wasm.ExternTypeFunc, DescFunc: 0},
		},
		FunctionSection: []wasm.Index{0, 5, 5}, // run(5), trap(6), doexit(7)
		MemorySection:   &wasm.Memory{Min: 1, Max: 1, IsMaxEncoded: true},
		ExportSection: []wasm.Export{
			{Name: "memory", Type: wasm.ExternTypeMemory, Index: 0},
			{Name: "run", Type: wasm.ExternTypeFunc, Index: 5},
			{Name: "trap", Type: wasm.ExternTypeFunc, Index: 6},
			{Name: "doexit", Type: wasm.ExternTypeFunc, Index: 7},
		},
	}

	var run []byte
	run = append(run, wasm.OpcodeCall, 4) // answer -> i32
	run = append(run, i32Const(0)...)
	run = append(run, i32Const(8)...)
	run = append(run, wasm.OpcodeCall, 0, wasm.OpcodeDrop) // random_get(0,8)
	run = append(run, i32Const(0)...)
	run = append(run, wasm.OpcodeI64Const, 0)
	run = append(run, i32Const(16)...)
	run = append(run, wasm.OpcodeCall, 1, wasm.OpcodeDrop) // clock_time_get(0,0,16)
	run = append(run, i32Const(1)...)
	run = append(run, i32Const(128)...)
	run = append(run, i32Const(1)...)
	run = append(run, i32Const(64)...)
	run = append(run, wasm.OpcodeCall, 2, wasm.OpcodeDrop) // fd_write(1,128,1,64)
	run = append(run, i32Const(100)...)
	run = append(run, wasm.OpcodeI32Add)
	run = append(run, wasm.OpcodeEnd)

	trapBody := []byte{wasm.OpcodeUnreachable, wasm.OpcodeEnd}

	var doexit []byte
	doexit = append(doexit, i32Const(42)...)
	doexit = append(doexit, wasm.OpcodeCall, 3, wasm.OpcodeEnd)

	m.CodeSection = []wasm.Code{{Body: run}, {Body: trapBody}, {Body: doexit}}

	// Segment loaded at memory 128: iov at +0 (ptr=256,len=6), string at +128.
	init := make([]byte, 128+6)
	binary.LittleEndian.PutUint32(init[0:], 256)
	binary.LittleEndian.PutUint32(init[4:], 6)
	copy(init[128:], "hello\n")
	m.DataSection = []wasm.DataSegment{{
		OffsetExpression: wasm.NewConstantExpressionFromI32(128),
		Init:             init,
	}}

	require.NoError(t, m.Validate(api.CoreFeaturesV2))
	return binaryencoding.EncodeModule(m)
}

func addGuestBinary(t *testing.T) []byte {
	m := &wasm.Module{
		TypeSection: []wasm.FunctionType{
			{Params: []wasm.ValueType{wasm.ValueTypeI32, wasm.ValueTypeI32}, Results: []wasm.ValueType{wasm.ValueTypeI32}},
		},
		FunctionSection: []wasm.Index{0},
		ExportSection: []wasm.Export{
			{Name: "add", Type: wasm.ExternTypeFunc, Index: 0},
		},
		CodeSection: []wasm.Code{{Body: []byte{
			wasm.OpcodeLocalGet, 0,
			wasm.OpcodeLocalGet, 1,
			wasm.OpcodeI32Add,
			wasm.OpcodeEnd,
		}}},
	}
	require.NoError(t, m.Validate(api.CoreFeaturesV2))
	return binaryencoding.EncodeModule(m)
}

// ---------------------------------------------------------------------------
// environment setup
// ---------------------------------------------------------------------------

type recordEnv struct {
	rand   *seqReader
	stdout *trackingWriter
}

func newRecordEnv() *recordEnv {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(10 + i)
	}
	return &recordEnv{rand: &seqReader{data: data}, stdout: new(trackingWriter)}
}

func (e *recordEnv) moduleConfig() wazero.ModuleConfig {
	wallCalls := 0
	return wazero.NewModuleConfig().
		WithRandSource(e.rand).
		WithWalltime(func() (int64, int32) { wallCalls++; return 1700000000 + int64(wallCalls), 0 }, 1000).
		WithNanotime(func() int64 { return 1 }, 1).
		WithStdout(e.stdout)
}

func setupArmedRuntime(t *testing.T, ctx context.Context, rc wazero.RuntimeConfig) (wazero.Runtime, *int32) {
	r := wazero.NewRuntimeWithConfig(ctx, rc)
	t.Cleanup(func() { _ = r.Close(ctx) })
	var answerCalls int32
	envAnswer := func() uint32 {
		atomic.AddInt32(&answerCalls, 1)
		return 7
	}
	_, err := r.NewHostModuleBuilder("env").
		NewFunctionBuilder().WithFunc(envAnswer).Export("answer").
		Instantiate(ctx)
	require.NoError(t, err)
	_, err = wasi.NewBuilder(r).Instantiate(ctx)
	require.NoError(t, err)
	return r, &answerCalls
}

func engineConfigs() []struct {
	name string
	rc   wazero.RuntimeConfig
} {
	out := []struct {
		name string
		rc   wazero.RuntimeConfig
	}{{name: "interpreter", rc: wazero.NewRuntimeConfigInterpreter()}}
	if platform.CompilerSupports(api.CoreFeaturesV2) {
		out = append(out, struct {
			name string
			rc   wazero.RuntimeConfig
		}{name: "compiler", rc: wazero.NewRuntimeConfigCompiler()})
	}
	return out
}

// ---------------------------------------------------------------------------
// happy path: record then replay, both engines
// ---------------------------------------------------------------------------

func TestBoundaryRecordReplay(t *testing.T) {
	ctx := context.Background()
	guestBin := boundaryGuestBinary(t)

	for _, engine := range engineConfigs() {
		engine := engine
		t.Run(engine.name, func(t *testing.T) {
			// --- record ---
			var log bytes.Buffer
			rec := boundary.NewRecorder(&log)
			rCtx := rec.Attach(ctx)
			rtR, answerR := setupArmedRuntime(t, rCtx, engine.rc)

			envR := newRecordEnv()
			cmR, err := rtR.CompileModule(rCtx, guestBin)
			require.NoError(t, err)
			modR, err := rtR.InstantiateModule(rCtx, cmR, envR.moduleConfig())
			require.NoError(t, err)

			res, err := rec.Call(rCtx, modR.ExportedFunction("run"))
			require.NoError(t, err)
			require.Equal(t, uint64(107), res[0])

			memR := modR.Memory()
			randBytes, ok := memR.Read(0, 8)
			require.True(t, ok)
			require.Equal(t, []byte{10, 11, 12, 13, 14, 15, 16, 17}, randBytes)
			ts, ok := memR.ReadUint64Le(16)
			require.True(t, ok)
			require.Equal(t, uint64(1700000001)*uint64(1e9), ts)
			require.Equal(t, "hello\n", envR.stdout.buf.String())
			require.Equal(t, int32(1), atomic.LoadInt32(answerR))

			_, err = rec.Call(rCtx, modR.ExportedFunction("trap"))
			require.Error(t, err)
			require.Contains(t, err.Error(), "unreachable")

			_, err = rec.Call(rCtx, modR.ExportedFunction("doexit"))
			var exit *sys.ExitError
			require.True(t, errors.As(err, &exit))
			require.Equal(t, uint32(42), exit.ExitCode())

			require.NoError(t, rec.Close())

			// --- replay ---
			rp, err := boundary.NewReplayer(bytes.NewReader(log.Bytes()))
			require.NoError(t, err)
			pCtx := rp.Attach(ctx)
			rtP, answerP := setupArmedRuntime(t, pCtx, engine.rc)

			replayWall := 0
			outReplay := new(trackingWriter)
			mcP := wazero.NewModuleConfig().
				WithRandSource(&seqReader{data: bytes.Repeat([]byte{0xFF}, 32)}).
				WithWalltime(func() (int64, int32) { replayWall++; return 999, 0 }, 1000).
				WithNanotime(func() int64 { return 999 }, 1).
				WithStdout(outReplay)

			cmP, err := rtP.CompileModule(pCtx, guestBin)
			require.NoError(t, err)
			require.NoError(t, rp.Verify(guestBin, cmP))
			modP, err := rtP.InstantiateModule(pCtx, cmP, mcP)
			require.NoError(t, err)

			res2, err := rp.Call(pCtx, modP.ExportedFunction("run"))
			require.NoError(t, err)
			require.Equal(t, []uint64{107}, res2)

			rb2, _ := modP.Memory().Read(0, 8)
			require.Equal(t, []byte{10, 11, 12, 13, 14, 15, 16, 17}, rb2)
			ts2, _ := modP.Memory().ReadUint64Le(16)
			require.Equal(t, uint64(1700000001)*uint64(1e9), ts2)

			// Generic user host function never re-executes on replay.
			require.Zero(t, atomic.LoadInt32(answerP))
			// Host-provided walltime and stdout are never re-invoked.
			require.Zero(t, replayWall)
			require.Zero(t, outReplay.calls)
			require.Zero(t, outReplay.buf.Len())

			_, err = rp.Call(pCtx, modP.ExportedFunction("trap"))
			require.Error(t, err)
			require.Contains(t, err.Error(), "unreachable")

			_, err = rp.Call(pCtx, modP.ExportedFunction("doexit"))
			require.True(t, errors.As(err, &exit))
			require.Equal(t, uint32(42), exit.ExitCode())

			require.NoError(t, rp.Close())
		})
	}
}

// ---------------------------------------------------------------------------
// deterministic file reads: stdout side effect not re-triggered
// ---------------------------------------------------------------------------

func TestBoundaryFileIO(t *testing.T) {
	if !platform.CompilerSupports(api.CoreFeaturesV2) {
		t.Skip("compiler unsupported on this platform")
	}
	ctx := context.Background()

	guestBin, err := os.ReadFile(filepath.Join("..", "..", "cmd", "wazero", "testdata", "wasi_fd.wasm"))
	require.NoError(t, err)

	dir := t.TempDir()
	content := strings.Repeat("bear", 20) // 80 bytes > the 50 byte read
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bear.txt"), []byte(content), 0o600))

	recordOnce := func() ([]byte, []byte) {
		var log bytes.Buffer
		out := new(trackingWriter)
		rec := boundary.NewRecorder(&log)
		sCtx := rec.Attach(ctx)
		rt, _ := setupArmedRuntime(t, sCtx, wazero.NewRuntimeConfigCompiler())
		mc := wazero.NewModuleConfig().
			WithStdout(out).
			WithFSConfig(wazero.NewFSConfig().WithDirMount(dir, ""))
		cm, err := rt.CompileModule(sCtx, guestBin)
		require.NoError(t, err)
		mod, err := rt.InstantiateModule(sCtx, cm, mc) // runs _start
		require.NoError(t, err)
		require.NoError(t, rec.Close())
		data, _ := mod.Memory().Read(100, 50)
		return append([]byte(nil), data...), log.Bytes()
	}

	replayOnce := func(log []byte) ([]byte, *trackingWriter) {
		out := new(trackingWriter)
		rp, err := boundary.NewReplayer(bytes.NewReader(log))
		require.NoError(t, err)
		sCtx := rp.Attach(ctx)
		rt, _ := setupArmedRuntime(t, sCtx, wazero.NewRuntimeConfigCompiler())
		mc := wazero.NewModuleConfig().
			WithStdout(out).
			WithFSConfig(wazero.NewFSConfig().WithDirMount(dir, ""))
		cm, err := rt.CompileModule(sCtx, guestBin)
		require.NoError(t, err)
		mod, err := rt.InstantiateModule(sCtx, cm, mc)
		require.NoError(t, err)
		require.NoError(t, rp.Close())
		data, _ := mod.Memory().Read(100, 50)
		return append([]byte(nil), data...), out
	}

	recorded, logBytes := recordOnce()
	require.Equal(t, content[:50], string(recorded))

	replayed, replayOut := replayOnce(logBytes)
	require.Equal(t, content[:50], string(replayed))
	require.Zero(t, replayOut.calls, "stdout side effect was re-triggered on replay")
}

// ---------------------------------------------------------------------------
// structured errors
// ---------------------------------------------------------------------------

func requireReplayError(t *testing.T, err error, kind boundary.ErrorKind) *boundary.ReplayError {
	t.Helper()
	var re *boundary.ReplayError
	if !errors.As(err, &re) {
		t.Fatalf("expected *boundary.ReplayError(%s), got %T: %v", kind, err, err)
	}
	require.Equal(t, kind, re.Kind)
	return re
}

func TestBoundaryReplayErrors(t *testing.T) {
	ctx := context.Background()
	guestBin := boundaryGuestBinary(t)
	addBin := addGuestBinary(t)

	var goodLog bytes.Buffer
	{
		rec := boundary.NewRecorder(&goodLog)
		rCtx := rec.Attach(ctx)
		rt, _ := setupArmedRuntime(t, rCtx, wazero.NewRuntimeConfigInterpreter())
		cm, err := rt.CompileModule(rCtx, guestBin)
		require.NoError(t, err)
		mod, err := rt.InstantiateModule(rCtx, cm, newRecordEnv().moduleConfig())
		require.NoError(t, err)
		_, err = rec.Call(rCtx, mod.ExportedFunction("run"))
		require.NoError(t, err)
		require.NoError(t, rec.Close())
	}

	t.Run("module digest mismatch", func(t *testing.T) {
		rp, err := boundary.NewReplayer(bytes.NewReader(goodLog.Bytes()))
		require.NoError(t, err)
		pCtx := rp.Attach(ctx)
		rt, _ := setupArmedRuntime(t, pCtx, wazero.NewRuntimeConfigInterpreter())
		_, err = rt.CompileModule(pCtx, addBin)
		requireReplayError(t, err, boundary.KindModuleDigest)
	})

	t.Run("module config mismatch", func(t *testing.T) {
		rp, err := boundary.NewReplayer(bytes.NewReader(goodLog.Bytes()))
		require.NoError(t, err)
		pCtx := rp.Attach(ctx)
		rt, _ := setupArmedRuntime(t, pCtx, wazero.NewRuntimeConfigInterpreter())
		cm, err := rt.CompileModule(pCtx, guestBin)
		require.NoError(t, err)
		_, err = rt.InstantiateModule(pCtx, cm, wazero.NewModuleConfig().WithArgs("different"))
		requireReplayError(t, err, boundary.KindModuleConfig)
	})

	t.Run("truncated and corrupt logs", func(t *testing.T) {
		raw := goodLog.Bytes()
		_, err := boundary.NewReplayer(bytes.NewReader(raw[:len(raw)-9]))
		requireReplayError(t, err, boundary.KindLogTruncated)

		bad := append([]byte(nil), raw...)
		bad[len(bad)-40] ^= 0xFF
		if _, err := boundary.NewReplayer(bytes.NewReader(bad)); err != nil {
			requireReplayError(t, err, boundary.KindTrailer)
		}
	})

	t.Run("call order change", func(t *testing.T) {
		rp, err := boundary.NewReplayer(bytes.NewReader(goodLog.Bytes()))
		require.NoError(t, err)
		pCtx := rp.Attach(ctx)
		rt, _ := setupArmedRuntime(t, pCtx, wazero.NewRuntimeConfigInterpreter())
		cm, err := rt.CompileModule(pCtx, guestBin)
		require.NoError(t, err)
		mod, err := rt.InstantiateModule(pCtx, cm, newRecordEnv().moduleConfig())
		require.NoError(t, err)
		_, err = rp.Call(pCtx, mod.ExportedFunction("trap"))
		requireReplayError(t, err, boundary.KindCallOrder)
	})

	t.Run("context canceled", func(t *testing.T) {
		rc := wazero.NewRuntimeConfigInterpreter().WithCloseOnContextDone(true)
		var cancelLog bytes.Buffer
		rec := boundary.NewRecorder(&cancelLog)
		rCtx := rec.Attach(ctx)
		rtR, _ := setupArmedRuntime(t, rCtx, rc)
		cm, err := rtR.CompileModule(rCtx, guestBin)
		require.NoError(t, err)
		mod, err := rtR.InstantiateModule(rCtx, cm, newRecordEnv().moduleConfig())
		require.NoError(t, err)
		_, err = rec.Call(rCtx, mod.ExportedFunction("run"))
		require.NoError(t, err)
		require.NoError(t, rec.Close())

		rp2, err := boundary.NewReplayer(bytes.NewReader(cancelLog.Bytes()))
		require.NoError(t, err)
		pCtx := rp2.Attach(ctx)
		rtP, _ := setupArmedRuntime(t, pCtx, rc)
		cm2, err := rtP.CompileModule(pCtx, guestBin)
		require.NoError(t, err)
		mcP := wazero.NewModuleConfig().
			WithRandSource(&seqReader{data: bytes.Repeat([]byte{1}, 32)}).
			WithWalltime(func() (int64, int32) { return 1, 0 }, 1000).
			WithNanotime(func() int64 { return 1 }, 1).
			WithStdout(new(trackingWriter))
		mod2, err := rtP.InstantiateModule(pCtx, cm2, mcP)
		require.NoError(t, err)

		canceledCtx, cancel := context.WithCancel(pCtx)
		cancel()
		_, err = rp2.Call(canceledCtx, mod2.ExportedFunction("run"))
		requireReplayError(t, err, boundary.KindContextCanceled)
	})

	// resignLog recomputes the trailer whole-log digest after a frame body
	// was tampered, so semantic per-event verification is exercised instead
	// of the transport-level trailer check.
	resignLog := func(raw []byte) []byte {
		out := append([]byte(nil), raw...)
		// locate trailer (last frame)
		off := 0
		for {
			n := int(binary.LittleEndian.Uint32(out[off+1:]))
			next := off + 5 + n
			if next == len(out) {
				break
			}
			off = next
		}
		sum := sha256.Sum256(out[:off])
		copy(out[off+5+8:], sum[:]) // trailer payload: u64 count, then [32]sha
		return out
	}

	// event-level tampering: mutate a recorded frame body.
	t.Run("tampered read and write events", func(t *testing.T) {
		parseFrames := func(raw []byte) []struct {
			typ        byte
			off        int
			payloadOff int
		} {
			var out []struct {
				typ             byte
				off, payloadOff int
			}
			off := 0
			for off+5 < len(raw) {
				typ := raw[off]
				n := int(binary.LittleEndian.Uint32(raw[off+1:]))
				if typ == 5 {
					break
				}
				out = append(out, struct {
					typ             byte
					off, payloadOff int
				}{typ, off, off + 5})
				off += 5 + n
			}
			return out
		}

		// read overflow: change the requested length in the evBytes frame.
		badRead := append([]byte(nil), goodLog.Bytes()...)
		for _, f := range parseFrames(badRead) {
			if f.typ == 0x11 { // evBytes
				badRead[f.payloadOff+20+1+4+8] ^= 0x01 // requested u32 low byte
				break
			}
		}
		badRead = resignLog(badRead)
		rp, err := boundary.NewReplayer(bytes.NewReader(badRead))
		require.NoError(t, err)
		pCtx := rp.Attach(ctx)
		rt, _ := setupArmedRuntime(t, pCtx, wazero.NewRuntimeConfigInterpreter())
		cm, err := rt.CompileModule(pCtx, guestBin)
		require.NoError(t, err)
		mod, err := rt.InstantiateModule(pCtx, cm, newRecordEnv().moduleConfig())
		require.NoError(t, err)
		_, err = rp.Call(pCtx, mod.ExportedFunction("run"))
		requireReplayError(t, err, boundary.KindReadOverflow)

		// write side effect: flip one digest byte inside the evWrite frame.
		badWrite := append([]byte(nil), goodLog.Bytes()...)
		for _, f := range parseFrames(badWrite) {
			if f.typ == 0x12 { // evWrite
				badWrite[f.payloadOff+20+1+4+8+4] ^= 0xFF // first digest byte
				break
			}
		}
		badWrite = resignLog(badWrite)
		rp2, err := boundary.NewReplayer(bytes.NewReader(badWrite))
		require.NoError(t, err)
		wCtx := rp2.Attach(ctx)
		rt2, _ := setupArmedRuntime(t, wCtx, wazero.NewRuntimeConfigInterpreter())
		cm2, err := rt2.CompileModule(wCtx, guestBin)
		require.NoError(t, err)
		mod2, err := rt2.InstantiateModule(wCtx, cm2, newRecordEnv().moduleConfig())
		require.NoError(t, err)
		_, err = rp2.Call(wCtx, mod2.ExportedFunction("run"))
		requireReplayError(t, err, boundary.KindSideEffect)
	})

	t.Run("unknown event type", func(t *testing.T) {
		bad := append([]byte(nil), goodLog.Bytes()...)
		// first event frame type byte at offset 462 (after 4 preface frames);
		// find it dynamically instead.
		off := 0
		for i := 0; i < 4; i++ {
			n := int(binary.LittleEndian.Uint32(bad[off+1:]))
			off += 5 + n
		}
		bad[off] = 0x7F
		_, err := boundary.NewReplayer(bytes.NewReader(bad))
		requireReplayError(t, err, boundary.KindUnknownEventType)
	})

	t.Run("unconsumed events on close", func(t *testing.T) {
		rp, err := boundary.NewReplayer(bytes.NewReader(goodLog.Bytes()))
		require.NoError(t, err)
		pCtx := rp.Attach(ctx)
		rt, _ := setupArmedRuntime(t, pCtx, wazero.NewRuntimeConfigInterpreter())
		cm, err := rt.CompileModule(pCtx, guestBin)
		require.NoError(t, err)
		_, err = rt.InstantiateModule(pCtx, cm, newRecordEnv().moduleConfig())
		require.NoError(t, err)
		// no Call: the recorded boundary events remain unconsumed.
		requireReplayError(t, rp.Close(), boundary.KindCallOrder)
	})

	t.Run("parameter mismatch", func(t *testing.T) {
		var l bytes.Buffer
		rec := boundary.NewRecorder(&l)
		rCtx := rec.Attach(ctx)
		rt := wazero.NewRuntime(rCtx)
		t.Cleanup(func() { _ = rt.Close(ctx) })
		cm, err := rt.CompileModule(rCtx, addBin)
		require.NoError(t, err)
		mod, err := rt.InstantiateModule(rCtx, cm, wazero.NewModuleConfig())
		require.NoError(t, err)
		_, err = rec.Call(rCtx, mod.ExportedFunction("add"), 2, 3)
		require.NoError(t, err)
		require.NoError(t, rec.Close())

		rp, err := boundary.NewReplayer(bytes.NewReader(l.Bytes()))
		require.NoError(t, err)
		pCtx := rp.Attach(ctx)
		rt2 := wazero.NewRuntime(pCtx)
		t.Cleanup(func() { _ = rt2.Close(ctx) })
		cm2, err := rt2.CompileModule(pCtx, addBin)
		require.NoError(t, err)
		mod2, err := rt2.InstantiateModule(pCtx, cm2, wazero.NewModuleConfig())
		require.NoError(t, err)
		_, err = rp.Call(pCtx, mod2.ExportedFunction("add"), 2, 4)
		requireReplayError(t, err, boundary.KindParamMismatch)
	})
}

// closing the runtime after recording still allows a consistent trailer
// commit, and the log replays cleanly on a fresh runtime.
func TestBoundaryRuntimeCloseAndCommit(t *testing.T) {
	ctx := context.Background()
	guestBin := boundaryGuestBinary(t)

	var log bytes.Buffer
	rec := boundary.NewRecorder(&log)
	rCtx := rec.Attach(ctx)
	rt, _ := setupArmedRuntime(t, rCtx, wazero.NewRuntimeConfigInterpreter())
	cm, err := rt.CompileModule(rCtx, guestBin)
	require.NoError(t, err)
	mod, err := rt.InstantiateModule(rCtx, cm, newRecordEnv().moduleConfig())
	require.NoError(t, err)
	res, err := rec.Call(rCtx, mod.ExportedFunction("run"))
	require.NoError(t, err)
	require.Equal(t, uint64(107), res[0])

	// Close the runtime (module exit/cleanup) and only then commit the log.
	require.NoError(t, rt.Close(rCtx))
	require.NoError(t, rec.Close())

	rp, err := boundary.NewReplayer(bytes.NewReader(log.Bytes()))
	require.NoError(t, err)
	pCtx := rp.Attach(ctx)
	rt2, _ := setupArmedRuntime(t, pCtx, wazero.NewRuntimeConfigInterpreter())
	cm2, err := rt2.CompileModule(pCtx, guestBin)
	require.NoError(t, err)
	mod2, err := rt2.InstantiateModule(pCtx, cm2, newRecordEnv().moduleConfig())
	require.NoError(t, err)
	res2, err := rp.Call(pCtx, mod2.ExportedFunction("run"))
	require.NoError(t, err)
	require.Equal(t, res, res2)
	require.NoError(t, rp.Close())
}

// ---------------------------------------------------------------------------
// concurrent independent sessions get identical results
// ---------------------------------------------------------------------------

func TestBoundaryConcurrentSessions(t *testing.T) {
	ctx := context.Background()
	guestBin := boundaryGuestBinary(t)

	var wg sync.WaitGroup
	var firstErr error
	var mu sync.Mutex
	setErr := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if firstErr == nil && err != nil {
			firstErr = err
		}
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var log bytes.Buffer
			rec := boundary.NewRecorder(&log)
			rCtx := rec.Attach(ctx)
			rt, _ := setupArmedRuntime(t, rCtx, wazero.NewRuntimeConfigInterpreter())
			cm, err := rt.CompileModule(rCtx, guestBin)
			if err != nil {
				setErr(err)
				return
			}
			mod, err := rt.InstantiateModule(rCtx, cm, newRecordEnv().moduleConfig())
			if err != nil {
				setErr(err)
				return
			}
			res, err := rec.Call(rCtx, mod.ExportedFunction("run"))
			if err != nil || res[0] != 107 {
				setErr(errors.New("bad record"))
				return
			}
			if err := rec.Close(); err != nil {
				setErr(err)
				return
			}

			rp, err := boundary.NewReplayer(bytes.NewReader(log.Bytes()))
			if err != nil {
				setErr(err)
				return
			}
			pCtx := rp.Attach(ctx)
			rt2, _ := setupArmedRuntime(t, pCtx, wazero.NewRuntimeConfigInterpreter())
			cm2, err := rt2.CompileModule(pCtx, guestBin)
			if err != nil {
				setErr(err)
				return
			}
			mod2, err := rt2.InstantiateModule(pCtx, cm2, newRecordEnv().moduleConfig())
			if err != nil {
				setErr(err)
				return
			}
			res2, err := rp.Call(pCtx, mod2.ExportedFunction("run"))
			if err != nil || res2[0] != 107 {
				setErr(errors.New("bad replay"))
				return
			}
			setErr(rp.Close())
		}()
	}
	wg.Wait()
	require.NoError(t, firstErr)
}

// ---------------------------------------------------------------------------
// disabled mode keeps standard behavior
// ---------------------------------------------------------------------------

func TestBoundaryDisabledIsTransparent(t *testing.T) {
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)
	// Plain, non-armed instantiation of the same host modules.
	_, err := r.NewHostModuleBuilder("env").
		NewFunctionBuilder().WithFunc(func() uint32 { return 7 }).Export("answer").
		Instantiate(ctx)
	require.NoError(t, err)
	_, err = wasi.NewBuilder(r).Instantiate(ctx)
	require.NoError(t, err)

	mod, err := r.InstantiateWithConfig(ctx, boundaryGuestBinary(t), wazero.NewModuleConfig())
	require.NoError(t, err)
	res, err := mod.ExportedFunction("run").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(107), res[0])
}
