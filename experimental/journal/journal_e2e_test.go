package journal_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero/internal/testing/require"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	pubjournal "github.com/tetratelabs/wazero/experimental/journal"
	wasi "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// ---------------------------------------------------------------------------
// Tiny hand-assembled Wasm modules (no wat2wasm dependency).
// ---------------------------------------------------------------------------

func uleb(n uint64) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			out = append(out, b|0x80)
		} else {
			out = append(out, b)
			break
		}
	}
	return out
}

func section(id byte, payload []byte) []byte {
	return append([]byte{id}, append(uleb(uint64(len(payload))), payload...)...)
}

func encStr(s string) []byte { return append(uleb(uint64(len(s))), s...) }

func vecBytes(items ...[]byte) []byte {
	out := uleb(uint64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

func funcType(params, results []byte) []byte {
	return append([]byte{0x60}, append(uleb(uint64(len(params))), append(params,
		append(uleb(uint64(len(results))), results...)...)...)...)
}

func funcBody(code []byte) []byte {
	payload := append([]byte{0x00 /* no locals */}, code...)
	payload = append(payload, 0x0b)
	return append(uleb(uint64(len(payload))), payload...)
}

// buildJournalGuest builds a module importing six "env" host functions and
// exporting run/helper/do_trap/do_exit/do_hosterr/spin/grow + memory.
//
// Imported functions (indices):
//
//	0 tick        () -> i32
//	1 putmem      (i32,i32) -> i32
//	2 fillrand    (i32,i32) -> i32
//	3 getval      (i32) -> i64
//	4 boom        (i32) -> ()
//	5 nest        () -> i64
//
// Defined: 6 run (i32)->i64, 7 helper ()->i32, 8..10 void, 11 grow (i32)->i32.
func buildJournalGuest(t *testing.T) []byte {
	t.Helper()
	types := [][]byte{
		funcType(nil, []byte{0x7f}),                // 0 () -> i32
		funcType([]byte{0x7f, 0x7f}, []byte{0x7f}), // 1 (i32,i32) -> i32
		funcType([]byte{0x7f}, []byte{0x7e}),       // 2 (i32) -> i64
		funcType([]byte{0x7f}, nil),                // 3 (i32) -> ()
		funcType(nil, []byte{0x7e}),                // 4 () -> i64
		funcType([]byte{0x7f}, []byte{0x7e}),       // 5 run (i32) -> i64
		funcType(nil, []byte{0x7f}),                // 6 helper () -> i32
		funcType(nil, nil),                         // 7 () -> ()
		funcType([]byte{0x7f}, []byte{0x7f}),       // 8 grow (i32) -> i32
	}

	var typeSec bytes.Buffer
	typeSec.Write(uleb(uint64(len(types))))
	for _, ty := range types {
		typeSec.Write(ty)
	}

	var importItems [][]byte
	imp := func(module, name string, typeIdx byte) {
		importItems = append(importItems,
			bytes.Join([][]byte{encStr(module), encStr(name), []byte{0x00, typeIdx}}, nil))
	}
	imp("env", "tick", 0)
	imp("env", "putmem", 1)
	imp("env", "fillrand", 1)
	imp("env", "getval", 2)
	imp("env", "boom", 3)
	imp("env", "nest", 4)
	importSec := bytes.NewBuffer(vecBytes(importItems...))

	// Defined function type indices: run, helper, do_trap, do_exit,
	// do_hosterr, do_panicstr, spin, grow.
	funcSec := append(uleb(8), 5, 6, 7, 7, 7, 7, 7, 8)

	// Memory: min 1, max 4 pages.
	memLimits := append([]byte{0x01, 0x01}, uleb(4)...)
	memSec := vecBytes(memLimits)

	var exportItems [][]byte
	exp := func(name string, kind byte, idx byte) {
		exportItems = append(exportItems,
			bytes.Join([][]byte{encStr(name), []byte{kind, idx}}, nil))
	}
	exp("run", 0x00, 6)
	exp("helper", 0x00, 7)
	exp("do_trap", 0x00, 8)
	exp("do_exit", 0x00, 9)
	exp("do_hosterr", 0x00, 10)
	exp("do_panicstr", 0x00, 11)
	exp("spin", 0x00, 12)
	exp("grow", 0x00, 13)
	exp("memory", 0x02, 0)
	exportSec := bytes.NewBuffer(vecBytes(exportItems...))

	// run(x): (([i64 @200] + getval(x)) + nest()); with env side effects.
	run := []byte{
		0x10, 0x00, 0x1a, // call tick; drop
		0x20, 0x00, 0x41, 0xe4, 0x00, 0x10, 0x01, 0x1a, // putmem(x,100)
		0x41, 0xc8, 0x01, 0x41, 0x08, 0x10, 0x02, 0x1a, // fillrand(200,8)
		0x41, 0xc8, 0x01, 0x29, 0x03, 0x00, // i64.load align=3 off=0 => mem[200]
		0x20, 0x00, 0x10, 0x03, 0x7c, // getval(x); i64.add
		0x10, 0x05, 0x7c, // call nest; i64.add
	}
	helper := []byte{0x10, 0x00} // call tick
	doTrap := []byte{0x00}       // unreachable
	doExit := []byte{0x41, 0x01, 0x10, 0x04}
	doHostErr := []byte{0x41, 0x02, 0x10, 0x04}
	doPanicStr := []byte{0x41, 0x03, 0x10, 0x04}
	spin := []byte{0x03, 0x40, 0x0c, 0x00, 0x0b} // loop; br 0; end
	grow := []byte{0x20, 0x00, 0x40, 0x00}       // local.get 0; memory.grow 0

	codeSec := vecBytes(
		funcBody(run), funcBody(helper), funcBody(doTrap),
		funcBody(doExit), funcBody(doHostErr), funcBody(doPanicStr),
		funcBody(spin), funcBody(grow),
	)

	var bin bytes.Buffer
	bin.Write([]byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00})
	bin.Write(section(1, typeSec.Bytes()))
	bin.Write(section(2, importSec.Bytes()))
	bin.Write(section(3, funcSec))
	bin.Write(section(5, memSec))
	bin.Write(section(7, exportSec.Bytes()))
	bin.Write(section(10, codeSec))
	return bin.Bytes()
}

// buildWasiGuest builds ()->i64 that returns clock_time_get(mem@8) +
// random_get(mem@16..24).
func buildWasiGuest(t *testing.T) []byte {
	t.Helper()
	types := [][]byte{
		funcType([]byte{0x7f, 0x7e, 0x7f}, []byte{0x7f}), // 0 (i32,i64,i32)->i32
		funcType([]byte{0x7f, 0x7f}, []byte{0x7f}),       // 1 (i32,i32)->i32
		funcType(nil, []byte{0x7e}),                      // 2 () -> i64
	}
	var typeSec bytes.Buffer
	typeSec.Write(uleb(uint64(len(types))))
	for _, ty := range types {
		typeSec.Write(ty)
	}
	var importSec bytes.Buffer
	importSec.Write(vecBytes(
		append(encStr("wasi_snapshot_preview1"), append(encStr("clock_time_get"), 0x00, 0x00)...),
		append(encStr("wasi_snapshot_preview1"), append(encStr("random_get"), 0x00, 0x01)...),
	))
	funcSec := vecBytes([]byte{2})
	memSec := vecBytes(append([]byte{0x01, 0x01}, uleb(2)...))
	exportSec := bytes.NewBuffer(vecBytes(
		bytes.Join([][]byte{encStr("run"), []byte{0x00, 0x02}}, nil),
		bytes.Join([][]byte{encStr("memory"), []byte{0x02, 0x00}}, nil),
	))
	run := []byte{
		0x41, 0x00, 0x42, 0x00, 0x41, 0x08, 0x10, 0x00, 0x1a, // clock_time_get(0,0,8)
		0x41, 0x10, 0x41, 0x08, 0x10, 0x01, 0x1a, // random_get(16,8)
		0x41, 0x08, 0x29, 0x03, 0x00, // i64.load @8
		0x41, 0x10, 0x29, 0x03, 0x00, 0x7c, // i64.load @16; add
	}
	codeSec := vecBytes(funcBody(run))

	var bin bytes.Buffer
	bin.Write([]byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00})
	bin.Write(section(1, typeSec.Bytes()))
	bin.Write(section(2, importSec.Bytes()))
	bin.Write(section(3, funcSec))
	bin.Write(section(5, memSec))
	bin.Write(section(7, exportSec.Bytes()))
	bin.Write(section(10, codeSec))
	return bin.Bytes()
}

// ---------------------------------------------------------------------------
// Instrumented host side.
// ---------------------------------------------------------------------------

type hostCounters struct {
	tick, putmem, fillrand, getval, boom, nest int
	state                                      uint64
}

func (c *hostCounters) export(t *testing.T, b wazero.HostModuleBuilder) {
	t.Helper()
	b.NewFunctionBuilder().WithFunc(func(ctx context.Context) int32 {
		c.tick++
		c.state++
		return int32(100 + c.state)
	}).Export("tick")

	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, mod api.Module, off, v uint32) uint32 {
		c.putmem++
		ok := mod.Memory().WriteUint32Le(off, v)
		if !ok {
			return 1
		}
		return 0
	}).Export("putmem")

	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, mod api.Module, off, n uint32) uint32 {
		c.fillrand++
		c.state++
		buf := make([]byte, 8)
		for i := range buf {
			buf[i] = byte(uint64(0xA0+i) + c.state)
		}
		if !mod.Memory().Write(off, buf[:n]) {
			return 1
		}
		return 0
	}).Export("fillrand")

	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, n uint32) uint64 {
		c.getval++
		c.state++
		return 1000 + c.state + uint64(n)
	}).Export("getval")

	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, code int32) {
		c.boom++
		switch code {
		case 1:
			panic(sys.NewExitError(42))
		case 2:
			panic(errors.New("host failure injected"))
		default:
			panic("non-error panic value")
		}
	}).Export("boom")

	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, mod api.Module) int64 {
		c.nest++
		// Re-entrant nested call into the guest, which itself calls a host fn.
		res, err := mod.ExportedFunction("helper").Call(ctx)
		require.NoError(t, err)
		return int64(res[0]) + 2000
	}).Export("nest")
}

type fixture struct {
	r     wazero.Runtime
	mod   api.Module
	cnt   *hostCounters
	guest []byte
}

func newFixture(t *testing.T, rc wazero.RuntimeConfig, guest []byte, exportWASI bool, cnt *hostCounters) *fixture {
	t.Helper()
	ctx := pubjournal.Enable(context.Background())
	r := wazero.NewRuntimeWithConfig(ctx, rc)
	t.Cleanup(func() { _ = r.Close(context.Background()) })

	if exportWASI {
		_, err := wasi.NewBuilder(r).Instantiate(ctx)
		require.NoError(t, err)
	} else {
		mb := r.NewHostModuleBuilder("env")
		cnt.export(t, mb)
		_, err := mb.Instantiate(ctx)
		require.NoError(t, err)
	}

	compiled, err := r.CompileModule(ctx, guest)
	if err != nil {
		// e.g. wazevo unsupported on the current platform.
		if strings.Contains(err.Error(), "unsupported") {
			t.Skipf("engine unsupported: %v", err)
		}
		require.NoError(t, err)
	}
	mod, err := r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
	require.NoError(t, err)
	return &fixture{r: r, mod: mod, cnt: cnt, guest: guest}
}
