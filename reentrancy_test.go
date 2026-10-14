package wazero

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	binaryencoding "github.com/tetratelabs/wazero/internal/testing/binaryencoding"
	"github.com/tetratelabs/wazero/internal/wasm"
	"github.com/tetratelabs/wazero/sys"
	stdruntime "runtime"
)

// Guest function selectors used by the "env.cb" host function. Untyped so
// they convert both to the guest i32 parameter and to Call's uint64 args.
const (
	cbNone       = 0
	cbSameFOnce  = 1 // re-enter f once, with cbNone (bounded)
	cbSameGOnce  = 2 // re-enter g once, with cbNone (bounded)
	cbModuleB    = 3 // enter the B instance
	cbMarked     = 4 // enter "marked", whose first instruction is env.mark
	cbProbe      = 5 // enter probeExport, which calls env.probe
	cbInstanceA2 = 6 // enter a second instance of the same compiled module
	cbInfiniteF  = 10
	cbInfiniteG  = 11
)

// Indices in the shared guest binary. Imports occupy 0..4.
const (
	guestExportF      = "f"
	guestExportG      = "g"
	guestExportMarked = "marked"
	guestExportTrap   = "trap"
	guestExportClean  = "clean"
	guestExportProbe  = "probeExport"
	guestExportClose  = "doClose"
	guestExportBoom   = "doBoom"
)

// reentrancyGuestBinary encodes one guest module with five host imports and
// seven defined functions. All defined functions are tiny, so the module
// indices stay below 128 and need no LEB128 encoding.
func reentrancyGuestBinary() []byte {
	return binaryencoding.EncodeModule(&wasm.Module{
		TypeSection: []wasm.FunctionType{
			{}, // 0: () -> ()
			{Params: []wasm.ValueType{wasm.ValueTypeI32}}, // 1: (i32) -> ()
		},
		ImportFunctionCount: 5,
		ImportSection: []wasm.Import{
			{Module: "env", Name: "cb", Type: wasm.ExternTypeFunc, DescFunc: 1},
			{Module: "env", Name: "probe", Type: wasm.ExternTypeFunc, DescFunc: 0},
			{Module: "env", Name: "mark", Type: wasm.ExternTypeFunc, DescFunc: 0},
			{Module: "env", Name: "boom", Type: wasm.ExternTypeFunc, DescFunc: 0},
			{Module: "env", Name: "closeit", Type: wasm.ExternTypeFunc, DescFunc: 0},
		},
		FunctionSection: []wasm.Index{1, 1, 0, 0, 0, 0, 0, 0},
		CodeSection: []wasm.Code{
			// f(sel): call cb(sel)
			{Body: []byte{wasm.OpcodeLocalGet, 0, wasm.OpcodeCall, 0, wasm.OpcodeEnd}},
			// g(sel): call cb(sel)
			{Body: []byte{wasm.OpcodeLocalGet, 0, wasm.OpcodeCall, 0, wasm.OpcodeEnd}},
			// marked: env.mark is the first guest-visible action.
			{Body: []byte{wasm.OpcodeCall, 2, wasm.OpcodeEnd}},
			// trap
			{Body: []byte{wasm.OpcodeUnreachable, wasm.OpcodeEnd}},
			// clean
			{Body: []byte{wasm.OpcodeEnd}},
			// probeExport: env.probe
			{Body: []byte{wasm.OpcodeCall, 1, wasm.OpcodeEnd}},
			// doClose: env.closeit
			{Body: []byte{wasm.OpcodeCall, 4, wasm.OpcodeEnd}},
			// doBoom: env.boom
			{Body: []byte{wasm.OpcodeCall, 3, wasm.OpcodeEnd}},
		},
		ExportSection: []wasm.Export{
			{Name: guestExportF, Type: wasm.ExternTypeFunc, Index: 5},
			{Name: guestExportG, Type: wasm.ExternTypeFunc, Index: 6},
			{Name: guestExportMarked, Type: wasm.ExternTypeFunc, Index: 7},
			{Name: guestExportTrap, Type: wasm.ExternTypeFunc, Index: 8},
			{Name: guestExportClean, Type: wasm.ExternTypeFunc, Index: 9},
			{Name: guestExportProbe, Type: wasm.ExternTypeFunc, Index: 10},
			{Name: guestExportClose, Type: wasm.ExternTypeFunc, Index: 11},
			{Name: guestExportBoom, Type: wasm.ExternTypeFunc, Index: 12},
		},
	})
}

type reentrancyEnv struct {
	t  *testing.T
	mu sync.Mutex

	r  Runtime
	a  api.Module
	a2 api.Module
	b  api.Module

	marks     int32
	depths    []int
	nestedErr error
	before    map[string]int
}

func (e *reentrancyEnv) cb(ctx context.Context, mod api.Module, sel uint32) {
	e.mu.Lock()
	e.depths = append(e.depths, ReentrancyCallDepth(ctx))
	e.mu.Unlock()

	if sel == cbNone {
		return
	}
	var fn api.Function
	var args []uint64
	switch sel {
	case cbSameFOnce:
		fn = mod.ExportedFunction(guestExportF)
		args = []uint64{cbNone}
	case cbSameGOnce:
		fn = mod.ExportedFunction(guestExportG)
		args = []uint64{cbNone}
	case cbModuleB:
		// B is another instance of the same compiled module, entered via f.
		fn = e.b.ExportedFunction(guestExportF)
		args = []uint64{cbNone}
	case cbMarked:
		fn = mod.ExportedFunction(guestExportMarked)
	case cbProbe:
		fn = mod.ExportedFunction(guestExportProbe)
	case cbInstanceA2:
		fn = e.a2.ExportedFunction(guestExportF)
		args = []uint64{cbNone}
	case cbInfiniteF:
		fn = mod.ExportedFunction(guestExportF)
		args = []uint64{cbInfiniteF}
	case cbInfiniteG:
		fn = mod.ExportedFunction(guestExportG)
		args = []uint64{cbInfiniteG}
	}
	if fn != nil {
		_, err := fn.Call(ctx, args...)
		e.mu.Lock()
		e.nestedErr = err
		e.mu.Unlock()
	}
}

func (e *reentrancyEnv) probe(ctx context.Context) {
	e.mu.Lock()
	e.depths = append(e.depths, ReentrancyCallDepth(ctx))
	e.mu.Unlock()
}

func (e *reentrancyEnv) mark(context.Context) {
	atomic.AddInt32(&e.marks, 1)
}

func (e *reentrancyEnv) boom(context.Context) {
	panic(errors.New("host boom"))
}

func (e *reentrancyEnv) closeit(ctx context.Context, mod api.Module) {
	_ = mod.CloseWithExitCode(ctx, 42)
}

func (e *reentrancyEnv) lastNestedError() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.nestedErr
}

func (e *reentrancyEnv) recordedDepths() []int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]int(nil), e.depths...)
}

func (e *reentrancyEnv) markCount() int32 { return atomic.LoadInt32(&e.marks) }

// instantiateReentrancyHost registers the five "env" host functions used by
// the shared guest binary.
func instantiateReentrancyHost(t *testing.T, r Runtime, env *reentrancyEnv) {
	ctx := context.Background()
	host := r.NewHostModuleBuilder("env")
	host.NewFunctionBuilder().WithFunc(env.cb).Export("cb")
	host.NewFunctionBuilder().WithFunc(env.probe).Export("probe")
	host.NewFunctionBuilder().WithFunc(env.mark).Export("mark")
	host.NewFunctionBuilder().WithFunc(env.boom).Export("boom")
	host.NewFunctionBuilder().WithFunc(env.closeit).Export("closeit")
	if _, err := host.Instantiate(ctx); err != nil {
		t.Fatalf("instantiate host module: %v", err)
	}
}

// newReentrancyRuntime builds host module "env" and three guest instances
// (A, A2, B) of the same compiled module under the given RuntimeConfig.
func newReentrancyRuntime(t *testing.T, rtc RuntimeConfig, withListeners bool) *reentrancyEnv {
	t.Helper()
	ctx := context.Background()
	r := NewRuntimeWithConfig(ctx, rtc)
	t.Cleanup(func() { _ = r.Close(ctx) })

	env := &reentrancyEnv{t: t, r: r, before: map[string]int{}}
	instantiateReentrancyHost(t, r, env)

	compileCtx := ctx
	if withListeners {
		compileCtx = experimental.WithFunctionListenerFactory(ctx, experimental.FunctionListenerFactoryFunc(
			func(def api.FunctionDefinition) experimental.FunctionListener {
				return experimental.FunctionListenerFunc(func(_ context.Context, _ api.Module, def api.FunctionDefinition, _ []uint64, _ experimental.StackIterator) {
					env.mu.Lock()
					env.before[def.DebugName()]++
					env.mu.Unlock()
				})
			}))
	}
	compiled, err := r.CompileModule(compileCtx, reentrancyGuestBinary())
	if err != nil {
		t.Fatalf("compile guest: %v", err)
	}

	instantiate := func(name string) api.Module {
		m, err := r.InstantiateModule(ctx, compiled, NewModuleConfig().WithName(name).WithStartFunctions())
		if err != nil {
			t.Fatalf("instantiate %s: %v", name, err)
		}
		return m
	}
	env.a = instantiate("A")
	env.b = instantiate("B")
	env.a2 = instantiate("A2")
	return env
}

func reentrancyEngines(t *testing.T, run func(t *testing.T, rtc func() RuntimeConfig)) {
	t.Helper()
	t.Run("interpreter", func(t *testing.T) { run(t, NewRuntimeConfigInterpreter) })
	t.Run("compiler", func(t *testing.T) { run(t, NewRuntimeConfigCompiler) })
}

func requirePolicyError(t *testing.T, err error, reason ReentrancyReason) *ReentrancyError {
	pe := &ReentrancyError{}
	if !errors.As(err, &pe) {
		t.Fatalf("want *ReentrancyError, got %T: %v", err, err)
	}
	if pe.Reason != reason {
		t.Fatalf("want reason %v, got %v (%v)", reason, pe.Reason, pe)
	}
	return pe
}

func TestReentrancy_DisabledIsFullyCompatible(t *testing.T) {
	reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
		env := newReentrancyRuntime(t, rtc(), false)
		ctx := context.Background()

		// Single-hop same-module and cross-module callbacks both succeed.
		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbSameFOnce); err != nil {
			t.Fatalf("same module: %v", err)
		}
		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbModuleB); err != nil {
			t.Fatalf("cross module: %v", err)
		}
		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbMarked); err != nil {
			t.Fatalf("marked: %v", err)
		}
		if env.markCount() != 1 {
			t.Fatalf("guest side effect marks = %d, want 1", env.markCount())
		}

		// Error categories are still classifiable with the feature off.
		if _, err := env.a.ExportedFunction(guestExportTrap).Call(ctx); ClassifyCallError(err) != CallErrorGuestTrap {
			t.Fatalf("trap classified as %v: %v", ClassifyCallError(err), err)
		}
		if _, err := env.a.ExportedFunction(guestExportBoom).Call(ctx); ClassifyCallError(err) != CallErrorHostFunction {
			t.Fatalf("host error classified as %v: %v", ClassifyCallError(err), err)
		}
		if _, err := env.a.ExportedFunction(guestExportClose).Call(ctx); ClassifyCallError(err) != CallErrorModuleExited {
			t.Fatalf("exit classified as %v: %v", ClassifyCallError(err), err)
		}
		if !env.a.IsClosed() {
			t.Fatal("doClose must close the module")
		}
	})
}

func TestReentrancy_EnabledPermissiveDefault(t *testing.T) {
	reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
		env := newReentrancyRuntime(t, rtc().WithReentrancyControl(PermissiveReentrancyPolicy()), false)
		ctx := context.Background()

		for _, sel := range []uint32{cbSameFOnce, cbSameGOnce, cbModuleB, cbMarked, cbProbe, cbInstanceA2} {
			if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, uint64(sel)); err != nil {
				t.Fatalf("selector %d: %v", sel, err)
			}
		}
		if env.markCount() != 1 {
			t.Fatalf("marks = %d, want 1", env.markCount())
		}
	})
}

func TestReentrancy_SameModulePolicy(t *testing.T) {
	strict := ReentrancyPolicy{AllowSameModuleReentry: false, AllowCrossModuleReentry: true}
	reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
		env := newReentrancyRuntime(t, rtc().WithReentrancyControl(strict), false)
		ctx := context.Background()

		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbSameFOnce); err != nil {
			t.Fatalf("root call must succeed (rejection surfaces inside host): %v", err)
		}
		requirePolicyError(t, env.lastNestedError(), ReasonSameModuleDenied)
		if env.a.IsClosed() {
			t.Fatal("policy rejection must not close the module")
		}
		// No guest instruction of the rejected segment ran.
		if marks := env.markCount(); marks != 0 {
			t.Fatalf("marks = %d, want 0", marks)
		}
		// Module remains usable for subsequent top-level calls.
		if _, err := env.a.ExportedFunction(guestExportClean).Call(ctx); err != nil {
			t.Fatalf("reuse after denial: %v", err)
		}
		// Same policy does not block a different instance.
		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbModuleB); err != nil {
			t.Fatalf("cross module must be admitted: %v", err)
		}
	})
}

func TestReentrancy_CrossModulePolicy(t *testing.T) {
	strict := ReentrancyPolicy{AllowSameModuleReentry: true, AllowCrossModuleReentry: false}
	reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
		env := newReentrancyRuntime(t, rtc().WithReentrancyControl(strict), false)
		ctx := context.Background()

		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbSameFOnce); err != nil {
			t.Fatalf("same module must be admitted: %v", err)
		}
		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbModuleB); err != nil {
			t.Fatalf("root should not fail directly: %v", err)
		}
		requirePolicyError(t, env.lastNestedError(), ReasonCrossModuleDenied)

		// A second instance of the same compiled module is also cross-module.
		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbInstanceA2); err != nil {
			t.Fatalf("root should not fail directly: %v", err)
		}
		requirePolicyError(t, env.lastNestedError(), ReasonCrossModuleDenied)
	})
}

func TestReentrancy_MaxDepth(t *testing.T) {
	for _, maxDepth := range []uint32{1, 2} {
		t.Run(fmt.Sprintf("max%d", maxDepth), func(t *testing.T) {
			policy := ReentrancyPolicy{
				AllowSameModuleReentry:  true,
				AllowCrossModuleReentry: true,
				MaxReentryDepth:         maxDepth,
			}
			reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
				env := newReentrancyRuntime(t, rtc().WithReentrancyControl(policy), false)
				ctx := context.Background()

				if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbInfiniteF); err != nil {
					t.Fatalf("root: %v", err)
				}
				pe := requirePolicyError(t, env.lastNestedError(), ReasonMaxDepthExceeded)
				if pe.Depth != int(maxDepth)+1 {
					t.Fatalf("rejected depth = %d, want %d", pe.Depth, maxDepth+1)
				}
				if _, err := env.a.ExportedFunction(guestExportClean).Call(ctx); err != nil {
					t.Fatalf("reuse after depth denial: %v", err)
				}
			})
		})
	}
}

func TestReentrancy_CycleDetection(t *testing.T) {
	policy := ReentrancyPolicy{
		AllowSameModuleReentry:  true,
		AllowCrossModuleReentry: true,
		DetectCycles:            true,
	}
	reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
		env := newReentrancyRuntime(t, rtc().WithReentrancyControl(policy), false)
		ctx := context.Background()

		// f -> cb -> f (same function node) is a cycle.
		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbInfiniteF); err != nil {
			t.Fatalf("root: %v", err)
		}
		requirePolicyError(t, env.lastNestedError(), ReasonCycleDetected)

		// g recursing into g also cycles, at the g node.
		if _, err := env.a.ExportedFunction(guestExportG).Call(ctx, cbInfiniteG); err != nil {
			t.Fatalf("root: %v", err)
		}
		requirePolicyError(t, env.lastNestedError(), ReasonCycleDetected)

		// f -> cb -> g (bounded) is same-module reentry but NOT a cycle.
		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbSameGOnce); err != nil {
			t.Fatalf("same module different function must be admitted: %v", err)
		}
		if err := env.lastNestedError(); err != nil {
			t.Fatalf("nested g call must succeed, got %v", err)
		}
	})
}

func TestReentrancy_ConfigPrecedence(t *testing.T) {
	strict := ReentrancyPolicy{AllowSameModuleReentry: false, AllowCrossModuleReentry: true}
	loose := ReentrancyPolicy{AllowSameModuleReentry: true, AllowCrossModuleReentry: true}

	type combo struct {
		runtimeAllow bool
		instance     *ReentrancyPolicy
		entry        *ReentrancyPolicy
		wantDeny     bool
	}
	boolPtr := func(p ReentrancyPolicy) *ReentrancyPolicy { return &p }
	cases := []combo{
		{false, nil, nil, true},
		{false, nil, boolPtr(loose), false},
		{false, boolPtr(loose), nil, false},
		{false, boolPtr(loose), boolPtr(strict), true},
		{true, nil, nil, false},
		{true, boolPtr(strict), nil, true},
		{true, nil, boolPtr(strict), true},
		{true, boolPtr(loose), boolPtr(loose), false},
	}
	reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
		for i, tc := range cases {
			t.Run(fmt.Sprintf("combo%d", i), func(t *testing.T) {
				runtimePolicy := strict
				if tc.runtimeAllow {
					runtimePolicy = loose
				}
				r := NewRuntimeWithConfig(context.Background(), rtc().WithReentrancyControl(runtimePolicy))
				defer r.Close(context.Background())

				// Minimal env with one host fn and one guest instance.
				env := &reentrancyEnv{t: t, r: r, before: map[string]int{}}
				instantiateReentrancyHost(t, r, env)
				compiled, err := r.CompileModule(context.Background(), reentrancyGuestBinary())
				if err != nil {
					t.Fatal(err)
				}
				mc := NewModuleConfig().WithName("A").WithStartFunctions()
				if tc.instance != nil {
					mc = mc.WithReentrancyPolicy(*tc.instance)
				}
				m, err := r.InstantiateModule(context.Background(), compiled, mc)
				if err != nil {
					t.Fatal(err)
				}
				env.a = m

				ctx := context.Background()
				if tc.entry != nil {
					ctx = WithReentrancyPolicy(ctx, *tc.entry)
				}
				if _, err = m.ExportedFunction(guestExportF).Call(ctx, cbSameFOnce); err != nil {
					t.Fatal(err)
				}
				var pe *ReentrancyError
				gotDeny := errors.As(env.lastNestedError(), &pe)
				if gotDeny != tc.wantDeny {
					t.Fatalf("combo %d: deny=%v want %v (err=%v)", i, gotDeny, tc.wantDeny, env.lastNestedError())
				}
			})
		}
	})
}

func TestReentrancy_EntryPolicyDoesNotPropagate(t *testing.T) {
	strict := ReentrancyPolicy{AllowSameModuleReentry: false, AllowCrossModuleReentry: true}
	reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
		env := newReentrancyRuntime(t, rtc().WithReentrancyControl(strict), false)
		// One-shot permissive override on the ROOT call: it admits the root
		// segment itself but must not reach nested callbacks, which fall back
		// to the strict runtime default instead of recursing forever.
		ctx := WithReentrancyPolicy(context.Background(), PermissiveReentrancyPolicy())
		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbInfiniteF); err != nil {
			t.Fatalf("root: %v", err)
		}
		pe := requirePolicyError(t, env.lastNestedError(), ReasonSameModuleDenied)
		if pe.Depth != 1 {
			t.Fatalf("override leaked %d levels deep, rejection at %d", pe.Depth, pe.Depth)
		}
	})
}

func TestReentrancy_DepthProbe(t *testing.T) {
	reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
		env := newReentrancyRuntime(t, rtc().WithReentrancyControl(PermissiveReentrancyPolicy()), false)
		ctx := context.Background()

		// Two sequential root segments must each report depth 1 at host entry.
		for i := 0; i < 2; i++ {
			if _, err := env.a.ExportedFunction(guestExportProbe).Call(ctx); err != nil {
				t.Fatal(err)
			}
		}
		// f(cbProbe): host cb depth 1, then nested probeExport host depth 2.
		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbProbe); err != nil {
			t.Fatal(err)
		}
		// Repeat to prove no state leaks between calls.
		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbProbe); err != nil {
			t.Fatal(err)
		}
		want := []int{1, 1, 1, 2, 1, 2}
		if got := env.recordedDepths(); len(got) != len(want) {
			t.Fatalf("depths = %v, want %v", got, want)
		} else {
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("depths = %v, want %v", got, want)
				}
			}
		}
	})
}

func TestReentrancy_RejectedSegmentHasNoSideEffects(t *testing.T) {
	strict := ReentrancyPolicy{AllowSameModuleReentry: false, AllowCrossModuleReentry: true}
	reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
		env := newReentrancyRuntime(t, rtc().WithReentrancyControl(strict), true)
		ctx := context.Background()

		// Root f runs; its cb is denied entry to marked, so neither the
		// listener Before nor env.mark for marked is observed.
		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbMarked); err != nil {
			t.Fatal(err)
		}
		requirePolicyError(t, env.lastNestedError(), ReasonSameModuleDenied)
		if env.markCount() != 0 {
			t.Fatalf("denied segment executed guest code, marks=%d", env.markCount())
		}
		env.mu.Lock()
		for name, count := range env.before {
			if strings.HasSuffix(name, ".$7") && count != 0 {
				t.Fatalf("listener.Before for denied marked (%s) called %d times", name, count)
			}
		}
		env.mu.Unlock()
	})
}

func TestReentrancy_ErrorClassification(t *testing.T) {
	reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
		ctx := context.Background()

		// Policy rejection (separate harness with strict policy).
		strict := ReentrancyPolicy{AllowSameModuleReentry: false, AllowCrossModuleReentry: true}
		env := newReentrancyRuntime(t, rtc().WithReentrancyControl(strict), false)
		if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbSameFOnce); err != nil {
			t.Fatal(err)
		}
		if k := ClassifyCallError(env.lastNestedError()); k != CallErrorPolicyRejected {
			t.Fatalf("policy error classified as %v", k)
		}
		if pe := (&ReentrancyError{}); !errors.As(env.lastNestedError(), &pe) {
			t.Fatal("errors.As must recover *ReentrancyError")
		}

		// Context cancellation before guest execution (feature enabled, no
		// WithCloseOnContextDone: the module is NOT closed).
		canceledCtx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := env.a.ExportedFunction(guestExportClean).Call(canceledCtx)
		if k := ClassifyCallError(err); k != CallErrorContextCanceled {
			t.Fatalf("canceled ctx classified as %v: %v", k, err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want errors.Is context.Canceled, got %v", err)
		}
		if env.a.IsClosed() {
			t.Fatal("boundary cancellation must not close the module")
		}

		// DeadlineExceeded likewise.
		deadlineCtx, cancelDeadline := context.WithDeadline(ctx, time.Now().Add(-time.Second))
		defer cancelDeadline()
		_, err = env.a.ExportedFunction(guestExportClean).Call(deadlineCtx)
		if k := ClassifyCallError(err); k != CallErrorContextCanceled {
			t.Fatalf("deadline ctx classified as %v: %v", k, err)
		}

		// Guest trap and host error on a fresh harness.
		env2 := newReentrancyRuntime(t, rtc().WithReentrancyControl(PermissiveReentrancyPolicy()), false)
		_, err = env2.a.ExportedFunction(guestExportTrap).Call(ctx)
		if k := ClassifyCallError(err); k != CallErrorGuestTrap {
			t.Fatalf("trap classified as %v: %v", k, err)
		}
		_, err = env2.a.ExportedFunction(guestExportBoom).Call(ctx)
		if k := ClassifyCallError(err); k != CallErrorHostFunction {
			t.Fatalf("host panic classified as %v: %v", k, err)
		}

		// Module exit.
		_, err = env2.a.ExportedFunction(guestExportClose).Call(ctx)
		var exitErr *sys.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 42 {
			t.Fatalf("want *sys.ExitError(42), got %v", err)
		}
		if k := ClassifyCallError(err); k != CallErrorModuleExited {
			t.Fatalf("exit classified as %v", k)
		}
	})
}

func TestReentrancy_RepeatedCallsDoNotPollute(t *testing.T) {
	strict := ReentrancyPolicy{AllowSameModuleReentry: false, AllowCrossModuleReentry: true}
	reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
		env := newReentrancyRuntime(t, rtc().WithReentrancyControl(strict), false)
		ctx := context.Background()
		for i := 0; i < 100; i++ {
			if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbMarked); err != nil {
				t.Fatalf("iter %d: %v", i, err)
			}
			requirePolicyError(t, env.lastNestedError(), ReasonSameModuleDenied)
		}
		if env.markCount() != 0 {
			t.Fatalf("marks = %d, want 0", env.markCount())
		}
		if _, err := env.a.ExportedFunction(guestExportClean).Call(ctx); err != nil {
			t.Fatalf("reuse: %v", err)
		}
	})
}

func TestReentrancy_HostPanicAndCloseUnwindChain(t *testing.T) {
	reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
		env := newReentrancyRuntime(t, rtc().WithReentrancyControl(PermissiveReentrancyPolicy()), false)
		ctx := context.Background()

		for i := 0; i < 3; i++ {
			_, err := env.a.ExportedFunction(guestExportBoom).Call(ctx)
			if ClassifyCallError(err) != CallErrorHostFunction {
				t.Fatalf("iter %d: %v", i, err)
			}
			if env.a.IsClosed() {
				t.Fatal("host panic must not close module")
			}
			if _, err := env.a.ExportedFunction(guestExportF).Call(ctx, cbSameFOnce); err != nil {
				t.Fatalf("chain not clean after host panic: %v", err)
			}
		}

		// Closing the runtime while calls happened must not leave the module
		// in an unusable-locked state; subsequent calls fail closed cleanly.
		if err := env.r.Close(ctx); err != nil {
			t.Fatalf("runtime close: %v", err)
		}
		if _, err := env.a.ExportedFunction(guestExportClean).Call(ctx); err == nil {
			t.Fatal("call after runtime close must fail")
		}
	})
}

func TestReentrancy_ConcurrentInstances(t *testing.T) {
	reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
		env := newReentrancyRuntime(t, rtc().WithReentrancyControl(PermissiveReentrancyPolicy()), false)
		ctx := context.Background()

		var wg sync.WaitGroup
		for g := 0; g < 50; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				root := env.a
				if g%2 == 0 {
					root = env.a2
				}
				for i := 0; i < 20; i++ {
					sel := []uint32{cbSameFOnce, cbSameGOnce, cbModuleB, cbProbe, cbNone}[i%5]
					if _, err := root.ExportedFunction(guestExportF).Call(ctx, uint64(sel)); err != nil {
						t.Errorf("g%d i%d: %v", g, i, err)
						return
					}
				}
			}(g)
		}
		wg.Wait()
		if _, err := env.a.ExportedFunction(guestExportClean).Call(ctx); err != nil {
			t.Fatalf("post-concurrency reuse: %v", err)
		}
	})
}

func TestReentrancy_NoGoroutineLeak(t *testing.T) {
	reentrancyEngines(t, func(t *testing.T, rtc func() RuntimeConfig) {
		settle := func() int {
			stdruntime.GC()
			time.Sleep(20 * time.Millisecond)
			return stdruntime.NumGoroutine()
		}
		_ = settle()
		before := settle()

		func() {
			env := newReentrancyRuntime(t, rtc().WithReentrancyControl(PermissiveReentrancyPolicy()), false)
			ctx := context.Background()
			_, _ = env.a.ExportedFunction(guestExportF).Call(ctx, cbSameFOnce)
			_, _ = env.a.ExportedFunction(guestExportF).Call(ctx, cbModuleB)
			_, _ = env.a.ExportedFunction(guestExportBoom).Call(ctx)
		}()

		// The reentrancy feature itself spawns no goroutines.
		after := settle()
		if after > before+1 {
			t.Fatalf("goroutine count grew: before=%d after=%d", before, after)
		}
	})
}
