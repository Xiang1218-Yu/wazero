package wazero

import (
	"context"
	"errors"
	"testing"
	"testing/fstest"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/binaryencoding"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// planEngineConfig pairs a name with an instantiation-plan-enabled runtime
// config. All plan tests run under both engines to prove the plan behavior is
// engine-independent.
func planEngineConfigs(t *testing.T) []struct {
	name string
	rc   RuntimeConfig
} {
	t.Helper()
	cfgs := []struct {
		name string
		rc   RuntimeConfig
	}{
		{"interpreter", NewRuntimeConfigInterpreter().WithInstantiationPlan(true)},
	}
	if platform.CompilerSupports(api.CoreFeaturesV2) {
		cfgs = append(cfgs, struct {
			name string
			rc   RuntimeConfig
		}{"compiler", NewRuntimeConfigCompiler().WithInstantiationPlan(true)})
	}
	return cfgs
}

func newPlanRuntime(t *testing.T, rc RuntimeConfig) (Runtime, context.Context) {
	t.Helper()
	ctx := context.Background()
	r := NewRuntimeWithConfig(ctx, rc)
	t.Cleanup(func() { _ = r.Close(ctx) })
	return r, ctx
}

func compilePlanGuest(t *testing.T, r Runtime, ctx context.Context, m *wasm.Module) CompiledModule {
	t.Helper()
	c, err := r.CompileModule(ctx, binaryencoding.EncodeModule(m))
	require.NoError(t, err)
	return c
}

// addFuncType is (i32,i32) -> i32, matching the host "env.add" function.
var addFuncType = wasm.FunctionType{
	Params:  []wasm.ValueType{wasm.ValueTypeI32, wasm.ValueTypeI32},
	Results: []wasm.ValueType{wasm.ValueTypeI32},
}

func instantiateAddHost(t *testing.T, r Runtime, ctx context.Context) api.Module {
	t.Helper()
	host, err := r.NewHostModuleBuilder("env").
		NewFunctionBuilder().
		WithFunc(func(x, y uint32) uint32 { return x + y }).
		Export("add").
		Instantiate(ctx)
	require.NoError(t, err)
	return host
}

func happyGuestModule() *wasm.Module {
	one := uint32(1)
	return &wasm.Module{
		TypeSection:     []wasm.FunctionType{addFuncType},
		ImportSection:   []wasm.Import{{Module: "env", Name: "add", Type: wasm.ExternTypeFunc, DescFunc: 0}},
		FunctionSection: []wasm.Index{0},
		CodeSection: []wasm.Code{
			// local.get 0; local.get 1; call $add; end
			{Body: []byte{wasm.OpcodeLocalGet, 0x00, wasm.OpcodeLocalGet, 0x01, wasm.OpcodeCall, 0x00, wasm.OpcodeEnd}},
		},
		ExportSection: []wasm.Export{{Name: "call", Type: wasm.ExternTypeFunc, Index: one}},
	}
}

func TestInstantiationPlan_DisabledByDefault(t *testing.T) {
	ctx := context.Background()
	r := NewRuntime(ctx)
	defer r.Close(ctx)

	compiled, err := r.CompileModule(ctx, binaryencoding.EncodeModule(&wasm.Module{}))
	require.NoError(t, err)

	_, err = r.NewInstantiationPlan(ctx, compiled, NewModuleConfig())
	require.ErrorIs(t, err, ErrInstantiationPlanDisabled)

	// Direct paths remain fully usable.
	mod, err := r.InstantiateModule(ctx, compiled, NewModuleConfig().WithName("plain"))
	require.NoError(t, err)
	require.Equal(t, "plain", mod.Name())
}

func TestInstantiationPlan_PrepareSnapshotsAndCommit(t *testing.T) {
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			instantiateAddHost(t, r, ctx)
			compiled := compilePlanGuest(t, r, ctx, happyGuestModule())

			mapFS := fstest.MapFS{"tmp/hello.txt": &fstest.MapFile{Data: []byte("hi")}}
			mc := NewModuleConfig().
				WithName("guest").
				WithArgs("argv0", "--flag").
				WithEnv("FOO", "BAR").
				WithFSConfig(NewFSConfig().WithFSMount(mapFS, "tmp"))

			beforeVersion := r.(*runtime).store.RegistryVersion()
			plan, err := r.NewInstantiationPlan(ctx, compiled, mc)
			require.NoError(t, err)

			// Snapshot content checks.
			require.Equal(t, "guest", plan.Name())
			require.Equal(t, 32, len(plan.Digest()))
			require.NotEqual(t, [32]byte{}, [32]byte(plan.Digest()))

			imports := plan.Imports()
			require.Equal(t, 1, len(imports))
			require.Equal(t, "env", imports[0].Module)
			require.Equal(t, "add", imports[0].Name)
			require.Equal(t, PlanExternalKindFunc, imports[0].Kind)
			require.Equal(t, []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, imports[0].Params)
			require.Equal(t, []api.ValueType{api.ValueTypeI32}, imports[0].Results)

			exports := plan.Exports()
			require.Equal(t, 1, len(exports))
			require.Equal(t, "call", exports[0].Name)
			require.Equal(t, []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, exports[0].Params)

			require.Equal(t, []string{"argv0", "--flag"}, plan.Args())
			require.Equal(t, [][2]string{{"FOO", "BAR"}}, plan.Env())
			require.Equal(t, []string{"tmp"}, plan.FilesystemPreopens())
			require.Nil(t, plan.WASICapabilities())
			require.Equal(t, uint32(0), plan.MemoryRequirements().MinPages)
			require.Equal(t, true, plan.HostRegistryVersion() >= beforeVersion)

			// Not visible until committed.
			require.Nil(t, r.Module("guest"))
			require.False(t, plan.Committed())

			mod, err := plan.Commit(ctx)
			require.NoError(t, err)
			require.True(t, plan.Committed())
			require.NotNil(t, r.Module("guest"))

			res, err := mod.ExportedFunction("call").Call(ctx, 3, 4)
			require.NoError(t, err)
			require.Equal(t, uint64(7), res[0])

			// Digest is stable across plans compiled from the same bytes.
			compiled2 := compilePlanGuest(t, r, ctx, happyGuestModule())
			plan2, err := r.NewInstantiationPlan(ctx, compiled2, NewModuleConfig().WithName("guest2"))
			require.NoError(t, err)
			require.Equal(t, plan.Digest(), plan2.Digest())
			_, err = plan2.Commit(ctx)
			require.NoError(t, err)
		})
	}
}

func TestInstantiationPlan_Requirements(t *testing.T) {
	maxPages := uint32(2)
	maxElems := uint32(4)
	m := &wasm.Module{
		MemorySection: &wasm.Memory{Min: 1, Max: maxPages, IsMaxEncoded: true},
		TableSection:  []wasm.Table{{Type: wasm.RefTypeFuncref, Min: 3, Max: &maxElems}},
		GlobalSection: []wasm.Global{
			{Type: wasm.GlobalType{ValType: wasm.ValueTypeI32, Mutable: true},
				Init: wasm.NewConstantExpressionFromI32(0)},
		},
		ExportSection: []wasm.Export{
			{Name: "memory", Type: wasm.ExternTypeMemory, Index: 0},
			{Name: "table", Type: wasm.ExternTypeTable, Index: 0},
			{Name: "g", Type: wasm.ExternTypeGlobal, Index: 0},
		},
	}

	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			compiled := compilePlanGuest(t, r, ctx, m)
			plan, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig().WithName("req"))
			require.NoError(t, err)

			mem := plan.MemoryRequirements()
			require.False(t, mem.Imported)
			require.Equal(t, uint32(1), mem.MinPages)
			require.Equal(t, uint32(2), mem.MaxPages)
			require.True(t, mem.HasMax)

			tables := plan.TableRequirements()
			require.Equal(t, 1, len(tables))
			require.False(t, tables[0].Imported)
			require.Equal(t, api.ValueType(wasm.RefTypeFuncref), tables[0].Type)
			require.Equal(t, uint32(3), tables[0].Min)
			require.Equal(t, uint32(4), tables[0].Max)
			require.True(t, tables[0].HasMax)

			globals := plan.GlobalRequirements()
			require.Equal(t, 1, len(globals))
			require.Equal(t, api.ValueTypeI32, globals[0].Type)
			require.True(t, globals[0].Mutable)

			mod, err := plan.Commit(ctx)
			require.NoError(t, err)
			require.NotNil(t, mod.Memory())
		})
	}
}

func TestInstantiationPlan_MissingImport(t *testing.T) {
	guest := &wasm.Module{
		TypeSection:   []wasm.FunctionType{{}},
		ImportSection: []wasm.Import{{Module: "env", Name: "ghost", Type: wasm.ExternTypeFunc, DescFunc: 0}},
	}
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			instantiateAddHost(t, r, ctx)
			compiled := compilePlanGuest(t, r, ctx, guest)
			_, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig())
			requirePlanError(t, err, PlanErrorMissingImport)
		})
	}
}

func TestInstantiationPlan_MissingModule(t *testing.T) {
	guest := &wasm.Module{
		TypeSection:   []wasm.FunctionType{{}},
		ImportSection: []wasm.Import{{Module: "nowhere", Name: "f", Type: wasm.ExternTypeFunc, DescFunc: 0}},
	}
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			compiled := compilePlanGuest(t, r, ctx, guest)
			_, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig())
			requirePlanError(t, err, PlanErrorMissingImport)
		})
	}
}

func TestInstantiationPlan_DuplicateConflictingImport(t *testing.T) {
	guest := &wasm.Module{
		TypeSection: []wasm.FunctionType{{}},
		ImportSection: []wasm.Import{
			{Module: "env", Name: "add", Type: wasm.ExternTypeFunc, DescFunc: 0},
			{Module: "env", Name: "add", Type: wasm.ExternTypeGlobal,
				DescGlobal: wasm.GlobalType{ValType: wasm.ValueTypeI32}},
		},
	}
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			// Host "add" must match the first (function) import so planning
			// reaches the cross-kind duplicate detection.
			_, err := r.NewHostModuleBuilder("env").
				NewFunctionBuilder().WithFunc(func() {}).Export("add").
				Instantiate(ctx)
			require.NoError(t, err)
			compiled := compilePlanGuest(t, r, ctx, guest)
			_, err = r.NewInstantiationPlan(ctx, compiled, NewModuleConfig())
			requirePlanError(t, err, PlanErrorDuplicateImport)
		})
	}
}

func TestInstantiationPlan_SignatureMismatch(t *testing.T) {
	guest := happyGuestModule() // expects env.add (i32,i32) -> i32
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			// Host exposes add (i32) -> i32 instead.
			_, err := r.NewHostModuleBuilder("env").
				NewFunctionBuilder().WithFunc(func(x uint32) uint32 { return x }).
				Export("add").Instantiate(ctx)
			require.NoError(t, err)

			compiled := compilePlanGuest(t, r, ctx, guest)
			_, err = r.NewInstantiationPlan(ctx, compiled, NewModuleConfig())
			requirePlanError(t, err, PlanErrorSignatureMismatch)

			// The direct path reports the same linking problem at instantiate.
			_, err = r.InstantiateModule(ctx, compiled, NewModuleConfig())
			require.Error(t, err)
			require.Contains(t, err.Error(), "signature mismatch")
		})
	}
}

func TestInstantiationPlan_NameConflict(t *testing.T) {
	guest := happyGuestModule()
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			instantiateAddHost(t, r, ctx)

			// Occupy "guest" with an anonymous-shape module.
			other, err := r.CompileModule(ctx, binaryencoding.EncodeModule(&wasm.Module{}))
			require.NoError(t, err)
			_, err = r.InstantiateModule(ctx, other, NewModuleConfig().WithName("guest"))
			require.NoError(t, err)

			compiled := compilePlanGuest(t, r, ctx, guest)
			_, err = r.NewInstantiationPlan(ctx, compiled, NewModuleConfig().WithName("guest"))
			requirePlanError(t, err, PlanErrorNameConflict)
		})
	}
}

func TestInstantiationPlan_WASICapability(t *testing.T) {
	procExitType := wasm.FunctionType{Params: []wasm.ValueType{wasm.ValueTypeI32}}
	wasiGuest := func(names ...string) *wasm.Module {
		m := &wasm.Module{TypeSection: []wasm.FunctionType{procExitType}}
		for _, n := range names {
			m.ImportSection = append(m.ImportSection,
				wasm.Import{Module: "wasi_snapshot_preview1", Name: n, Type: wasm.ExternTypeFunc, DescFunc: 0})
		}
		return m
	}

	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name+"/module absent", func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			compiled := compilePlanGuest(t, r, ctx, wasiGuest("proc_exit"))
			_, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig())
			requirePlanError(t, err, PlanErrorWASICapability)
		})
		t.Run(ec.name+"/export absent", func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			// Host WASI module only provides proc_exit, but guest needs sock_accept.
			_, err := r.NewHostModuleBuilder("wasi_snapshot_preview1").
				NewFunctionBuilder().WithFunc(func(uint32) {}).Export("proc_exit").
				Instantiate(ctx)
			require.NoError(t, err)
			compiled := compilePlanGuest(t, r, ctx, wasiGuest("proc_exit", "sock_accept"))
			plan, perr := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig())
			require.Nil(t, plan)
			requirePlanError(t, perr, PlanErrorWASICapability)
		})
		t.Run(ec.name+"/capability snapshot", func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			_, err := r.NewHostModuleBuilder("wasi_snapshot_preview1").
				NewFunctionBuilder().WithFunc(func(uint32) {}).Export("proc_exit").
				NewFunctionBuilder().WithFunc(func(uint32, uint32, uint32) uint32 { return 0 }).
				Export("fd_write").Instantiate(ctx)
			require.NoError(t, err)
			guest := &wasm.Module{
				TypeSection: []wasm.FunctionType{
					{Params: []wasm.ValueType{wasm.ValueTypeI32}}, // 0 proc_exit
					{Params: []wasm.ValueType{wasm.ValueTypeI32, wasm.ValueTypeI32, wasm.ValueTypeI32}, // 1 fd_write
						Results: []wasm.ValueType{wasm.ValueTypeI32}},
				},
				ImportSection: []wasm.Import{
					{Module: "wasi_snapshot_preview1", Name: "proc_exit", Type: wasm.ExternTypeFunc, DescFunc: 0},
					{Module: "wasi_snapshot_preview1", Name: "fd_write", Type: wasm.ExternTypeFunc, DescFunc: 1},
				},
			}
			compiled := compilePlanGuest(t, r, ctx, guest)
			plan, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig().WithName("wguest"))
			require.NoError(t, err)
			require.Equal(t, []string{
				"wasi_snapshot_preview1.fd_write",
				"wasi_snapshot_preview1.proc_exit",
			}, plan.WASICapabilities())
			mod, err := plan.Commit(ctx)
			require.NoError(t, err)
			require.Equal(t, "wguest", mod.Name())
		})
	}
}

// Plan resource-limit classification is checked at the shared engine-neutral
// layer: compiled modules may originate from a runtime with higher limits.
func TestInstantiationPlan_ResourceLimitConflict(t *testing.T) {
	store := wasm.NewStore(api.CoreFeaturesV2, nil)
	m := &wasm.Module{MemorySection: &wasm.Memory{Min: 2, Max: 2, IsMaxEncoded: true}}
	_, _, err := store.CheckInstantiationPlan(m, "m", wasm.PlanLimits{MemoryLimitPages: 1})
	var pe *wasm.PlanCheckError
	require.True(t, errors.As(err, &pe))
	require.Equal(t, wasm.PlanCheckResourceLimit, pe.Kind)
}

func TestInstantiationPlan_InvalidConfigAtPrepare(t *testing.T) {
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			compiled := compilePlanGuest(t, r, ctx, &wasm.Module{})
			_, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig().WithEnv("", "v"))
			require.Error(t, err)
			require.Contains(t, err.Error(), "environ invalid")
		})
	}
}

func TestInstantiationPlan_CommitRegistryDrift(t *testing.T) {
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name+"/host signature changed", func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			host := instantiateAddHost(t, r, ctx)
			compiled := compilePlanGuest(t, r, ctx, happyGuestModule())
			plan, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig().WithName("guest"))
			require.NoError(t, err)

			// Replace env.add with an incompatible signature.
			require.NoError(t, host.Close(ctx))
			_, err = r.NewHostModuleBuilder("env").
				NewFunctionBuilder().WithFunc(func(x uint32) uint32 { return x }).
				Export("add").Instantiate(ctx)
			require.NoError(t, err)

			_, err = plan.Commit(ctx)
			requirePlanError(t, err, PlanErrorRegistryChanged)
			var pe *PlanError
			require.True(t, errors.As(err, &pe))
			// Inner cause keeps the precise classification.
			var inner *PlanError
			require.True(t, errors.As(pe.Err, &inner))
			require.Equal(t, PlanErrorSignatureMismatch, inner.Kind)

			// Nothing was registered by the failed commit.
			require.Nil(t, r.Module("guest"))
			require.False(t, plan.Committed())
		})

		t.Run(ec.name+"/unrelated registry change is accepted", func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			instantiateAddHost(t, r, ctx)
			compiled := compilePlanGuest(t, r, ctx, happyGuestModule())
			plan, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig().WithName("guest"))
			require.NoError(t, err)
			preparedVersion := plan.HostRegistryVersion()

			// Add an unrelated host module: version moves, but bindings remain equal.
			_, err = r.NewHostModuleBuilder("other").
				NewFunctionBuilder().WithFunc(func() {}).Export("ping").
				Instantiate(ctx)
			require.NoError(t, err)
			require.NotEqual(t, preparedVersion, r.(*runtime).store.RegistryVersion())

			mod, err := plan.Commit(ctx)
			require.NoError(t, err)
			require.Equal(t, "guest", mod.Name())
		})

		t.Run(ec.name+"/name taken after prepare", func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			instantiateAddHost(t, r, ctx)
			compiled := compilePlanGuest(t, r, ctx, happyGuestModule())
			plan, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig().WithName("guest"))
			require.NoError(t, err)

			squatter := compilePlanGuest(t, r, ctx, &wasm.Module{})
			_, err = r.InstantiateModule(ctx, squatter, NewModuleConfig().WithName("guest"))
			require.NoError(t, err)

			_, err = plan.Commit(ctx)
			requirePlanError(t, err, PlanErrorRegistryChanged)
		})

		t.Run(ec.name+"/host module removed", func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			host := instantiateAddHost(t, r, ctx)
			compiled := compilePlanGuest(t, r, ctx, happyGuestModule())
			plan, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig().WithName("guest"))
			require.NoError(t, err)
			require.NoError(t, host.Close(ctx))
			_, err = plan.Commit(ctx)
			requirePlanError(t, err, PlanErrorRegistryChanged)
		})
	}
}

func TestInstantiationPlan_CommitFailureRollback(t *testing.T) {
	// A guest whose start function traps.
	zero := uint32(0)
	trapping := &wasm.Module{
		TypeSection:     []wasm.FunctionType{{}},
		FunctionSection: []wasm.Index{0},
		CodeSection:     []wasm.Code{{Body: []byte{wasm.OpcodeUnreachable, wasm.OpcodeEnd}}},
		StartSection:    &zero,
	}

	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			compiled := compilePlanGuest(t, r, ctx, trapping)
			plan, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig().WithName("boom"))
			require.NoError(t, err)

			_, err = plan.Commit(ctx)
			require.Error(t, err)
			// No partial registration, no orphan instance, name is reusable.
			require.Nil(t, r.Module("boom"))
			require.False(t, plan.Committed())
			squatter := compilePlanGuest(t, r, ctx, &wasm.Module{})
			other, err := r.InstantiateModule(ctx, squatter, NewModuleConfig().WithName("boom"))
			require.NoError(t, err)
			require.Equal(t, "boom", other.Name())
			require.NoError(t, other.Close(ctx))

			// Retrying the same plan fails the same way but never double-registers.
			_, err = plan.Commit(ctx)
			require.Error(t, err)
			require.Nil(t, r.Module("boom"))
		})
	}
}

func TestInstantiationPlan_CommitCanceledContext(t *testing.T) {
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			instantiateAddHost(t, r, ctx)
			compiled := compilePlanGuest(t, r, ctx, happyGuestModule())
			plan, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig().WithName("guest"))
			require.NoError(t, err)

			canceledCtx, cancel := context.WithCancel(ctx)
			cancel()
			_, err = plan.Commit(canceledCtx)
			requirePlanError(t, err, PlanErrorContextCanceled)
			require.Nil(t, r.Module("guest"))
			require.False(t, plan.Committed())

			// Same plan can still be committed with a live context.
			mod, err := plan.Commit(ctx)
			require.NoError(t, err)
			require.Equal(t, "guest", mod.Name())
		})
	}
}

func TestInstantiationPlan_CommitIsIdempotent(t *testing.T) {
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			calls := 0
			_, err := r.NewHostModuleBuilder("env").
				NewFunctionBuilder().WithFunc(func() { calls++ }).Export("bump").
				Instantiate(ctx)
			require.NoError(t, err)

			zero := uint32(0)
			one := uint32(1)
			guest := &wasm.Module{
				TypeSection:     []wasm.FunctionType{{}},
				ImportSection:   []wasm.Import{{Module: "env", Name: "bump", Type: wasm.ExternTypeFunc, DescFunc: 0}},
				FunctionSection: []wasm.Index{0},
				CodeSection:     []wasm.Code{{Body: []byte{wasm.OpcodeCall, 0x00, wasm.OpcodeEnd}}},
				ExportSection:   []wasm.Export{{Name: "bump", Type: wasm.ExternTypeFunc, Index: one}},
				StartSection:    &zero,
			}
			compiled := compilePlanGuest(t, r, ctx, guest)
			plan, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig().WithName("guest"))
			require.NoError(t, err)

			mod, err := plan.Commit(ctx)
			require.NoError(t, err)
			require.Equal(t, 1, calls)
			require.Equal(t, "guest", mod.Name())

			// Repeated commit changes nothing: no new instance, no second
			// start/host-function invocation, no config consumption.
			_, err = plan.Commit(ctx)
			require.ErrorIs(t, err, ErrPlanAlreadyCommitted)
			require.Equal(t, 1, calls)
			require.Equal(t, 1, namedModuleCount(t, r, "guest"))
			require.True(t, plan.Committed())
		})
	}
}

func TestInstantiationPlan_CloseSemantics(t *testing.T) {
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			instantiateAddHost(t, r, ctx)
			compiled := compilePlanGuest(t, r, ctx, happyGuestModule())
			plan, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig().WithName("guest"))
			require.NoError(t, err)

			require.NoError(t, plan.Close(ctx))
			_, err = plan.Commit(ctx)
			require.ErrorIs(t, err, ErrPlanClosed)

			// Closing a committed plan does not close its instance.
			plan2, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig().WithName("guest2"))
			require.NoError(t, err)
			mod, err := plan2.Commit(ctx)
			require.NoError(t, err)
			require.NoError(t, plan2.Close(ctx))
			_, err = mod.ExportedFunction("call").Call(ctx, 1, 2)
			require.NoError(t, err)
		})
	}
}

func TestInstantiationPlan_PlanIsImmutableAndConfigBound(t *testing.T) {
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			instantiateAddHost(t, r, ctx)
			compiled := compilePlanGuest(t, r, ctx, happyGuestModule())

			mc := NewModuleConfig().WithName("guest").WithArgs("snapshotted")
			plan, err := r.NewInstantiationPlan(ctx, compiled, mc)
			require.NoError(t, err)

			// Deriving a new config from the caller's object does not affect
			// the plan: commit binds to the prepared snapshot.
			mc2 := mc.WithArgs("different")
			require.Equal(t, []string{"snapshotted"}, plan.Args())
			_ = mc2

			mod, err := plan.Commit(ctx)
			require.NoError(t, err)
			require.Equal(t, "guest", mod.Name())
		})
	}
}

func TestInstantiationPlan_RegistryVersionBumps(t *testing.T) {
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			store := r.(*runtime).store
			v0 := store.RegistryVersion()
			host := instantiateAddHost(t, r, ctx)
			v1 := store.RegistryVersion()
			require.True(t, v1 > v0)
			require.NoError(t, host.Close(ctx))
			require.True(t, store.RegistryVersion() > v1)
		})
	}
}

// Ensure direct paths stay usable with the plan feature enabled.
func TestInstantiationPlan_DirectPathsUnaffected(t *testing.T) {
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			instantiateAddHost(t, r, ctx)
			mod, err := r.Instantiate(ctx, binaryencoding.EncodeModule(&wasm.Module{}))
			require.NoError(t, err)
			require.Equal(t, "", mod.Name()) // anonymous

			c, err := r.CompileModule(ctx, binaryencoding.EncodeModule(happyGuestModule()))
			require.NoError(t, err)
			g, err := r.InstantiateModule(ctx, c, NewModuleConfig().WithName("direct"))
			require.NoError(t, err)
			res, err := g.ExportedFunction("call").Call(ctx, 10, 20)
			require.NoError(t, err)
			require.Equal(t, uint64(30), res[0])
		})
	}
}

func TestInstantiationPlan_ImportedRequirements(t *testing.T) {
	max := uint32(5)
	// Host exports memory, a table and a global for the guest to import.
	hostMod := &wasm.Module{
		MemorySection: &wasm.Memory{Min: 2, Max: max, IsMaxEncoded: true},
		TableSection:  []wasm.Table{{Type: wasm.RefTypeFuncref, Min: 2, Max: &max}},
		GlobalSection: []wasm.Global{
			{Type: wasm.GlobalType{ValType: wasm.ValueTypeI32, Mutable: false},
				Init: wasm.NewConstantExpressionFromI32(1)},
		},
		ExportSection: []wasm.Export{
			{Name: "mem", Type: wasm.ExternTypeMemory, Index: 0},
			{Name: "tbl", Type: wasm.ExternTypeTable, Index: 0},
			{Name: "g", Type: wasm.ExternTypeGlobal, Index: 0},
		},
	}
	guest := &wasm.Module{
		ImportSection: []wasm.Import{
			{Module: "h", Name: "mem", Type: wasm.ExternTypeMemory,
				DescMem: &wasm.Memory{Min: 1, Max: max, IsMaxEncoded: true}},
			{Module: "h", Name: "tbl", Type: wasm.ExternTypeTable,
				DescTable: wasm.Table{Type: wasm.RefTypeFuncref, Min: 2, Max: &max}},
			{Module: "h", Name: "g", Type: wasm.ExternTypeGlobal,
				DescGlobal: wasm.GlobalType{ValType: wasm.ValueTypeI32}},
		},
	}
	for _, ec := range planEngineConfigs(t) {
		t.Run(ec.name, func(t *testing.T) {
			r, ctx := newPlanRuntime(t, ec.rc)
			hostCompiled := compilePlanGuest(t, r, ctx, hostMod)
			_, err := r.InstantiateModule(ctx, hostCompiled, NewModuleConfig().WithName("h"))
			require.NoError(t, err)

			compiled := compilePlanGuest(t, r, ctx, guest)
			plan, err := r.NewInstantiationPlan(ctx, compiled, NewModuleConfig().WithName("g"))
			require.NoError(t, err)

			mem := plan.MemoryRequirements()
			require.True(t, mem.Imported)
			require.Equal(t, uint32(1), mem.MinPages)
			tables := plan.TableRequirements()
			require.Equal(t, 1, len(tables))
			require.True(t, tables[0].Imported)
			globals := plan.GlobalRequirements()
			require.Equal(t, 1, len(globals))
			require.True(t, globals[0].Imported)

			mod, err := plan.Commit(ctx)
			require.NoError(t, err)
			require.Equal(t, "g", mod.Name())
		})
	}
}

func TestInstantiationPlan_CanBeExplicitlyDisabled(t *testing.T) {
	ctx := context.Background()
	rc := NewRuntimeConfigInterpreter().WithInstantiationPlan(true).WithInstantiationPlan(false)
	r := NewRuntimeWithConfig(ctx, rc)
	defer r.Close(ctx)

	compiled, err := r.CompileModule(ctx, binaryencoding.EncodeModule(&wasm.Module{}))
	require.NoError(t, err)
	_, err = r.NewInstantiationPlan(ctx, compiled, NewModuleConfig())
	require.ErrorIs(t, err, ErrInstantiationPlanDisabled)
}

func requirePlanError(t *testing.T, err error, kind PlanErrorKind) {
	t.Helper()
	require.Error(t, err)
	var pe *PlanError
	require.True(t, errors.As(err, &pe), "expected *PlanError, got %T: %v", err, err)
	require.Equal(t, kind, pe.Kind, err.Error())
}

func namedModuleCount(t *testing.T, r Runtime, name string) int {
	t.Helper()
	if m := r.Module(name); m != nil {
		return 1
	}
	return 0
}
