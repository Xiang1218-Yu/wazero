package wazero

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/tetratelabs/wazero/api"
	experimentalapi "github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/expctxkeys"
	"github.com/tetratelabs/wazero/internal/internalapi"
	internalsock "github.com/tetratelabs/wazero/internal/sock"
	"github.com/tetratelabs/wazero/internal/wasm"
	"github.com/tetratelabs/wazero/sys"
)

// ErrInstantiationPlanDisabled is returned by Runtime.NewInstantiationPlan
// when the instantiation plan capability was not enabled via
// RuntimeConfig.WithInstantiationPlan(true).
var ErrInstantiationPlanDisabled = errors.New("module instantiation plan is disabled; enable it with RuntimeConfig.WithInstantiationPlan(true)")

// ErrPlanAlreadyCommitted is returned when InstantiationPlan.Commit is
// called again after a successful commit. Re-committing a plan has no side
// effects: it does not register anything twice and does not consume the
// planned configuration again.
var ErrPlanAlreadyCommitted = errors.New("instantiation plan already committed")

// ErrPlanClosed is returned by InstantiationPlan.Commit after
// InstantiationPlan.Close was called.
var ErrPlanClosed = errors.New("instantiation plan closed")

// PlanErrorKind classifies an error detected while preparing or committing an
// InstantiationPlan. Classifications are identical for the compiler and
// interpreter engines because plan checks operate on the decoded module and
// host registry, not on engine-specific state.
type PlanErrorKind int

const (
	// PlanErrorMissingImport: an imported module namespace or export is not
	// present in the host registry.
	PlanErrorMissingImport PlanErrorKind = iota + 1
	// PlanErrorDuplicateImport: one two-level import name is imported with
	// incompatible extern kinds.
	PlanErrorDuplicateImport
	// PlanErrorSignatureMismatch: an import and its host definition disagree
	// on function signature, table type/limits, memory limits, global type or
	// tag type.
	PlanErrorSignatureMismatch
	// PlanErrorNameConflict: the planned instance name is already in use.
	PlanErrorNameConflict
	// PlanErrorWASICapability: a WASI host module, export or socket capability
	// required by the guest is not provided.
	PlanErrorWASICapability
	// PlanErrorResourceLimit: a memory, global, function or table requirement
	// conflicts with runtime limits.
	PlanErrorResourceLimit
	// PlanErrorConfigChanged: the RuntimeConfig-relevant state changed between
	// preparation and commit.
	PlanErrorConfigChanged
	// PlanErrorRegistryChanged: the host registry or its import definitions
	// changed between preparation and commit and no longer match the plan.
	PlanErrorRegistryChanged
	// PlanErrorContextCanceled: the context passed to Commit was already
	// canceled or expired.
	PlanErrorContextCanceled
)

// String implements fmt.Stringer.
func (k PlanErrorKind) String() string {
	switch k {
	case PlanErrorMissingImport:
		return "missing import"
	case PlanErrorDuplicateImport:
		return "duplicate import"
	case PlanErrorSignatureMismatch:
		return "signature mismatch"
	case PlanErrorNameConflict:
		return "module name conflict"
	case PlanErrorWASICapability:
		return "WASI capability insufficient"
	case PlanErrorResourceLimit:
		return "resource limit conflict"
	case PlanErrorConfigChanged:
		return "runtime configuration changed"
	case PlanErrorRegistryChanged:
		return "host import registry changed"
	case PlanErrorContextCanceled:
		return "context canceled"
	default:
		return fmt.Sprintf("unknown plan error kind(%d)", k)
	}
}

// PlanError is the error returned while preparing or committing an
// InstantiationPlan. Use errors.As to inspect the Kind and related import
// coordinates.
type PlanError struct {
	// Kind classifies the failure.
	Kind PlanErrorKind
	// Module is the affected import namespace, or the conflicting instance
	// name.
	Module string
	// Name is the affected import/export name when applicable.
	Name string
	// Err is the underlying cause, if any.
	Err error
}

// Error implements error.
func (e *PlanError) Error() string {
	msg := e.Kind.String()
	if e.Module != "" || e.Name != "" {
		msg += " [" + e.Module
		if e.Name != "" {
			msg += "." + e.Name
		}
		msg += "]"
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap supports errors.Is/As against the underlying cause.
func (e *PlanError) Unwrap() error { return e.Err }

// PlanExternalKind identifies the kind of an import or export recorded in a
// plan.
type PlanExternalKind = api.ExternType

// External kinds recorded in a plan.
const (
	PlanExternalKindFunc   PlanExternalKind = api.ExternTypeFunc
	PlanExternalKindTable  PlanExternalKind = api.ExternTypeTable
	PlanExternalKindMemory PlanExternalKind = api.ExternTypeMemory
	PlanExternalKindGlobal PlanExternalKind = api.ExternTypeGlobal
	// PlanExternalKindTag is the exception-handling tag extern kind.
	PlanExternalKindTag PlanExternalKind = 0x04
)

// PlanImport is an immutable snapshot of one module import and the signature
// the guest requires.
type PlanImport struct {
	// Module and Name are the two-level import coordinates.
	Module, Name string
	// Kind is the extern kind.
	Kind PlanExternalKind

	// Params and Results are the function/tag signature.
	Params, Results []api.ValueType

	// Min and Max describe memory page or table element limits.
	Min, Max uint32
	// HasMax reports whether Max is encoded.
	HasMax bool

	// ValueType is the global value type or the table reference type.
	ValueType api.ValueType
	// Mutable is the global mutability.
	Mutable bool
}

// PlanExport is an immutable snapshot of one module export. Function exports
// carry their signature.
type PlanExport struct {
	Name  string
	Kind  PlanExternalKind
	Index uint32
	// Params and Results are set for function exports.
	Params, Results []api.ValueType
}

// PlanMemoryRequirements describes the memory the instance needs.
type PlanMemoryRequirements struct {
	// Imported is true when the memory is imported rather than defined.
	Imported bool
	// MinPages is the required minimum in 64KiB pages.
	MinPages uint32
	// MaxPages is the maximum; meaningful when HasMax.
	MaxPages uint32
	// HasMax reports whether a maximum is encoded/required.
	HasMax bool
	// Shared is true for shared memories (threads proposal).
	Shared bool
}

// PlanTableRequirements describes one table the instance needs.
type PlanTableRequirements struct {
	Imported bool
	// Type is the table reference type.
	Type api.ValueType
	Min  uint32
	Max  uint32
	// HasMax reports whether Max is encoded.
	HasMax bool
}

// PlanGlobalRequirements describes one global the instance needs.
type PlanGlobalRequirements struct {
	Imported bool
	Type     api.ValueType
	Mutable  bool
}

// InstantiationPlan is an immutable, prepare-then-commit plan for
// instantiating one CompiledModule.
//
// A plan is prepared with Runtime.NewInstantiationPlan, which snapshots the
// module digest, name, import/export signatures, resource requirements, WASI
// capabilities, filesystem preopens, arguments/environment and the host
// registry version, and which fails early for missing imports, duplicate
// imports, signature mismatches, name conflicts, insufficient WASI
// capabilities and resource limit conflicts.
//
// Commit re-verifies runtime configuration, host import definitions and
// capability versions against the snapshot before creating the instance; it
// never reparses the module nor silently adopts new configuration. Any
// failure leaves no partial registration, orphan instance or unclosed
// resource. A successfully committed plan cannot be committed again.
//
// All accessors are safe to call concurrently with each other. Commit and
// Close are mutually serialized.
type InstantiationPlan interface {
	// Name is the instance name resolved at preparation ("" when anonymous).
	Name() string

	// Digest is the sha256 content digest of the compiled module.
	Digest() []byte

	// Imports returns the required imports with signatures, in binary order.
	Imports() []PlanImport
	// Exports returns the module exports, in binary order.
	Exports() []PlanExport

	// MemoryRequirements returns the required/imported memory limits.
	MemoryRequirements() PlanMemoryRequirements
	// TableRequirements returns all (imported and defined) tables.
	TableRequirements() []PlanTableRequirements
	// GlobalRequirements returns all (imported and defined) globals.
	GlobalRequirements() []PlanGlobalRequirements

	// WASICapabilities returns the sorted, unique "namespace.function"
	// imports from WASI host namespaces.
	WASICapabilities() []string

	// FilesystemPreopens returns the planned guest preopen paths in order.
	FilesystemPreopens() []string
	// Args returns the planned command-line arguments.
	Args() []string
	// Env returns the planned environment as key/value pairs in set order.
	Env() [][2]string

	// HostRegistryVersion is the host import registry version captured at
	// preparation time.
	HostRegistryVersion() uint64

	// Committed reports whether Commit already completed successfully.
	Committed() bool

	// Commit validates the plan against the current runtime state and
	// instantiates the module using prepare-then-commit semantics.
	Commit(ctx context.Context) (api.Module, error)

	// Close discards an uncommitted plan. It never closes an already
	// committed instance. It is safe to call multiple times.
	Close(ctx context.Context) error
}

// compile-time check
var _ InstantiationPlan = &instantiationPlan{}

type instantiationPlan struct {
	internalapi.WazeroOnlyType

	r    *runtime
	code *compiledModule

	mu        sync.Mutex
	closed    bool
	committed bool

	// Immutable snapshot.
	name                string
	digest              wasm.ModuleID
	mConfig             *moduleConfig
	rtEnabledFeatures   api.CoreFeatures
	rtMemoryLimitPages  uint32
	rtMemCapFromMax     bool
	rtEnsureTermination bool
	rtDwarfDisabled     bool
	rtCustomSections    bool
	hasSockConfig       bool

	registryVersion uint64
	bindings        []wasm.ResolvedImportBinding

	planImports []PlanImport
	planExports []PlanExport
	memoryReq   PlanMemoryRequirements
	tableReqs   []PlanTableRequirements
	globalReqs  []PlanGlobalRequirements
	wasiCaps    []string
	preopens    []string
	args        []string
	env         [][2]string
}

// NewInstantiationPlan implements Runtime.NewInstantiationPlan.
func (r *runtime) NewInstantiationPlan(
	ctx context.Context,
	compiled CompiledModule,
	mConfig ModuleConfig,
) (InstantiationPlan, error) {
	if !r.instantiationPlan {
		return nil, ErrInstantiationPlanDisabled
	}
	if err := r.failIfClosed(); err != nil {
		return nil, err
	}
	if compiled == nil {
		return nil, errors.New("compiled module is nil")
	}
	code, ok := compiled.(*compiledModule)
	if !ok || code == nil || code.module == nil {
		return nil, errors.New("unimplemented CompiledModule implementation")
	}
	if mConfig == nil {
		return nil, errors.New("module config is nil")
	}
	config, ok := mConfig.(*moduleConfig)
	if !ok {
		return nil, errors.New("unimplemented ModuleConfig implementation")
	}
	module := code.module

	// Snapshot the module configuration so later changes to the caller's
	// configuration cannot affect the plan.
	cfg := config.clone()
	if !module.IsHostModule {
		if sockConfig, ok := ctx.Value(internalsock.ConfigKey{}).(*internalsock.Config); ok {
			cfg.sockConfig = sockConfig
		}
	}

	// Validate args/environment without opening any resources.
	if err := cfg.validateInstantiation(); err != nil {
		return nil, err
	}

	name := cfg.name
	if !cfg.nameSet && module.NameSection != nil && module.NameSection.ModuleName != "" {
		name = module.NameSection.ModuleName
	}

	limits := wasm.PlanLimits{
		MemoryLimitPages: r.memoryLimitPages,
		HasSockConfig:    cfg.sockConfig != nil,
	}
	bindings, version, err := r.store.CheckInstantiationPlan(module, name, limits)
	if err != nil {
		return nil, mapPlanCheckError(err)
	}

	p := &instantiationPlan{
		r:                   r,
		code:                code,
		name:                name,
		digest:              module.ID,
		mConfig:             cfg,
		rtEnabledFeatures:   r.enabledFeatures,
		rtMemoryLimitPages:  r.memoryLimitPages,
		rtMemCapFromMax:     r.memoryCapacityFromMax,
		rtEnsureTermination: r.ensureTermination,
		rtDwarfDisabled:     r.dwarfDisabled,
		rtCustomSections:    r.storeCustomSections,
		hasSockConfig:       cfg.sockConfig != nil,
		registryVersion:     version,
		bindings:            bindings,
		planImports:         buildPlanImports(module),
		planExports:         buildPlanExports(module),
		memoryReq:           buildPlanMemoryRequirements(module),
		tableReqs:           buildPlanTableRequirements(module),
		globalReqs:          buildPlanGlobalRequirements(module),
		wasiCaps:            buildPlanWASICapabilities(module),
		preopens:            snapshotPreopens(cfg),
		args:                snapshotArgs(cfg),
		env:                 snapshotEnv(cfg),
	}
	return p, nil
}

func mapPlanCheckError(err error) error {
	var cpe *wasm.PlanCheckError
	if !errors.As(err, &cpe) {
		return err
	}
	var kind PlanErrorKind
	switch cpe.Kind {
	case wasm.PlanCheckMissingImport:
		kind = PlanErrorMissingImport
	case wasm.PlanCheckDuplicateImport:
		kind = PlanErrorDuplicateImport
	case wasm.PlanCheckSignatureMismatch:
		kind = PlanErrorSignatureMismatch
	case wasm.PlanCheckNameConflict:
		kind = PlanErrorNameConflict
	case wasm.PlanCheckWASICapability:
		kind = PlanErrorWASICapability
	case wasm.PlanCheckResourceLimit:
		kind = PlanErrorResourceLimit
	default:
		kind = PlanErrorSignatureMismatch
	}
	return &PlanError{Kind: kind, Module: cpe.Module, Name: cpe.Name, Err: err}
}

func buildPlanImports(module *wasm.Module) []PlanImport {
	if len(module.ImportSection) == 0 {
		return nil
	}
	ret := make([]PlanImport, 0, len(module.ImportSection))
	for i := range module.ImportSection {
		imp := &module.ImportSection[i]
		pi := PlanImport{Module: imp.Module, Name: imp.Name, Kind: imp.Type}
		switch imp.Type {
		case wasm.ExternTypeFunc:
			ft := &module.TypeSection[imp.DescFunc]
			pi.Params = wasm.ToApiValueType(ft.Params)
			pi.Results = wasm.ToApiValueType(ft.Results)
		case wasm.ExternTypeTag:
			ft := &module.TypeSection[imp.DescTag]
			pi.Params = wasm.ToApiValueType(ft.Params)
			pi.Results = wasm.ToApiValueType(ft.Results)
		case wasm.ExternTypeTable:
			pi.ValueType = api.ValueType(imp.DescTable.Type)
			pi.Min = imp.DescTable.Min
			pi.HasMax = imp.DescTable.Max != nil
			if imp.DescTable.Max != nil {
				pi.Max = *imp.DescTable.Max
			}
		case wasm.ExternTypeMemory:
			pi.Min = imp.DescMem.Min
			pi.Max = imp.DescMem.Max
			pi.HasMax = imp.DescMem.IsMaxEncoded
		case wasm.ExternTypeGlobal:
			pi.ValueType = api.ValueType(imp.DescGlobal.ValType)
			pi.Mutable = imp.DescGlobal.Mutable
		}
		ret = append(ret, pi)
	}
	return ret
}

func buildPlanExports(module *wasm.Module) []PlanExport {
	if len(module.ExportSection) == 0 {
		return nil
	}
	ret := make([]PlanExport, 0, len(module.ExportSection))
	for i := range module.ExportSection {
		exp := &module.ExportSection[i]
		pe := PlanExport{Name: exp.Name, Kind: exp.Type, Index: exp.Index}
		if exp.Type == wasm.ExternTypeFunc {
			if ft := module.TypeOfFunction(exp.Index); ft != nil {
				pe.Params = wasm.ToApiValueType(ft.Params)
				pe.Results = wasm.ToApiValueType(ft.Results)
			}
		}
		ret = append(ret, pe)
	}
	return ret
}

func buildPlanMemoryRequirements(module *wasm.Module) PlanMemoryRequirements {
	for i := range module.ImportSection {
		imp := &module.ImportSection[i]
		if imp.Type == wasm.ExternTypeMemory {
			return PlanMemoryRequirements{
				Imported: true,
				MinPages: imp.DescMem.Min,
				MaxPages: imp.DescMem.Max,
				HasMax:   imp.DescMem.IsMaxEncoded,
				Shared:   imp.DescMem.IsShared,
			}
		}
	}
	if mem := module.MemorySection; mem != nil {
		return PlanMemoryRequirements{
			MinPages: mem.Min,
			MaxPages: mem.Max,
			HasMax:   mem.IsMaxEncoded,
			Shared:   mem.IsShared,
		}
	}
	return PlanMemoryRequirements{}
}

func buildPlanTableRequirements(module *wasm.Module) []PlanTableRequirements {
	total := int(module.ImportTableCount) + len(module.TableSection)
	if total == 0 {
		return nil
	}
	ret := make([]PlanTableRequirements, 0, total)
	for i := range module.ImportSection {
		imp := &module.ImportSection[i]
		if imp.Type != wasm.ExternTypeTable {
			continue
		}
		t := PlanTableRequirements{
			Imported: true,
			Type:     api.ValueType(imp.DescTable.Type),
			Min:      imp.DescTable.Min,
			HasMax:   imp.DescTable.Max != nil,
		}
		if imp.DescTable.Max != nil {
			t.Max = *imp.DescTable.Max
		}
		ret = append(ret, t)
	}
	for i := range module.TableSection {
		t := &module.TableSection[i]
		req := PlanTableRequirements{
			Type:   api.ValueType(t.Type),
			Min:    t.Min,
			HasMax: t.Max != nil,
		}
		if t.Max != nil {
			req.Max = *t.Max
		}
		ret = append(ret, req)
	}
	return ret
}

func buildPlanGlobalRequirements(module *wasm.Module) []PlanGlobalRequirements {
	total := int(module.ImportGlobalCount) + len(module.GlobalSection)
	if total == 0 {
		return nil
	}
	ret := make([]PlanGlobalRequirements, 0, total)
	for i := range module.ImportSection {
		imp := &module.ImportSection[i]
		if imp.Type != wasm.ExternTypeGlobal {
			continue
		}
		ret = append(ret, PlanGlobalRequirements{
			Imported: true,
			Type:     api.ValueType(imp.DescGlobal.ValType),
			Mutable:  imp.DescGlobal.Mutable,
		})
	}
	for i := range module.GlobalSection {
		g := &module.GlobalSection[i]
		ret = append(ret, PlanGlobalRequirements{
			Type:    api.ValueType(g.Type.ValType),
			Mutable: g.Type.Mutable,
		})
	}
	return ret
}

func buildPlanWASICapabilities(module *wasm.Module) []string {
	seen := map[string]struct{}{}
	for i := range module.ImportSection {
		imp := &module.ImportSection[i]
		if imp.Type != wasm.ExternTypeFunc {
			continue
		}
		if imp.Module != "wasi_snapshot_preview1" && imp.Module != "wasi_unstable" {
			continue
		}
		seen[imp.Module+"."+imp.Name] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	ret := make([]string, 0, len(seen))
	for name := range seen {
		ret = append(ret, name)
	}
	sort.Strings(ret)
	return ret
}

func snapshotPreopens(cfg *moduleConfig) []string {
	if f, ok := cfg.fsConfig.(*fsConfig); ok {
		_, guestPaths := f.preopens()
		return guestPaths
	}
	return nil
}

func snapshotArgs(cfg *moduleConfig) []string {
	if len(cfg.args) == 0 {
		return nil
	}
	ret := make([]string, len(cfg.args))
	for i, a := range cfg.args {
		ret[i] = string(a)
	}
	return ret
}

func snapshotEnv(cfg *moduleConfig) [][2]string {
	if len(cfg.environ) == 0 {
		return nil
	}
	ret := make([][2]string, 0, len(cfg.environ)/2)
	for i := 0; i+1 < len(cfg.environ); i += 2 {
		ret = append(ret, [2]string{string(cfg.environ[i]), string(cfg.environ[i+1])})
	}
	return ret
}

// Accessors.

func (p *instantiationPlan) Name() string          { return p.name }
func (p *instantiationPlan) Digest() []byte        { return append([]byte(nil), p.digest[:]...) }
func (p *instantiationPlan) Imports() []PlanImport { return p.planImports }
func (p *instantiationPlan) Exports() []PlanExport { return p.planExports }
func (p *instantiationPlan) MemoryRequirements() PlanMemoryRequirements {
	return p.memoryReq
}
func (p *instantiationPlan) TableRequirements() []PlanTableRequirements   { return p.tableReqs }
func (p *instantiationPlan) GlobalRequirements() []PlanGlobalRequirements { return p.globalReqs }
func (p *instantiationPlan) WASICapabilities() []string                   { return p.wasiCaps }
func (p *instantiationPlan) FilesystemPreopens() []string                 { return p.preopens }
func (p *instantiationPlan) Args() []string                               { return p.args }
func (p *instantiationPlan) Env() [][2]string                             { return p.env }
func (p *instantiationPlan) HostRegistryVersion() uint64                  { return p.registryVersion }

func (p *instantiationPlan) Committed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.committed
}

func (p *instantiationPlan) Close(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

// Commit implements InstantiationPlan.Commit.
func (p *instantiationPlan) Commit(ctx context.Context) (mod api.Module, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrPlanClosed
	}
	if p.committed {
		// Idempotency guard: no re-registration, no configuration consumption.
		return nil, ErrPlanAlreadyCommitted
	}

	r := p.r
	if err = r.failIfClosed(); err != nil {
		return nil, err
	}

	// 1. The RuntimeConfig-relevant state must still match the plan.
	if r.enabledFeatures != p.rtEnabledFeatures ||
		r.memoryLimitPages != p.rtMemoryLimitPages ||
		r.memoryCapacityFromMax != p.rtMemCapFromMax ||
		r.ensureTermination != p.rtEnsureTermination ||
		r.dwarfDisabled != p.rtDwarfDisabled ||
		r.storeCustomSections != p.rtCustomSections {
		return nil, &PlanError{Kind: PlanErrorConfigChanged}
	}
	// Content digest is immutable for a CompiledModule; verify it regardless.
	if p.code.module.ID != p.digest {
		return nil, &PlanError{Kind: PlanErrorConfigChanged,
			Err: errors.New("compiled module content digest differs from the plan")}
	}

	// 2. The host registry and its import definitions must still match the
	// plan. An unchanged version is a fast path; otherwise re-validate fully
	// and compare the binding snapshots.
	limits := wasm.PlanLimits{
		MemoryLimitPages: p.rtMemoryLimitPages,
		HasSockConfig:    p.hasSockConfig,
	}
	if currentVersion := r.store.RegistryVersion(); currentVersion != p.registryVersion {
		bindings, _, checkErr := r.store.CheckInstantiationPlan(p.code.module, p.name, limits)
		if checkErr != nil {
			return nil, &PlanError{Kind: PlanErrorRegistryChanged, Err: mapPlanCheckError(checkErr)}
		}
		if !wasm.ResolvedBindingsEqual(bindings, p.bindings) {
			return nil, &PlanError{Kind: PlanErrorRegistryChanged,
				Err: fmt.Errorf("host import definitions for module[%s] changed since the plan was prepared", p.name)}
		}
		// Definitions are still equal: only unrelated registry entries moved.
		// The plan snapshot stays immutable.
	}

	// 3. Cancellation is checked before any resource is created.
	if err = ctx.Err(); err != nil {
		return nil, &PlanError{Kind: PlanErrorContextCanceled, Err: err}
	}

	// 4. Prepare instance resources from the planned configuration only.
	sysCtx, err := p.mConfig.toSysContext()
	if err != nil {
		return nil, err
	}
	typeIDs, err := r.store.GetFunctionTypeIDs(p.code.module.TypeSection)
	if err != nil {
		_ = sysCtx.FS().Close()
		return nil, err
	}

	// 5. Prepare-then-commit: the store fully builds, links and starts the
	// instance before publishing it; on any failure the half-built instance
	// is closed, leaving no partial registration or unclosed resource.
	mi, err := r.store.CommitInstantiation(ctx, p.code.module, p.name, sysCtx, typeIDs)
	if err != nil {
		return nil, err
	}

	// Post-registration hooks mirror Runtime.InstantiateModule.
	if closeNotifier, ok := ctx.Value(expctxkeys.CloseNotifierKey{}).(experimentalapi.CloseNotifier); ok {
		mi.CloseNotifier = closeNotifier
	}
	if p.code.closeWithModule {
		mi.CodeCloser = p.code
	}

	// 6. Run configured start functions. Failure rolls back the instance.
	for _, fn := range p.mConfig.startFunctions {
		start := mi.ExportedFunction(fn)
		if start == nil {
			continue
		}
		if _, err = start.Call(ctx); err != nil {
			_ = mi.Close(ctx) // No orphan instance, no partial registration.

			if se, ok := err.(*sys.ExitError); ok {
				if se.ExitCode() == 0 { // Don't err on success.
					// Mirrors Runtime.InstantiateModule: exit code 0 closes the
					// instance and is reported without error.
					p.committed = true
					return mi, nil
				}
				return nil, se // Don't wrap an exit error.
			}
			return nil, fmt.Errorf("module[%s] function[%s] failed: %w", p.name, fn, err)
		}
	}

	p.committed = true
	return mi, nil
}
