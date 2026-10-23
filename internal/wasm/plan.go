package wasm

import (
	"context"
	"fmt"
	"sort"
	"strings"

	internalsys "github.com/tetratelabs/wazero/internal/sys"
)

// PlanCheckKind classifies a problem detected while preparing an
// instantiation plan. The same classification is produced regardless of the
// underlying execution engine (compiler or interpreter), because plan checking
// runs against the decoded module and the store registry only.
type PlanCheckKind int

const (
	// PlanCheckMissingImport indicates an imported module or export is absent
	// from the host registry.
	PlanCheckMissingImport PlanCheckKind = iota + 1
	// PlanCheckDuplicateImport indicates the same two-level import name is
	// imported with incompatible extern kinds.
	PlanCheckDuplicateImport
	// PlanCheckSignatureMismatch indicates a supplied import fails the type,
	// signature, limits or mutability matching required by the guest.
	PlanCheckSignatureMismatch
	// PlanCheckNameConflict indicates the planned instance name is already
	// registered in the store.
	PlanCheckNameConflict
	// PlanCheckWASICapability indicates the guest requires a WASI capability
	// (an absent WASI host module/export or socket support) that is not
	// provided.
	PlanCheckWASICapability
	// PlanCheckResourceLimit indicates a resource requirement (memory,
	// globals, functions or tables) conflicts with runtime limits.
	PlanCheckResourceLimit
)

// String implements fmt.Stringer.
func (k PlanCheckKind) String() string {
	switch k {
	case PlanCheckMissingImport:
		return "missing import"
	case PlanCheckDuplicateImport:
		return "duplicate import"
	case PlanCheckSignatureMismatch:
		return "signature mismatch"
	case PlanCheckNameConflict:
		return "module name conflict"
	case PlanCheckWASICapability:
		return "WASI capability insufficient"
	case PlanCheckResourceLimit:
		return "resource limit conflict"
	default:
		return fmt.Sprintf("unknown plan check kind(%d)", k)
	}
}

// PlanCheckError is the engine-independent error raised while validating an
// instantiation plan.
type PlanCheckError struct {
	// Kind classifies the problem.
	Kind PlanCheckKind
	// Module is the import namespace (or the conflicting instance name).
	Module string
	// Name is the conflicting import/export name, when applicable.
	Name string
	// detail carries the human-readable cause.
	detail error
}

// Error implements error.
func (e *PlanCheckError) Error() string {
	var b strings.Builder
	b.WriteString(e.Kind.String())
	if e.Module != "" || e.Name != "" {
		b.WriteString(" [")
		b.WriteString(e.Module)
		if e.Name != "" {
			b.WriteByte('.')
			b.WriteString(e.Name)
		}
		b.WriteByte(']')
	}
	if e.detail != nil {
		b.WriteString(": ")
		b.WriteString(e.detail.Error())
	}
	return b.String()
}

// Unwrap allows errors.Is/As against the underlying cause.
func (e *PlanCheckError) Unwrap() error { return e.detail }

// PlanLimits carries runtime-side limits and capabilities used while checking
// a plan.
type PlanLimits struct {
	// MemoryLimitPages is the runtime configured maximum number of 64KiB
	// memory pages.
	MemoryLimitPages uint32
	// HasSockConfig is true when socket pre-configuration is available to the
	// instance.
	HasSockConfig bool
}

// ResolvedImportBinding is an immutable snapshot of how one guest import binds
// to the current host registry. Commit compares freshly resolved bindings with
// the snapshot to detect host definition drift without reparsing the module.
type ResolvedImportBinding struct {
	Module string
	Name   string
	Type   ExternType

	// Host function signature snapshot.
	HostFuncParams  []ValueType
	HostFuncResults []ValueType

	// Host table snapshot.
	HostTableType     ValueType
	HostTableMin      uint32
	HostTableMax      uint32
	HostTableHasMax   bool
	HostMemMinPages   uint32
	HostMemMaxPages   uint32
	HostGlobalValType ValueType
	HostGlobalMutable bool
	HostTagParams     []ValueType
	HostTagResults    []ValueType
}

func (b ResolvedImportBinding) equal(o ResolvedImportBinding) bool {
	if b.Module != o.Module || b.Name != o.Name || b.Type != o.Type ||
		b.HostTableType != o.HostTableType || b.HostTableMin != o.HostTableMin ||
		b.HostTableMax != o.HostTableMax || b.HostTableHasMax != o.HostTableHasMax ||
		b.HostMemMinPages != o.HostMemMinPages || b.HostMemMaxPages != o.HostMemMaxPages ||
		b.HostGlobalValType != o.HostGlobalValType || b.HostGlobalMutable != o.HostGlobalMutable {
		return false
	}
	return valueTypesEqual(b.HostFuncParams, o.HostFuncParams) &&
		valueTypesEqual(b.HostFuncResults, o.HostFuncResults) &&
		valueTypesEqual(b.HostTagParams, o.HostTagParams) &&
		valueTypesEqual(b.HostTagResults, o.HostTagResults)
}

func valueTypesEqual(a, b []ValueType) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ResolvedBindingsEqual reports whether two binding snapshots describe the
// same host definitions.
func ResolvedBindingsEqual(a, b []ResolvedImportBinding) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].equal(b[i]) {
			return false
		}
	}
	return true
}

// wasiModuleNames are the host namespaces treated as WASI capability
// providers.
var wasiModuleNames = map[string]bool{
	"wasi_snapshot_preview1": true,
	"wasi_unstable":          true,
}

func isWASINamespace(moduleName string) bool { return wasiModuleNames[moduleName] }

// TypeOfFunction is the exported view of Module.typeOfFunction for use by the
// instantiation plan implementation.
func (m *Module) TypeOfFunction(funcIdx Index) *FunctionType {
	return m.typeOfFunction(funcIdx)
}

// CheckInstantiationPlan performs all read-only validations needed to prepare
// a module instantiation:
//   - module name conflict with registered instances,
//   - missing / duplicate imports against the current host registry,
//   - import signature, table, memory, global and tag matching,
//   - WASI capability availability (host module, exports, sockets),
//   - resource limit conflicts (memory pages plus section count limits).
//
// The registry is snapshotted under a single read lock, so the returned
// version exactly identifies the registry state the checks ran against.
// Bindings snapshot host-side definitions in import-section order.
//
// This never mutates the registry, module instances or engine state.
func (s *Store) CheckInstantiationPlan(module *Module, name string, limits PlanLimits) (
	bindings []ResolvedImportBinding, version uint64, err error,
) {
	instances, version := s.SnapshotRegistryForPlan()
	if err = checkPlanNameConflict(name, instances); err != nil {
		return nil, version, err
	}
	bindings, err = checkPlanImports(module, instances, limits)
	if err != nil {
		return nil, version, err
	}
	if err = checkPlanResourceLimits(module, limits); err != nil {
		return nil, version, err
	}
	return bindings, version, nil
}

// SnapshotRegistryForPlan atomically returns the current registry version and
// a copy of the namespace to ModuleInstance mapping. Exported for the
// instantiation plan implementation.
func (s *Store) SnapshotRegistryForPlan() (map[string]*ModuleInstance, uint64) {
	s.mux.RLock()
	defer s.mux.RUnlock()
	instances := make(map[string]*ModuleInstance, len(s.nameToModule))
	for k, v := range s.nameToModule {
		instances[k] = v
	}
	return instances, s.registryVersion
}

func checkPlanNameConflict(name string, instances map[string]*ModuleInstance) error {
	if name == "" {
		return nil // Anonymous modules never conflict.
	}
	if m := instances[name]; m != nil {
		return &PlanCheckError{
			Kind:   PlanCheckNameConflict,
			Module: name,
			detail: fmt.Errorf("module[%s] has already been instantiated", name),
		}
	}
	return nil
}

func checkPlanImports(module *Module, instances map[string]*ModuleInstance, limits PlanLimits) ([]ResolvedImportBinding, error) {
	bindings := make([]ResolvedImportBinding, 0, len(module.ImportSection))

	// Sort namespaces so error ordering is deterministic for callers.
	namespaces := make([]string, 0, len(module.ImportPerModule))
	for moduleName := range module.ImportPerModule {
		namespaces = append(namespaces, moduleName)
	}
	sort.Strings(namespaces)

	// seen records the extern kind of each two-level import name to detect
	// incompatible duplicate imports.
	seen := map[string]ExternType{}
	for _, moduleName := range namespaces {
		importedModule, present := instances[moduleName]
		if !present {
			if isWASINamespace(moduleName) {
				return nil, &PlanCheckError{
					Kind:   PlanCheckWASICapability,
					Module: moduleName,
					detail: fmt.Errorf("WASI host module %q is not instantiated", moduleName),
				}
			}
			return nil, &PlanCheckError{
				Kind:   PlanCheckMissingImport,
				Module: moduleName,
				detail: fmt.Errorf("module[%s] not instantiated", moduleName),
			}
		}

		for _, i := range module.ImportPerModule[moduleName] {
			seenKey := i.Module + "\x00" + i.Name
			if prior, ok := seen[seenKey]; ok && prior != i.Type {
				return nil, &PlanCheckError{
					Kind:   PlanCheckDuplicateImport,
					Module: i.Module,
					Name:   i.Name,
					detail: fmt.Errorf("imported as both %s and %s",
						ExternTypeName(prior), ExternTypeName(i.Type)),
				}
			}
			seen[seenKey] = i.Type

			binding, err := checkPlanImport(module, importedModule, i, limits)
			if err != nil {
				return nil, err
			}
			bindings = append(bindings, binding)
		}
	}
	return bindings, nil
}

func checkPlanImport(module *Module, importedModule *ModuleInstance, i *Import, limits PlanLimits) (ResolvedImportBinding, error) {
	binding := ResolvedImportBinding{Module: i.Module, Name: i.Name, Type: i.Type}

	export, err := importedModule.getExport(i.Name, i.Type)
	if err != nil {
		kind := PlanCheckMissingImport
		if isWASINamespace(i.Module) {
			kind = PlanCheckWASICapability
		}
		return binding, &PlanCheckError{Kind: kind, Module: i.Module, Name: i.Name, detail: err}
	}

	switch i.Type {
	case ExternTypeFunc:
		expectedType := &module.TypeSection[i.DescFunc]
		src := importedModule.Source
		actual := src.typeOfFunction(export.Index)
		if actual == nil {
			return binding, &PlanCheckError{
				Kind: PlanCheckSignatureMismatch, Module: i.Module, Name: i.Name,
				detail: fmt.Errorf("exported function index %d has no type", export.Index),
			}
		}
		binding.HostFuncParams = append([]ValueType(nil), actual.Params...)
		binding.HostFuncResults = append([]ValueType(nil), actual.Results...)
		if !actual.EqualsSignature(expectedType.Params, expectedType.Results) {
			return binding, &PlanCheckError{
				Kind: PlanCheckSignatureMismatch, Module: i.Module, Name: i.Name,
				detail: fmt.Errorf("signature mismatch: %s != %s", expectedType, actual),
			}
		}
		if isWASINamespace(i.Module) && strings.HasPrefix(i.Name, "sock_") && !limits.HasSockConfig {
			return binding, &PlanCheckError{
				Kind: PlanCheckWASICapability, Module: i.Module, Name: i.Name,
				detail: fmt.Errorf("WASI socket capability %q is used without a socket configuration", i.Name),
			}
		}
	case ExternTypeTable:
		expected := i.DescTable
		importedTable := importedModule.Tables[export.Index]
		binding.HostTableType = importedTable.Type
		binding.HostTableMin = importedTable.Min
		if importedTable.Max != nil {
			binding.HostTableHasMax = true
			binding.HostTableMax = *importedTable.Max
		}
		if expected.Type != importedTable.Type {
			return binding, &PlanCheckError{
				Kind: PlanCheckSignatureMismatch, Module: i.Module, Name: i.Name,
				detail: fmt.Errorf("table type mismatch: %s != %s",
					RefTypeName(expected.Type), RefTypeName(importedTable.Type)),
			}
		}
		if uint64(expected.Min) > uint64(len(importedTable.References)) {
			return binding, &PlanCheckError{
				Kind: PlanCheckSignatureMismatch, Module: i.Module, Name: i.Name,
				detail: fmt.Errorf("minimum size mismatch: %d > %d", expected.Min, importedTable.Min),
			}
		}
		if expected.Max != nil {
			expectedMax := *expected.Max
			if importedTable.Max == nil {
				return binding, &PlanCheckError{
					Kind: PlanCheckSignatureMismatch, Module: i.Module, Name: i.Name,
					detail: fmt.Errorf("maximum size mismatch: %d, but actual has no max", expectedMax),
				}
			} else if expectedMax < *importedTable.Max {
				return binding, &PlanCheckError{
					Kind: PlanCheckSignatureMismatch, Module: i.Module, Name: i.Name,
					detail: fmt.Errorf("maximum size mismatch: %d < %d", expectedMax, *importedTable.Max),
				}
			}
		}
	case ExternTypeMemory:
		expected := i.DescMem
		importedMemory := importedModule.MemoryInstance
		hostMin := memoryBytesNumToPages(uint64(len(importedMemory.Buffer)))
		// Snapshot the declared limits for drift detection: the memory may
		// grow between preparation and commit, but matching uses its size.
		binding.HostMemMinPages = importedMemory.Min
		binding.HostMemMaxPages = importedMemory.Max
		if expected.Min > hostMin {
			return binding, &PlanCheckError{
				Kind: PlanCheckSignatureMismatch, Module: i.Module, Name: i.Name,
				detail: fmt.Errorf("minimum size mismatch: %d > %d", expected.Min, importedMemory.Min),
			}
		}
		if expected.Max < importedMemory.Max {
			return binding, &PlanCheckError{
				Kind: PlanCheckSignatureMismatch, Module: i.Module, Name: i.Name,
				detail: fmt.Errorf("maximum size mismatch: %d < %d", expected.Max, importedMemory.Max),
			}
		}
	case ExternTypeGlobal:
		expected := i.DescGlobal
		importedGlobal := importedModule.Globals[export.Index]
		binding.HostGlobalValType = importedGlobal.Type.ValType
		binding.HostGlobalMutable = importedGlobal.Type.Mutable
		if expected.Mutable != importedGlobal.Type.Mutable {
			return binding, &PlanCheckError{
				Kind: PlanCheckSignatureMismatch, Module: i.Module, Name: i.Name,
				detail: fmt.Errorf("mutability mismatch: %t != %t",
					expected.Mutable, importedGlobal.Type.Mutable),
			}
		}
		if expected.Mutable && expected.ValType != importedGlobal.Type.ValType ||
			!expected.Mutable && !isRefSubtypeOf(importedGlobal.Type.ValType, expected.ValType) {
			return binding, &PlanCheckError{
				Kind: PlanCheckSignatureMismatch, Module: i.Module, Name: i.Name,
				detail: fmt.Errorf("value type mismatch: %s != %s",
					ValueTypeName(expected.ValType), ValueTypeName(importedGlobal.Type.ValType)),
			}
		}
	case ExternTypeTag:
		expected := &module.TypeSection[i.DescTag]
		importedTag := importedModule.Tags[export.Index]
		binding.HostTagParams = append([]ValueType(nil), importedTag.Type.Params...)
		binding.HostTagResults = append([]ValueType(nil), importedTag.Type.Results...)
		if !importedTag.Type.EqualsType(expected) {
			return binding, &PlanCheckError{
				Kind: PlanCheckSignatureMismatch, Module: i.Module, Name: i.Name,
				detail: fmt.Errorf("tag type mismatch: %s != %s", expected, importedTag.Type),
			}
		}
	default:
		return binding, &PlanCheckError{
			Kind: PlanCheckSignatureMismatch, Module: i.Module, Name: i.Name,
			detail: fmt.Errorf("unknown extern type %d", i.Type),
		}
	}
	return binding, nil
}

func checkPlanResourceLimits(module *Module, limits PlanLimits) error {
	if mem := module.MemorySection; mem != nil {
		if mem.Min > limits.MemoryLimitPages {
			return &PlanCheckError{
				Kind: PlanCheckResourceLimit,
				detail: fmt.Errorf("memory minimum %d pages exceeds runtime limit of %d pages",
					mem.Min, limits.MemoryLimitPages),
			}
		}
		if mem.IsMaxEncoded && mem.Max > limits.MemoryLimitPages {
			return &PlanCheckError{
				Kind: PlanCheckResourceLimit,
				detail: fmt.Errorf("memory maximum %d pages exceeds runtime limit of %d pages",
					mem.Max, limits.MemoryLimitPages),
			}
		}
	}
	if uint64(module.ImportGlobalCount)+uint64(len(module.GlobalSection)) > uint64(MaximumGlobals) {
		return &PlanCheckError{
			Kind:   PlanCheckResourceLimit,
			detail: fmt.Errorf("global count exceeds maximum %d", MaximumGlobals),
		}
	}
	if uint64(module.ImportFunctionCount)+uint64(len(module.FunctionSection)) > uint64(MaximumFunctionIndex) {
		return &PlanCheckError{
			Kind:   PlanCheckResourceLimit,
			detail: fmt.Errorf("function count exceeds maximum %d", MaximumFunctionIndex),
		}
	}
	if uint64(module.ImportTableCount)+uint64(len(module.TableSection)) > uint64(MaximumTableIndex) {
		return &PlanCheckError{
			Kind:   PlanCheckResourceLimit,
			detail: fmt.Errorf("table count exceeds maximum %d", MaximumTableIndex),
		}
	}
	return nil
}

// RegistryVersion returns a monotonically increasing version of the host
// registry. The version changes whenever a named module is registered or
// removed. It is read under the store lock and is safe for concurrent use.
func (s *Store) RegistryVersion() uint64 {
	s.mux.RLock()
	defer s.mux.RUnlock()
	return s.registryVersion
}

// CommitInstantiation prepares and publishes a module instance with
// prepare-then-commit semantics: the instance is fully built, linked,
// resource-initialized and start-section-executed before being registered;
// registration is the single visibility point. Any failure rolls back the
// half-built instance (closing its system and memory resources) and leaves
// the store untouched.
//
// This is the commit path used by instantiation plans; the behavior of a
// successful commit is identical to Store.Instantiate.
func (s *Store) CommitInstantiation(
	ctx context.Context,
	module *Module,
	name string,
	sysCtx *internalsys.Context,
	typeIDs []FunctionTypeID,
) (*ModuleInstance, error) {
	m, err := s.instantiate(ctx, module, name, sysCtx, typeIDs)
	if err != nil {
		if m != nil {
			// Release the unregistered, half-built instance's resources.
			_ = m.Close(ctx)
		} else if sysCtx != nil {
			_ = sysCtx.FS().Close()
		}
		return nil, err
	}

	// Publish: this is the only point at which the instance becomes visible.
	if err = s.registerModule(m); err != nil {
		_ = m.Close(ctx)
		return nil, err
	}
	return m, nil
}
