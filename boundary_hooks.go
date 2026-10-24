package wazero

import (
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/internal/boundary"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// boundaryBuildManifest computes the module digest and the canonical list of
// imported/exported function signatures for the execution log manifest.
func boundaryBuildManifest(bin []byte, imports []api.FunctionDefinition,
	exports map[string]api.FunctionDefinition) (mf boundary.Manifest) {
	mf.ModuleSHA = sha256.Sum256(bin)
	mf.Sigs = boundaryCanonicalSigs(imports, exports)
	return
}

// boundaryCanonicalSigs returns a deterministic ordering of imported and
// exported function signatures.
func boundaryCanonicalSigs(imports []api.FunctionDefinition,
	exports map[string]api.FunctionDefinition) []boundary.Sig {
	type sigKey struct {
		isImport       bool
		module, name   string
		params, result []byte
	}
	keys := make([]sigKey, 0, len(imports)+len(exports))
	for _, d := range imports {
		mod, name, _ := d.Import()
		keys = append(keys, sigKey{true, mod, name,
			append([]byte(nil), d.ParamTypes()...), append([]byte(nil), d.ResultTypes()...)})
	}
	for name, d := range exports {
		keys = append(keys, sigKey{false, "", name,
			append([]byte(nil), d.ParamTypes()...), append([]byte(nil), d.ResultTypes()...)})
	}
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.isImport != b.isImport {
			return a.isImport
		}
		if a.module != b.module {
			return a.module < b.module
		}
		return a.name < b.name
	})
	sigs := make([]boundary.Sig, 0, len(keys))
	for _, k := range keys {
		sigs = append(sigs, boundary.Sig{
			Import: k.isImport, Module: k.module, Name: k.name,
			Params: k.params, Results: k.result,
		})
	}
	return sigs
}

// boundarySigsFromCompiled mirrors boundaryBuildManifest using the public
// CompiledModule view, used by the explicit pre-replay verification API.
func boundarySigsFromCompiled(cm CompiledModule) []boundary.Sig {
	return boundaryCanonicalSigs(cm.ImportedFunctions(), cm.ExportedFunctions())
}

// wrapBoundaryModule installs record/replay interception on every Go host
// function of a freshly built, private host module.
func wrapBoundaryModule(sess *boundary.Session, hostModuleName string, m *wasm.Module) error {
	for idx := range m.CodeSection {
		typeIdx := m.FunctionSection[idx]
		if int(typeIdx) >= len(m.TypeSection) {
			continue
		}
		ft := &m.TypeSection[typeIdx]
		params := valueTypeBytes(ft.Params)
		results := valueTypeBytes(ft.Results)
		exportName := ""
		if uint32(idx) < uint32(len(m.ExportSection)) {
			exportName = m.ExportSection[idx].Name
		}
		code := &m.CodeSection[idx]
		switch g := code.GoFunc.(type) {
		case api.GoModuleFunction:
			code.GoFunc = sess.WrapGoModuleFunction(hostModuleName, exportName, params, results, g)
		case api.GoFunction:
			code.GoFunc = sess.WrapGoFunction(hostModuleName, exportName, params, results, g)
		default:
			return fmt.Errorf("boundary: host function %s.%s has unsupported GoFunc type %T", hostModuleName, exportName, g)
		}
	}
	return nil
}

func valueTypeBytes(vs []wasm.ValueType) []byte {
	out := make([]byte, len(vs))
	for i, v := range vs {
		out[i] = byte(v)
	}
	return out
}

// boundaryBuildConfigFP fingerprints the module configuration.
func boundaryBuildConfigFP(c *moduleConfig) boundary.ConfigFP {
	fp := boundary.ConfigFP{
		Name:               c.name,
		NameSet:            c.nameSet,
		StartFunctions:     append([]string(nil), c.startFunctions...),
		Args:               c.args,
		Environ:            c.environ,
		WalltimeResolution: uint64(c.walltimeResolution),
		NanotimeResolution: uint64(c.nanotimeResolution),
		HasCustomWalltime:  c.walltime != nil,
		HasCustomNanotime:  c.nanotime != nil,
		HasCustomNanosleep: c.nanosleep != nil,
		HasRandSource:      c.randSource != nil,
		HasStdin:           c.stdin != nil,
		HasStdout:          c.stdout != nil,
		HasStderr:          c.stderr != nil,
		HasTCPListeners:    c.sockConfig != nil,
	}
	if f, ok := c.fsConfig.(*fsConfig); ok {
		_, fp.GuestPaths = f.preopens()
	}
	return fp
}
