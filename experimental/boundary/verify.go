package boundary

import (
	"sort"

	"github.com/tetratelabs/wazero"
	ib "github.com/tetratelabs/wazero/internal/boundary"
)

// boundarySigs builds the canonical signature list from a CompiledModule.
func boundarySigs(cm wazero.CompiledModule) []ib.Sig {
	type sigKey struct {
		isImport        bool
		module, name    string
		params, results []byte
	}
	keys := make([]sigKey, 0)
	for _, d := range cm.ImportedFunctions() {
		mod, name, _ := d.Import()
		keys = append(keys, sigKey{true, mod, name,
			append([]byte(nil), d.ParamTypes()...), append([]byte(nil), d.ResultTypes()...)})
	}
	for name, d := range cm.ExportedFunctions() {
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
	sigs := make([]ib.Sig, 0, len(keys))
	for _, k := range keys {
		sigs = append(sigs, ib.Sig{Import: k.isImport, Module: k.module, Name: k.name,
			Params: k.params, Results: k.results})
	}
	return sigs
}
