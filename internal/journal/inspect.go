package journal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/tetratelabs/wazero/api"
	internalsys "github.com/tetratelabs/wazero/internal/sys"
	"github.com/tetratelabs/wazero/internal/version"
	"github.com/tetratelabs/wazero/internal/wasm"
	"github.com/tetratelabs/wazero/sys"
)

// EngineKind normalizes the concrete engine of a module instance.
func EngineKind(inst *wasm.ModuleInstance) string {
	t := fmt.Sprintf("%T", inst.Engine)
	switch {
	case strings.Contains(t, "interpreter"):
		return "interpreter"
	default:
		// wazevo and any future compiled engine share the same host-call
		// boundary, so they produce the same event stream.
		return "compiler"
	}
}

// BuildHeader captures the identity and configuration digest of one
// Function.Call before it starts.
func BuildHeader(inst *wasm.ModuleInstance, fn api.Function, params []uint64) Header {
	h := Header{
		WazeroVersion: version.GetWazeroVersion(),
		Engine:        EngineKind(inst),
		Features:      uint64(inst.EnabledFeatures()),
		ModuleID:      inst.Source.ID,
		ModuleName:    inst.ModuleName,
		Params:        cloneU64(params),
	}
	if fn != nil && fn.Definition() != nil {
		h.FunctionName = fn.Definition().DebugName()
	}
	if h.ModuleID == ([32]byte{}) {
		// Host modules and other modules without a binary ID get a stable
		// synthetic digest.
		h.ModuleID = sha256.Sum256([]byte("module:" + h.ModuleName))
	}
	h.Imports = importManifest(inst.Source)

	h.RuntimeDigest = runtimeDigest(h.WazeroVersion, h.Engine, h.Features)
	h.ModuleConfigDigest = moduleConfigDigest(inst.Sys)

	if inst.MemoryInstance != nil && len(inst.MemoryInstance.Buffer) > 0 {
		h.InitPages = memoryPages(uint32(len(inst.MemoryInstance.Buffer)))
		h.InitMemoryHash = sha256.Sum256(inst.MemoryInstance.Buffer)
	}
	return h
}

func runtimeDigest(wazeroVersion, engine string, features uint64) [32]byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "wazero=%s|engine=%s|journal=%d|features=0x%x",
		wazeroVersion, engine, FormatVersion, features)
	return sha256.Sum256(b.Bytes())
}

func moduleConfigDigest(sysCtx *internalsys.Context) [32]byte {
	var b bytes.Buffer
	if sysCtx != nil {
		for _, a := range sysCtx.Args() {
			b.Write(a)
			b.WriteByte(0)
		}
		b.WriteByte('|')
		for _, e := range sysCtx.Environ() {
			b.Write(e)
			b.WriteByte(0)
		}
	}
	return sha256.Sum256(b.Bytes())
}

func importManifest(m *wasm.Module) []ImportSig {
	if len(m.ImportSection) == 0 {
		return nil
	}
	out := make([]ImportSig, 0, len(m.ImportSection))
	for _, imp := range m.ImportSection {
		sig := ImportSig{Module: imp.Module, Name: imp.Name}
		switch imp.Type {
		case wasm.ExternTypeFunc:
			sig.Kind = externFunc
			if int(imp.DescFunc) < len(m.TypeSection) {
				ft := &m.TypeSection[imp.DescFunc]
				sig.Params = valueTypes(ft.Params)
				sig.Results = valueTypes(ft.Results)
			}
		case wasm.ExternTypeTable:
			sig.Kind = externTable
		case wasm.ExternTypeMemory:
			sig.Kind = externMemory
		case wasm.ExternTypeGlobal:
			sig.Kind = externGlobal
		case wasm.ExternTypeTag:
			sig.Kind = externTag
		default:
			sig.Kind = 0
		}
		out = append(out, sig)
	}
	return out
}

func valueTypes(vs []wasm.ValueType) []byte {
	if len(vs) == 0 {
		return nil
	}
	out := make([]byte, len(vs))
	for i, v := range vs {
		out[i] = byte(v)
	}
	return out
}

// CompareHeader verifies that the replay context still matches the record
// header. It returns a locatable DiffError on the first mismatch.
func CompareHeader(want, got Header) *DiffError {
	if want.ModuleID != got.ModuleID {
		d := newDiff(-1, "header", "")
		d.Field = "module"
		d.Want = fmt.Sprintf("%x (module %q)", want.ModuleID[:8], want.ModuleName)
		d.Got = fmt.Sprintf("%x (module %q)", got.ModuleID[:8], got.ModuleName)
		return d
	}
	if want.WazeroVersion != got.WazeroVersion {
		return headerDiff("wazero version", want.WazeroVersion, got.WazeroVersion)
	}
	if want.RuntimeDigest != got.RuntimeDigest {
		return headerDiff("runtime configuration", fmt.Sprintf("%x", want.RuntimeDigest[:8]),
			fmt.Sprintf("%x", got.RuntimeDigest[:8]))
	}
	if want.ModuleConfigDigest != got.ModuleConfigDigest {
		return headerDiff("module configuration (args/environ)",
			fmt.Sprintf("%x", want.ModuleConfigDigest[:8]),
			fmt.Sprintf("%x", got.ModuleConfigDigest[:8]))
	}
	if want.Engine != got.Engine {
		return headerDiff("engine", want.Engine, got.Engine)
	}
	if !equalImports(want.Imports, got.Imports) {
		return headerDiff("import signatures", describeImports(want.Imports), describeImports(got.Imports))
	}
	if want.FunctionName != got.FunctionName {
		return headerDiff("function", want.FunctionName, got.FunctionName)
	}
	if want.InitPages != got.InitPages || want.InitMemoryHash != got.InitMemoryHash {
		d := newDiff(-1, "memory", "")
		d.Field = "initial memory"
		d.Want = fmt.Sprintf("pages=%d hash=%x", want.InitPages, want.InitMemoryHash[:8])
		d.Got = fmt.Sprintf("pages=%d hash=%x", got.InitPages, got.InitMemoryHash[:8])
		return d
	}
	return nil
}

func headerDiff(field, want, got string) *DiffError {
	d := newDiff(-1, "header", "")
	d.Field = field
	d.Want = want
	d.Got = got
	return d
}

func equalImports(a, b []ImportSig) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Kind != b[i].Kind || a[i].Module != b[i].Module || a[i].Name != b[i].Name ||
			!bytes.Equal(a[i].Params, b[i].Params) || !bytes.Equal(a[i].Results, b[i].Results) {
			return false
		}
	}
	return true
}

func describeImports(is []ImportSig) string {
	var b strings.Builder
	for i, im := range is {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s.%s(%v)->%v", im.Module, im.Name, im.Params, im.Results)
	}
	return b.String()
}

// ClassifyTerminal maps the error returned by Function.Call to a journal
// terminal state.
func ClassifyTerminal(callErr error) (Status, uint32, string) {
	if callErr == nil {
		return StatusCompleted, 0, ""
	}
	var exitErr *sys.ExitError
	if errors.As(callErr, &exitErr) {
		switch exitErr.ExitCode() {
		case sys.ExitCodeContextCanceled:
			return StatusContextCanceled, exitErr.ExitCode(), callErr.Error()
		case sys.ExitCodeDeadlineExceeded:
			return StatusContextDeadline, exitErr.ExitCode(), callErr.Error()
		default:
			return StatusExited, exitErr.ExitCode(), callErr.Error()
		}
	}
	return StatusTrap, 0, callErr.Error()
}

// FinalMemory snapshots the post-call memory size and hash.
func FinalMemory(inst *wasm.ModuleInstance) (uint32, [32]byte) {
	var h [32]byte
	if inst == nil || inst.MemoryInstance == nil || len(inst.MemoryInstance.Buffer) == 0 {
		return 0, h
	}
	h = sha256.Sum256(inst.MemoryInstance.Buffer)
	return memoryPages(uint32(len(inst.MemoryInstance.Buffer))), h
}

// CompareTerminal verifies the replay terminal state against the record.
func CompareTerminal(want EndEvent, callErr error, results []uint64, inst *wasm.ModuleInstance) *DiffError {
	gotStatus, gotCode, gotMsg := ClassifyTerminal(callErr)
	if gotStatus != want.Status ||
		(want.Status == StatusExited && gotCode != want.ExitCode) {
		d := newDiff(-1, "terminal", "")
		d.Want = fmt.Sprintf("%s(code=%d)", want.Status, want.ExitCode)
		d.Got = fmt.Sprintf("%s(code=%d): %s", gotStatus, gotCode, gotMsg)
		return d
	}
	switch want.Status {
	case StatusCompleted:
		if !equalU64(want.Results, results) {
			d := newDiff(-1, "results", "")
			d.Want = fmtU64(want.Results)
			d.Got = fmtU64(results)
			return d
		}
	case StatusTrap:
		// Traps are fully deterministic given identical inputs; compare the
		// normalized error text as well as the classification.
		if gotMsg != want.TrapMessage {
			d := newDiff(-1, "terminal", "")
			d.Field = "trap"
			d.Want = want.TrapMessage
			d.Got = gotMsg
			return d
		}
	case StatusContextCanceled, StatusContextDeadline:
		// The exact cancellation point is not instruction-reproducible, so
		// memory state at termination is not compared.
		return nil
	}
	pages, hash := FinalMemory(inst)
	if pages != want.Pages || hash != want.MemoryHash {
		d := newDiff(-1, "memory", "")
		d.Field = "final memory"
		d.Want = fmt.Sprintf("pages=%d hash=%x", want.Pages, want.MemoryHash[:8])
		d.Got = fmt.Sprintf("pages=%d hash=%x", pages, hash[:8])
		return d
	}
	return nil
}

// AssertInstance extracts the concrete module instance behind an api.Module.
func AssertInstance(mod api.Module) (*wasm.ModuleInstance, bool) {
	inst, ok := mod.(*wasm.ModuleInstance)
	return inst, ok
}
