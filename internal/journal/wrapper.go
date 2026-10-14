package journal

import (
	"context"
	"errors"
	"fmt"

	"github.com/tetratelabs/wazero/api"
	expsys "github.com/tetratelabs/wazero/experimental/sys"
	"github.com/tetratelabs/wazero/internal/wasm"
	"github.com/tetratelabs/wazero/sys"
)

// HostModuleEnabled reports whether the given context enables journal
// instrumentation for host modules compiled with it.
type enableKey struct{}

// Enable returns a context that opts in to journal instrumentation for host
// modules compiled while the context is active. It is default-off: without it,
// host modules are compiled exactly as before and journal adds zero overhead.
func Enable(ctx context.Context) context.Context {
	return context.WithValue(ctx, enableKey{}, true)
}

// Enabled reports whether journal instrumentation is enabled.
func Enabled(ctx context.Context) bool {
	v, _ := ctx.Value(enableKey{}).(bool)
	return v
}

// WrapModule rewrites the GoFunc entries of a compiled host module with
// journal-aware wrappers. The wrappers are inert unless a Session is carried
// by the call context. It is idempotent: already wrapped modules are skipped.
func WrapModule(m *wasm.Module) {
	if m == nil || !m.IsHostModule {
		return
	}
	moduleName := ""
	if m.NameSection != nil {
		moduleName = m.NameSection.ModuleName
	}
	for i := range m.CodeSection {
		c := &m.CodeSection[i]
		if _, ok := c.GoFunc.(journalWrapped); ok {
			continue
		}
		var pn, rn int
		if i < len(m.FunctionSection) {
			typeIdx := m.FunctionSection[i]
			if int(typeIdx) < len(m.TypeSection) {
				ft := &m.TypeSection[typeIdx]
				pn, rn = len(ft.Params), len(ft.Results)
			}
		}
		name := exportName(m, wasm.Index(i))
		id := hostID{module: moduleName, name: name, paramN: pn, resultN: rn}
		switch fn := c.GoFunc.(type) {
		case api.GoModuleFunction:
			c.GoFunc = &goModuleWrapper{inner: fn, hostID: id}
		case api.GoFunction:
			c.GoFunc = &goWrapper{inner: fn, hostID: id}
		}
	}
}

func exportName(m *wasm.Module, idx wasm.Index) string {
	for i := range m.ExportSection {
		if e := &m.ExportSection[i]; e.Type == wasm.ExternTypeFunc && e.Index == idx {
			return e.Name
		}
	}
	if m.NameSection != nil {
		for _, n := range m.NameSection.FunctionNames {
			if n.Index == idx {
				return n.Name
			}
		}
	}
	return fmt.Sprintf("$%d", idx)
}

// journalWrapped marks wrappers to prevent double wrapping.
type journalWrapped interface {
	journalWrapped()
}

type hostID struct {
	module  string
	name    string
	paramN  int
	resultN int
}

type goWrapper struct {
	inner api.GoFunction
	hostID
}

type goModuleWrapper struct {
	inner api.GoModuleFunction
	hostID
}

func (*goWrapper) journalWrapped()       {}
func (*goModuleWrapper) journalWrapped() {}

// Call implements api.GoFunction.
func (w *goWrapper) Call(ctx context.Context, stack []uint64) {
	if ctx == nil {
		w.inner.Call(ctx, stack)
		return
	}
	s := FromContext(ctx)
	if s == nil {
		w.inner.Call(ctx, stack)
		return
	}
	switch s.mode {
	case modeRecord:
		recordCall(s, w.hostID, nil, stack, func() { w.inner.Call(ctx, stack) })
	case modeReplay:
		replayCall(s, w.hostID, nil, stack)
	default:
		w.inner.Call(ctx, stack)
	}
}

// Call implements api.GoModuleFunction.
func (w *goModuleWrapper) Call(ctx context.Context, mod api.Module, stack []uint64) {
	if ctx == nil {
		w.inner.Call(ctx, mod, stack)
		return
	}
	s := FromContext(ctx)
	if s == nil {
		w.inner.Call(ctx, mod, stack)
		return
	}
	switch s.mode {
	case modeRecord:
		recordCall(s, w.hostID, mod, stack, func() { w.inner.Call(ctx, mod, stack) })
	case modeReplay:
		replayCall(s, w.hostID, mod, stack)
	default:
		w.inner.Call(ctx, mod, stack)
	}
}

// recordCall is the shared recording implementation. invoke executes the real
// host function.
func recordCall(s *Session, id hostID, mod api.Module, resultStack []uint64, invoke func()) {
	var prePages uint32
	var pre map[uint32]uint64
	var mem api.Memory
	if mod != nil {
		mem = mod.Memory()
	}
	if mem != nil && mem.Size() > 0 {
		prePages, pre = snapshotMemory(mem)
	}

	var params []uint64
	if id.paramN > 0 {
		params = resultStack[:id.paramN]
	}
	ev := s.enterRecord(id.module, id.name, params, pre, prePages)

	var recovered interface{}
	func() {
		defer func() { recovered = recover() }()
		invoke()
	}()

	// Results live in the first resultN slots of the Go-visible stack.
	if id.resultN > 0 && len(resultStack) >= id.resultN {
		ev.Results = cloneU64(resultStack[:id.resultN])
	}
	if mem != nil {
		ev.PostPages, ev.Patches = diffMemory(mem, pre, prePages)
	}
	classifyPanic(recovered, ev)
	s.exitRecord(ev)
	if recovered != nil {
		panic(recovered)
	}
}

// replayCall drives one recorded interaction without invoking the host
// function, so no host-side effect is ever repeated.
func replayCall(s *Session, id hostID, mod api.Module, stack []uint64) {
	var params []uint64
	if id.paramN > 0 {
		params = stack[:id.paramN]
	}
	ev := s.enterReplay(id.module, id.name, params)

	if mod != nil {
		applyMemory(s, ev, mod.Memory())
	} else if ev.PostPages != 0 || len(ev.Patches) != 0 {
		s.fail(newDiff(s.cursor, "memory", "recorded memory effects for a function without module access"))
		panic(errReplayAbort)
	}

	if len(ev.Results) != id.resultN {
		s.fail(newDiff(s.cursor, "signature", "result count %d for %s.%s, function defines %d",
			len(ev.Results), ev.Module, ev.Name, id.resultN))
		panic(errReplayAbort)
	}
	if id.resultN > 0 {
		copy(stack[:id.resultN], ev.Results)
	}

	s.exitReplay(ev)

	if ev.PanicClass != panicNone {
		panic(reconstructPanic(ev))
	}
}

func classifyPanic(v interface{}, ev *HostEvent) {
	if v == nil {
		return
	}
	switch x := v.(type) {
	case *sys.ExitError:
		ev.PanicClass = panicExit
		ev.PanicValue = uint64(x.ExitCode())
		ev.PanicMessage = x.Error()
	case expsys.Errno:
		ev.PanicClass = panicErrno
		ev.PanicValue = uint64(uint16(x))
		ev.PanicMessage = x.Error()
	case string:
		// A string panic is reproduced as the same string so the engine
		// formats an identical "(recovered by wazero)" message.
		ev.PanicClass = panicString
		ev.PanicMessage = x
	case error:
		ev.PanicClass = panicOther
		ev.PanicMessage = x.Error()
	default:
		ev.PanicClass = panicOther
		ev.PanicMessage = fmt.Sprintf("%v", x)
	}
}

func reconstructPanic(ev *HostEvent) interface{} {
	switch ev.PanicClass {
	case panicExit:
		return sys.NewExitError(uint32(ev.PanicValue))
	case panicErrno:
		return expsys.Errno(uint16(ev.PanicValue))
	case panicString:
		return ev.PanicMessage
	default:
		return errors.New(ev.PanicMessage)
	}
}

// ---------------------------------------------------------------------------
// Page-granular memory tracking.
// ---------------------------------------------------------------------------

const memoryPageSize = uint32(65536)

func memoryPages(size uint32) uint32 {
	return (size + memoryPageSize - 1) / memoryPageSize
}

// fnv64 computes FNV-1a 64 without allocations.
func fnv64(b []byte) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for _, c := range b {
		h ^= uint64(c)
		h *= prime64
	}
	return h
}

func snapshotMemory(mem api.Memory) (uint32, map[uint32]uint64) {
	size := mem.Size()
	pages := memoryPages(size)
	hashes := make(map[uint32]uint64, pages)
	for i := uint32(0); i < pages; i++ {
		off := i * memoryPageSize
		n := memoryPageSize
		if rest := size - off; rest < n {
			n = rest
		}
		if view, ok := mem.Read(off, n); ok {
			hashes[i] = fnv64(view)
		}
	}
	return pages, hashes
}

func diffMemory(mem api.Memory, pre map[uint32]uint64, prePages uint32) (uint32, []MemoryPatch) {
	size := mem.Size()
	postPages := memoryPages(size)
	var patches []MemoryPatch
	for i := uint32(0); i < postPages; i++ {
		off := i * memoryPageSize
		n := memoryPageSize
		if rest := size - off; rest < n {
			n = rest
		}
		view, ok := mem.Read(off, n)
		if !ok {
			continue
		}
		now := fnv64(view)
		if i >= prePages || pre[i] != now {
			data := make([]byte, n)
			copy(data, view)
			patches = append(patches, MemoryPatch{Page: i, Data: data})
		}
	}
	return postPages, patches
}

func applyMemory(s *Session, ev *HostEvent, mem api.Memory) {
	pages := memoryPages(mem.Size())
	if pages < ev.PrePages {
		s.fail(newDiff(s.cursor, "memory", "caller memory has %d page(s) before the call, record requires %d", pages, ev.PrePages))
		panic(errReplayAbort)
	}
	if pages < ev.PostPages {
		if _, ok := mem.Grow(ev.PostPages - pages); !ok {
			s.fail(newDiff(s.cursor, "memory", "could not grow memory from %d to %d recorded page(s)", pages, ev.PostPages))
			panic(errReplayAbort)
		}
	}
	for _, p := range ev.Patches {
		off := p.Page * memoryPageSize
		if !mem.Write(off, p.Data) {
			s.fail(newDiff(s.cursor, "memory", "cannot apply %d recorded byte(s) at page %d (memory size %d)",
				len(p.Data), p.Page, mem.Size()))
			panic(errReplayAbort)
		}
	}
	if got := memoryPages(mem.Size()); got != ev.PostPages {
		s.fail(newDiff(s.cursor, "memory", "post-call page count mismatch: want %d, got %d", ev.PostPages, got))
		panic(errReplayAbort)
	}
}
