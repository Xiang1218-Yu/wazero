package boundary

import (
	"context"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/internal/wasip1"
)

// WASI module names whose host functions execute against recorded resource
// doubles during replay (instead of being stubbed like user host functions).
var wasiModuleNames = map[string]struct{}{
	wasip1.InternalModuleName: {},
	"wasi_unstable":           {},
}

// hostGoModule wraps an api.GoModuleFunction with boundary interception.
type hostGoModule struct {
	s                       *Session
	hostModule, name        string
	paramTypes, resultTypes []byte
	nParams, nResults       int
	under                   api.GoModuleFunction
}

// hostGoFunc wraps an api.GoFunction with boundary interception.
type hostGoFunc struct {
	s                       *Session
	hostModule, name        string
	paramTypes, resultTypes []byte
	nParams, nResults       int
	under                   api.GoFunction
}

// WrapGoModuleFunction installs record/replay interception around a host
// function. The user function is never modified.
func (s *Session) WrapGoModuleFunction(hostModule, name string, paramTypes, resultTypes []byte,
	under api.GoModuleFunction) api.GoModuleFunction {
	return &hostGoModule{
		s: s, hostModule: hostModule, name: name,
		paramTypes: append([]byte(nil), paramTypes...), resultTypes: append([]byte(nil), resultTypes...),
		nParams: len(paramTypes), nResults: len(resultTypes), under: under,
	}
}

// WrapGoFunction installs record/replay interception around a host function
// without module access.
func (s *Session) WrapGoFunction(hostModule, name string, paramTypes, resultTypes []byte,
	under api.GoFunction) api.GoFunction {
	return &hostGoFunc{
		s: s, hostModule: hostModule, name: name,
		paramTypes: append([]byte(nil), paramTypes...), resultTypes: append([]byte(nil), resultTypes...),
		nParams: len(paramTypes), nResults: len(resultTypes), under: under,
	}
}

// hostEnter validates/emits the host call boundary. On success the session
// depth is incremented and the host frame is pushed. On replay mismatch it
// returns the recorded depth so the caller can skip the matching subtree.
func (s *Session) hostEnter(hmod, name string, pt, rt []byte, nParams int, stack []uint64) (recordedDepth uint32, ok bool) {
	np := nParams
	if np > len(stack) {
		np = len(stack)
	}
	dg := digestWords(stack[:np])
	wantDepth := s.depth + 1
	parent := s.parentTop()

	if s.mode == ModeRecord {
		var e encBuffer
		e.str(hmod)
		e.str(name)
		e.bytes(pt)
		e.bytes(rt)
		e.u32(uint32(nParams))
		e.hash(dg)
		s.depth = wantDepth // emitEvent reads the current depth/parent
		s.emitEvent(evHostEnter, e.b)
		s.parents = append(s.parents, s.seq-1)
		return wantDepth, true
	}

	d, depth, p, err := s.expectEvent(evHostEnter)
	if err != nil {
		s.fatal(err)
		return depth, false
	}
	gotMod := d.str()
	gotName := d.str()
	gotParams := d.bytes()
	gotResults := d.bytes()
	gotN := int(d.u32())
	gotDigest := d.hash()
	seq := int64(s.seq - 1)
	switch {
	case depth != wantDepth || p != parent:
		err = fail(KindNested, StageEvent, seq, -1,
			"host call nesting changed: recorded depth=%d parent=#%d, replay depth=%d parent=#%d",
			depth, p, wantDepth, parent)
	case gotMod != hmod || gotName != name:
		err = fail(KindCallOrder, StageEvent, seq, -1,
			"host call order changed: recorded %s.%s, replay %s.%s", gotMod, gotName, hmod, name)
	case string(gotParams) != string(pt) || string(gotResults) != string(rt):
		err = fail(KindSignature, StageEvent, seq, -1,
			"host function %s.%s signature changed", hmod, name)
	case gotN != nParams || gotDigest != dg:
		err = fail(KindParamMismatch, StageEvent, seq, -1,
			"host function %s.%s parameters differ from the recorded invocation", hmod, name)
	}
	if err != nil {
		s.fatal(err)
		return depth, false
	}
	s.depth = wantDepth
	s.parents = append(s.parents, uint64(s.seq-1))
	return wantDepth, true
}

func (s *Session) popHost() {
	if s.depth > 0 {
		s.depth--
	}
	if len(s.parents) > 0 {
		s.parents = s.parents[:len(s.parents)-1]
	}
}

// hostExitRecord records a normal host return.
func (s *Session) hostExitRecord(hmod string, mod api.Module, nResults int, stack []uint64) {
	var results []uint64
	if nResults > 0 && len(stack) >= nResults {
		results = append(results, stack[:nResults]...)
	}
	var e encBuffer
	e.u8(0)
	e.str("")
	e.words(results)
	e.hash(digestWords(results))
	s.appendMemoryIntegrity(&e, hmod, mod)
	s.emitEvent(evHostExit, e.b)
	s.popHost()
}

// hostExitAbort records an aborted host call and re-panics the value.
func (s *Session) hostExitAbort(r any) {
	msg := panicString(r)
	var e encBuffer
	e.u8(1)
	e.str(msg)
	e.words(nil)
	e.hash([32]byte{})
	e.u32(0)
	e.hash([32]byte{})
	s.emitEvent(evHostExit, e.b)
	s.popHost()
}

func (s *Session) appendMemoryIntegrity(e *encBuffer, hmod string, mod api.Module) {
	var zero [32]byte
	if !s.opts.MemoryIntegrity {
		e.u32(0)
		e.hash(zero)
		return
	}
	if _, isWASI := wasiModuleNames[hmod]; !isWASI || mod == nil || mod.Memory() == nil {
		e.u32(0)
		e.hash(zero)
		return
	}
	mem := mod.Memory()
	size := mem.Size()
	data, ok := mem.Read(0, size)
	if !ok || uint32(len(data)) != size {
		e.u32(0)
		e.hash(zero)
		return
	}
	e.u32(size)
	e.hash(digestBytes(data))
}

// hostExitExpect verifies a normal host return after replaying a WASI host
// function against log-backed doubles.
func (s *Session) hostExitExpect(hmod string, mod api.Module, nResults int, stack []uint64) error {
	d, depth, _, perr := s.expectEvent(evHostExit)
	seq := int64(s.seq - 1)
	defer s.popHost()
	if perr != nil {
		return perr
	}
	if depth != s.depth {
		return fail(KindNested, StageEvent, seq, -1,
			"host exit nesting changed: recorded depth %d, replay depth %d", depth, s.depth)
	}
	abort := d.u8()
	msg := d.str()
	results := d.words()
	wantDigest := d.hash()
	memLen := d.u32()
	wantMem := d.hash()
	if abort != 0 {
		return fail(KindResultMismatch, StageEvent, seq, -1,
			"host call aborted during recording (%q) but returned during replay", msg)
	}
	var got []uint64
	if nResults > 0 && len(stack) >= nResults {
		got = stack[:nResults]
	} else {
		got = stack
	}
	if len(results) != nResults || wantDigest != digestWords(got) {
		return fail(KindResultMismatch, StageEvent, seq, -1,
			"host function %s return length/values differ from the recorded invocation", hmod)
	}
	if s.opts.MemoryIntegrity && memLen != 0 {
		if mod == nil || mod.Memory() == nil {
			return fail(KindResultMismatch, StageEvent, seq, -1, "guest memory missing on replay")
		}
		mem := mod.Memory()
		if mem.Size() != memLen {
			return fail(KindResultMismatch, StageEvent, seq, -1,
				"guest memory size differs: recorded %d, replay %d", memLen, mem.Size())
		}
		data, ok := mem.Read(0, memLen)
		if !ok || digestBytes(data) != wantMem {
			return fail(KindResultMismatch, StageEvent, seq, -1,
				"guest memory contents after a %s host call differ from the recorded run", hmod)
		}
	}
	return nil
}

// hostExitExpectAbort verifies an aborted host call during replay.
func (s *Session) hostExitExpectAbort(r any) error {
	d, depth, _, perr := s.expectEvent(evHostExit)
	defer s.popHost()
	if perr != nil {
		return perr
	}
	if depth != s.depth {
		return fail(KindNested, StageEvent, int64(s.seq-1), -1,
			"host abort nesting changed: recorded depth %d, replay depth %d", depth, s.depth)
	}
	abort := d.u8()
	msg := d.str()
	if abort == 0 {
		return fail(KindResultMismatch, StageEvent, int64(s.seq-1), -1,
			"host call returned during recording but aborted during replay (%v)", r)
	}
	if got := panicString(r); got != msg {
		return fail(KindResultMismatch, StageEvent, int64(s.seq-1), -1,
			"host panic differs: recorded %q, replay %q", msg, got)
	}
	return nil
}

// hostExitStub consumes the host exit (and any nested events) for a stubbed
// user host function without executing it.
func (s *Session) hostExitStub(wantDepth uint32) (abort bool, msg string, results []uint64) {
	d := s.consumeHostSubtree(wantDepth)
	abort = d.u8() != 0
	msg = d.str()
	results = d.words()
	return
}

// consumeHostSubtree skips nested events until the matching host exit frame.
func (s *Session) consumeHostSubtree(wantDepth uint32) *decBuffer {
	for {
		if s.evPos >= len(s.frames) {
			s.fatal(fail(KindLogTruncated, StageEvent, int64(s.seq), -1,
				"log ends inside a host call subtree"))
			return &decBuffer{}
		}
		f := s.frames[s.evPos]
		depth := eventDepth(f)
		s.evPos++
		s.seq++
		s.events++
		if f.typ == evHostExit && depth == wantDepth {
			d := &decBuffer{b: f.payload}
			d.u64() // skip common event header: seq
			d.u32() // depth
			d.u64() // parent
			return d
		}
	}
}

// eventDepth reads the depth field (offset 8 in the common event header).
func eventDepth(f rawFrame) uint32 {
	if len(f.payload) < 12 {
		return 0
	}
	return uint32(f.payload[8]) | uint32(f.payload[9])<<8 |
		uint32(f.payload[10])<<16 | uint32(f.payload[11])<<24
}

// replayStub handles a user host function by restoring recorded results
// without invoking the real implementation. pushed reports whether the
// matching host enter frame/path was pushed on the replay side.
func (s *Session) replayStub(stack []uint64, nResults int, recordedDepth uint32, pushed bool) {
	abort, msg, results := s.hostExitStub(recordedDepth)
	if pushed {
		s.popHost()
	}
	if abort {
		panic(&hostPanicError{msg: msg})
	}
	restoreResults(stack, nResults, results)
}

// ---------------------------------------------------------------------------
// interceptor entry points
// ---------------------------------------------------------------------------

func (h *hostGoModule) Call(ctx context.Context, mod api.Module, stack []uint64) {
	// Once a replay verification failure is in flight, neutralize remaining
	// host calls without consuming events or touching the real host.
	if h.s.mode == ModeReplay && h.s.verr != nil {
		for i := 0; i < h.nResults && i < len(stack); i++ {
			stack[i] = 0
		}
		return
	}
	defer func() {
		// Malformed log payloads surface as structured decoder panics: stash
		// them for the boundary to return; propagate everything else.
		if r := recover(); r != nil {
			if re, isRe := replayPanicValue(r); isRe {
				h.s.fatal(re)
				return
			}
			panic(r)
		}
	}()
	depth, ok := h.s.hostEnter(h.hostModule, h.name, h.paramTypes, h.resultTypes, h.nParams, stack)
	if !ok {
		h.s.replayStub(stack, h.nResults, depth, ok)
		return
	}
	if h.s.mode == ModeReplay {
		if _, isWASI := wasiModuleNames[h.hostModule]; isWASI {
			defer func() {
				if r := recover(); r != nil {
					if err := h.s.hostExitExpectAbort(r); err != nil {
						h.s.fatal(err)
					}
					panic(r)
				}
			}()
			h.under.Call(ctx, mod, stack)
			if err := h.s.hostExitExpect(h.hostModule, mod, h.nResults, stack); err != nil {
				h.s.fatal(err)
			}
			return
		}
		// User host functions never execute on replay.
		h.s.replayStub(stack, h.nResults, depth, ok)
		return
	}
	defer func() {
		if r := recover(); r != nil {
			h.s.hostExitAbort(r)
			panic(r)
		}
	}()
	h.under.Call(ctx, mod, stack)
	h.s.hostExitRecord(h.hostModule, mod, h.nResults, stack)
}

func (h *hostGoFunc) Call(ctx context.Context, stack []uint64) {
	if h.s.mode == ModeReplay && h.s.verr != nil {
		for i := 0; i < h.nResults && i < len(stack); i++ {
			stack[i] = 0
		}
		return
	}
	defer func() {
		if r := recover(); r != nil {
			if re, isRe := replayPanicValue(r); isRe {
				h.s.fatal(re)
				return
			}
			panic(r)
		}
	}()
	depth, ok := h.s.hostEnter(h.hostModule, h.name, h.paramTypes, h.resultTypes, h.nParams, stack)
	if !ok {
		h.s.replayStub(stack, h.nResults, depth, ok)
		return
	}
	if h.s.mode == ModeReplay {
		h.s.replayStub(stack, h.nResults, depth, ok)
		return
	}
	defer func() {
		if r := recover(); r != nil {
			h.s.hostExitAbort(r)
			panic(r)
		}
	}()
	h.under.Call(ctx, stack)
	h.s.hostExitRecord(h.hostModule, nil, h.nResults, stack)
}

func restoreResults(stack []uint64, nResults int, results []uint64) {
	for i := 0; i < nResults && i < len(results) && i < len(stack); i++ {
		stack[i] = results[i]
	}
}
