package boundary

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero/api"
)

// BoundaryCall runs fn.Call with recording/replay of the call boundary.
// When no session is attached to ctx this is an exact pass-through.
func BoundaryCall(ctx context.Context, fn api.Function, params []uint64) (results []uint64, err error) {
	s := SessionFromContext(ctx)
	if s == nil {
		return fn.Call(ctx, params...)
	}
	return s.runBoundary(ctx, fn, params, false, nil)
}

// BoundaryCallWithStack is the CallWithStack variant of BoundaryCall.
func BoundaryCallWithStack(ctx context.Context, fn api.Function, stack []uint64) error {
	s := SessionFromContext(ctx)
	if s == nil {
		return fn.CallWithStack(ctx, stack)
	}
	_, err := s.runBoundary(ctx, fn, stack, true, stack)
	return err
}

func fnIdentity(def api.FunctionDefinition) (ref string, paramTypes, resultTypes []byte) {
	name := def.Name()
	if names := def.ExportNames(); len(names) > 0 {
		name = names[0]
	}
	pts := def.ParamTypes()
	rts := def.ResultTypes()
	paramTypes = make([]byte, len(pts))
	resultTypes = make([]byte, len(rts))
	for i, t := range pts {
		paramTypes[i] = t
	}
	for i, t := range rts {
		resultTypes[i] = t
	}
	return def.ModuleName() + "\x00" + name, paramTypes, resultTypes
}

func (s *Session) runBoundary(ctx context.Context, fn api.Function, in []uint64, stackMode bool, stack []uint64) (results []uint64, err error) {
	def := fn.Definition()
	ref, paramTypes, resultTypes := fnIdentity(def)
	nParams := len(paramTypes)
	nResults := len(resultTypes)

	var callParams []uint64
	if stackMode {
		if len(in) < nParams {
			return nil, fail(KindState, StageSession, -1, -1, "stack length %d smaller than parameter count %d", len(in), nParams)
		}
		callParams = in[:nParams]
	} else {
		callParams = in
	}
	paramDigest := digestWords(callParams)

	s.mu.Lock()
	if e := s.beginBoundary(ref, paramTypes, nParams, callParams, paramDigest); e != nil {
		s.mu.Unlock()
		return nil, e
	}

	commitFailure := func(re *ReplayError) {
		s.active.Store(false)
		s.depth = 0
		s.parents = s.parents[:0]
		s.busy = false
		s.mu.Unlock()
	}

	s.active.Store(true)

	// Panics are not expected to cross the engine boundary (both engines
	// recover host panics); a structured decoder panic is converted into a
	// returned error and any other panic is propagated unchanged.
	defer func() {
		if r := recover(); r != nil {
			commitFailure(nil)
			if re, ok := replayPanicValue(r); ok {
				err = re
				return
			}
			panic(r)
		}
	}()

	if stackMode {
		err = fn.CallWithStack(ctx, stack)
		if err == nil {
			results = stack[:nResults]
		}
	} else {
		results, err = fn.Call(ctx, in...)
	}

	var exitErr error
	if s.mode == ModeRecord {
		exitErr = s.recordExitLocked(results, err, ctx)
	} else {
		// If the replay context was canceled (the call may have stopped
		// mid-execution), classify against the recorded call exit before the
		// regular event position checks.
		if ctx != nil && ctx.Err() != nil && s.verr == nil {
			gotClass, _, _ := classifyError(err, ctx)
			if gotClass == classCanceled {
				if recClass, ok := s.scanRecordedCallExitClass(); ok && recClass != classCanceled {
					s.resetCallFrame()
					exitErr = fail(KindContextCanceled, StageEvent, int64(s.seq), -1,
						"replay context was canceled while the recorded call completed")
				}
			}
		}
		if exitErr == nil {
			exitErr = s.verifyExitLocked(results, err, ctx, nResults)
		}
	}
	commitFailure(nil)
	if exitErr != nil {
		return nil, exitErr
	}
	return results, err
}

func (s *Session) beginBoundary(ref string, paramTypes []byte, nParams int, params []uint64, dg [32]byte) error {
	if s.closed {
		return fail(KindState, StageSession, -1, -1, "session closed")
	}
	if s.busy {
		return fail(KindState, StageSession, int64(s.seq), -1,
			"session is already executing a boundary call; concurrent calls require independent sessions")
	}
	if !s.started {
		return fail(KindState, StageSession, -1, -1, "module was compiled/instantiated without an attached boundary session")
	}
	s.busy = true
	s.verr = nil
	s.depth = 0
	s.parents = s.parents[:0]

	if s.mode == ModeRecord {
		var e encBuffer
		e.str(ref)
		e.bytes(paramTypes)
		e.u32(uint32(nParams))
		e.hash(dg)
		s.depth = 1
		s.emitEvent(evCallEnter, e.b)
		s.parents = append(s.parents, s.seq-1)
		return nil
	}

	d, depth, parent, perr := s.expectEvent(evCallEnter)
	if perr != nil {
		s.busy = false
		return perr
	}
	gotRef := d.str()
	gotTypes := d.bytes()
	gotN := int(d.u32())
	gotDigest := d.hash()
	if depth != 1 || parent != 0 {
		s.busy = false
		return fail(KindNested, StageEvent, int64(s.seq-1), -1,
			"call boundary nesting changed: recorded depth=%d parent=#%d", depth, parent)
	}
	if gotRef != ref {
		s.busy = false
		return fail(KindCallOrder, StageEvent, int64(s.seq-1), -1,
			"call order changed: recorded call %q, replay call %q", gotRef, ref)
	}
	if string(gotTypes) != string(paramTypes) {
		s.busy = false
		return fail(KindSignature, StageEvent, int64(s.seq-1), -1,
			"call parameter types for %q changed since recording", ref)
	}
	if gotN != nParams || gotDigest != dg {
		s.busy = false
		return fail(KindParamMismatch, StageEvent, int64(s.seq-1), -1,
			"call parameters to %q differ from the recorded invocation", ref)
	}
	s.depth = 1
	s.parents = append(s.parents, s.seq-1)
	return nil
}

func encodeCallExit(e *encBuffer, results []uint64, err error, ctx context.Context) {
	class, code, msg := classifyError(err, ctx)
	e.u8(class)
	e.u32(code)
	e.str(msg)
	e.u32(uint32(len(results)))
	e.hash(digestWords(results))
}

func (s *Session) recordExitLocked(results []uint64, callErr error, ctx context.Context) (ret error) {
	defer func() {
		s.depth = 0
		s.parents = s.parents[:0]
		s.busy = false
		s.active.Store(false)
	}()
	var e encBuffer
	encodeCallExit(&e, results, callErr, ctx)
	s.emitEvent(evCallExit, e.b)
	if s.writeErr != nil {
		return &ReplayError{Kind: KindState, Stage: StageEvent, EventSeq: int64(s.seq),
			Detail: "execution log could not be written", Err: s.writeErr}
	}
	return nil
}

func (s *Session) verifyExitLocked(results []uint64, callErr error, ctx context.Context, nResults int) error {
	defer func() {
		s.depth = 0
		s.parents = s.parents[:0]
		s.busy = false
		s.active.Store(false)
	}()
	// A verification failure detected inside a double/host wrapper takes
	// precedence over the (necessarily divergent) boundary outcome.
	stashed := s.verr
	s.verr = nil
	if stashed != nil {
		// Consume the recorded exit if present so the session position stays
		// meaningful, but return the structured failure to the caller.
		if s.evPos < len(s.frames) && s.frames[s.evPos].typ == evCallExit {
			_, _, _, _ = s.expectEvent(evCallExit)
		}
		return stashed
	}
	d, _, _, perr := s.expectEvent(evCallExit)
	if perr != nil {
		return perr
	}
	wantClass := d.u8()
	wantCode := d.u32()
	wantMsg := d.str()
	wantN := int(d.u32())
	wantDigest := d.hash()

	gotClass, gotCode, gotMsg := classifyError(callErr, ctx)
	seq := int64(s.seq - 1)
	if len(results) != nResults {
		return fail(KindResultMismatch, StageEvent, seq, -1,
			"return length changed: replay produced %d values, signature declares %d", len(results), nResults)
	}
	if wantClass != gotClass || wantCode != gotCode {
		if wantClass == classCanceled || gotClass == classCanceled {
			return fail(KindContextCanceled, StageEvent, seq, -1,
				"context cancellation differs: recorded class=%d code=%d, replay class=%d code=%d (%v)",
				wantClass, wantCode, gotClass, gotCode, callErr)
		}
		if wantClass == classExit || gotClass == classExit {
			return fail(KindResultMismatch, StageEvent, seq, -1,
				"module exit differs: recorded code=%d, replay code=%d", wantCode, gotCode)
		}
		return fail(KindResultMismatch, StageEvent, seq, -1,
			"error class differs: recorded class=%d code=%d %q, replay class=%d code=%d %q",
			wantClass, wantCode, wantMsg, gotClass, gotCode, gotMsg)
	}
	if wantClass != classOK && wantMsg != gotMsg {
		return fail(KindResultMismatch, StageEvent, seq, -1,
			"error message differs: recorded %q, replay %q", wantMsg, gotMsg)
	}
	if wantN != nResults || wantDigest != digestWords(results) {
		return fail(KindResultMismatch, StageEvent, seq, -1,
			"return values differ from the recorded invocation")
	}
	return nil
}

// scanRecordedCallExitClass looks ahead for the recorded call exit of the
// in-flight boundary (skipping host/resource events) without consuming it.
func (s *Session) scanRecordedCallExitClass() (byte, bool) {
	for i := s.evPos; i < len(s.frames); i++ {
		if s.frames[i].typ == evCallExit && len(s.frames[i].payload) >= 21 {
			return s.frames[i].payload[20], true
		}
	}
	return 0, false
}

// resetCallFrame fast-forwards replay position to the recorded call exit,
// matching a mid-call cancellation on the replay side.
func (s *Session) resetCallFrame() {
	for s.evPos < len(s.frames) && s.frames[s.evPos].typ != evCallExit {
		s.evPos++
		s.seq++
		s.events++
	}
	if s.evPos < len(s.frames) {
		s.evPos++
		s.seq++
		s.events++
	}
}

// panicString renders a recovered panic value.
func panicString(r any) string {
	switch v := r.(type) {
	case string:
		return v
	case error:
		return v.Error()
	default:
		return fmt.Sprint(v)
	}
}
