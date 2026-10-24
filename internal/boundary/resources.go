package boundary

import (
	"errors"
	"io"

	experimentalsys "github.com/tetratelabs/wazero/experimental/sys"
	topsys "github.com/tetratelabs/wazero/sys"
)

// Resources are the host-provided module resources that the root package
// makes wrappable when a session is attached. Nil fields keep wazero's
// deterministic defaults (and are therefore left untouched).
type Resources struct {
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
	Rand      io.Reader
	Walltime  topsys.Walltime
	Nanotime  topsys.Nanotime
	Nanosleep topsys.Nanosleep
}

// WrapResources returns copies of the resources bound to recording/replay
// doubles. User-provided readers, writers and funcs are never modified: the
// wrappers are new values referencing the originals in record mode, and
// replay doubles never invoke the originals.
func (s *Session) WrapResources(in Resources) Resources {
	out := in
	if in.Rand != nil {
		out.Rand = s.newByteDouble(bytesRand, 0, in.Rand)
	}
	if in.Stdin != nil {
		out.Stdin = s.newByteDouble(bytesStdin, 0, in.Stdin)
	}
	if in.Stdout != nil {
		out.Stdout = &writeDouble{s: s, kind: writeStdout, id: 0, under: in.Stdout}
	}
	if in.Stderr != nil {
		out.Stderr = &writeDouble{s: s, kind: writeStderr, id: 0, under: in.Stderr}
	}
	if in.Walltime != nil {
		wt := in.Walltime
		out.Walltime = func() (int64, int32) {
			sec, nsec := wt()
			s.wallRecord(sec, nsec)
			return sec, nsec
		}
	}
	if in.Nanotime != nil {
		nt := in.Nanotime
		out.Nanotime = func() int64 {
			v := nt()
			s.nanoRecord(v)
			return v
		}
	}
	if in.Nanosleep != nil {
		ns := in.Nanosleep
		out.Nanosleep = func(v int64) {
			s.sleepRecord(v)
			ns(v)
		}
	}
	if s.mode == ModeReplay {
		s.installReplayDoubles(&out)
	}
	return out
}

func (s *Session) installReplayDoubles(out *Resources) {
	if out.Rand != nil {
		out.Rand = &byteDouble{s: s, kind: bytesRand, id: 0}
	}
	if out.Stdin != nil {
		out.Stdin = &byteDouble{s: s, kind: bytesStdin, id: 0}
	}
	if out.Stdout != nil {
		out.Stdout = &writeDouble{s: s, kind: writeStdout, id: 0}
	}
	if out.Stderr != nil {
		out.Stderr = &writeDouble{s: s, kind: writeStderr, id: 0}
	}
	// Only replace clocks that the caller configured; nil keeps wazero's
	// deterministic fake defaults and their recorded resolutions.
	if out.Walltime != nil {
		out.Walltime = func() (int64, int32) { return s.wallExpect() }
	}
	if out.Nanotime != nil {
		out.Nanotime = func() int64 { return s.nanoExpect() }
	}
	if out.Nanosleep != nil {
		out.Nanosleep = func(int64) { /* never sleep on replay */ }
	}
}

// ---------------------------------------------------------------------------
// clock events
// ---------------------------------------------------------------------------

func (s *Session) wallRecord(sec int64, nsec int32) {
	if !s.active.Load() {
		return
	}
	var e encBuffer
	e.i64(sec)
	e.i32(nsec)
	s.emitEvent(evWall, e.b)
}

func (s *Session) wallExpect() (int64, int32) {
	if !s.active.Load() || s.verr != nil {
		return 0, 0
	}
	d, _, _, err := s.expectEvent(evWall)
	if err != nil {
		s.fatal(err)
		return 0, 0
	}
	return d.i64(), d.i32()
}

func (s *Session) nanoRecord(v int64) {
	if !s.active.Load() {
		return
	}
	var e encBuffer
	e.i64(v)
	s.emitEvent(evNano, e.b)
}

func (s *Session) nanoExpect() int64 {
	if !s.active.Load() || s.verr != nil {
		return 0
	}
	d, _, _, err := s.expectEvent(evNano)
	if err != nil {
		s.fatal(err)
		return 0
	}
	return d.i64()
}

func (s *Session) sleepRecord(v int64) {
	if !s.active.Load() {
		return
	}
	var e encBuffer
	e.i64(v)
	s.emitEvent(evSleep, e.b)
}

// ---------------------------------------------------------------------------
// byte input events (random source, stdin, file reads)
// ---------------------------------------------------------------------------

func (s *Session) bytesRecord(kind byte, id uint32, off int64, req int, data []byte, errno uint16, eof bool) {
	var e encBuffer
	e.u8(kind)
	e.u32(id)
	e.i64(off)
	e.u32(uint32(req))
	e.u32(uint32(len(data)))
	e.b = append(e.b, data...)
	e.u16(errno)
	e.boolean(eof)
	s.emitEvent(evBytes, e.b)
}

// bytesExpect verifies the next input event and returns the recorded payload.
func (s *Session) bytesExpect(kind byte, id uint32, off int64, req int) (data []byte, errno uint16, eof bool) {
	if s.verr != nil {
		return nil, 0, false
	}
	d, _, _, err := s.expectEvent(evBytes)
	if err != nil {
		s.fatal(err)
		return nil, 0, false
	}
	gotKind := d.u8()
	gotID := d.u32()
	gotOff := d.i64()
	gotReq := int(d.u32())
	data = d.bytes()
	errno = d.u16()
	eof = d.boolean()
	if gotKind != kind || gotID != id || gotOff != off || gotReq != req {
		s.fatal(fail(KindReadOverflow, StageEvent, int64(s.seq-1), -1,
			"input read changed: recorded kind=%d id=%d off=%d requested=%d, replay kind=%d id=%d off=%d requested=%d",
			gotKind, gotID, gotOff, gotReq, kind, id, off, req))
		return nil, 0, false
	}
	if req < len(data) {
		s.fatal(fail(KindReadOverflow, StageEvent, int64(s.seq-1), -1,
			"recorded read supplied %d bytes for a %d byte request", len(data), req))
		return nil, 0, false
	}
	return
}

// ---------------------------------------------------------------------------
// write events
// ---------------------------------------------------------------------------

func (s *Session) writeRecord(kind byte, id uint32, off int64, p []byte, n int, errno uint16) {
	var e encBuffer
	e.u8(kind)
	e.u32(id)
	e.i64(off)
	e.u32(uint32(len(p)))
	e.hash(digestBytes(p))
	e.u32(uint32(n))
	e.u16(errno)
	s.emitEvent(evWrite, e.b)
}

func (s *Session) writeExpect(kind byte, id uint32, off int64, p []byte) (int, uint16) {
	if s.verr != nil {
		return 0, uint16(experimentalsys.EIO)
	}
	d, _, _, err := s.expectEvent(evWrite)
	if err != nil {
		s.fatal(err)
		return 0, 0
	}
	gotKind := d.u8()
	gotID := d.u32()
	gotOff := d.i64()
	gotLen := int(d.u32())
	gotDigest := d.hash()
	n := int(d.u32())
	errno := d.u16()
	gotSHA := digestBytes(p)
	if gotKind != kind || gotID != id || gotOff != off || gotLen != len(p) || gotDigest != gotSHA {
		s.fatal(fail(KindSideEffect, StageEvent, int64(s.seq-1), -1,
			"write side effect differs: recorded kind=%d id=%d off=%d len=%d sha=%x, replay kind=%d id=%d off=%d len=%d sha=%x",
			gotKind, gotID, gotOff, gotLen, gotDigest[:8], kind, id, off, len(p), gotSHA[:8]))
		return 0, 0
	}
	return n, errno
}

// fatal records the first verification failure so the in-flight boundary can
// return it; replay continues with neutral values instead of triggering any
// further real side effect.
func (s *Session) fatal(err error) {
	if err == nil {
		return
	}
	if s.verr == nil {
		s.verr = err
	}
}

// ---------------------------------------------------------------------------
// doubles
// ---------------------------------------------------------------------------

type byteDoubleReader struct {
	s     *Session
	kind  byte
	id    uint32
	under io.Reader // record mode only
}

// newByteDouble builds the record-mode reader; replay mode replaces it in
// installReplayDoubles.
func (s *Session) newByteDouble(kind byte, id uint32, under io.Reader) io.Reader {
	return &byteDoubleReader{s: s, kind: kind, id: id, under: under}
}

func (r *byteDoubleReader) Read(p []byte) (int, error) {
	if !r.s.active.Load() {
		return r.under.Read(p)
	}
	n, err := r.under.Read(p)
	errno, eof := mapIOError(err)
	r.s.bytesRecord(r.kind, r.id, 0, len(p), append([]byte(nil), p[:n]...), errno, eof)
	return n, err
}

type byteDouble struct {
	s    *Session
	kind byte
	id   uint32
}

func (r *byteDouble) Read(p []byte) (int, error) {
	if !r.s.active.Load() {
		return 0, io.EOF
	}
	data, errno, eof := r.s.bytesExpect(r.kind, r.id, 0, len(p))
	// A verification failure must terminate reader loops (e.g. io.ReadAtLeast)
	// instead of returning zero bytes forever.
	if r.s.verr != nil {
		return 0, io.ErrClosedPipe
	}
	n := copy(p, data)
	if n < len(data) {
		// Cannot happen: copy fills min(len(p), len(data)); req==len(p) and
		// len(data) <= req was validated in bytesExpect.
		r.s.fatal(fail(KindReadOverflow, StageEvent, int64(r.s.seq-1), -1,
			"replay buffer smaller than recorded data"))
	}
	if errno != 0 {
		return n, experimentalsys.Errno(errno)
	}
	if eof {
		return n, io.EOF
	}
	return n, nil
}

type writeDouble struct {
	s     *Session
	kind  byte
	id    uint32
	under io.Writer // record mode only; nil in replay mode
}

func (w *writeDouble) Write(p []byte) (int, error) {
	if !w.s.active.Load() {
		if w.under != nil {
			return w.under.Write(p)
		}
		return len(p), nil
	}
	if w.s.mode == ModeRecord {
		n, err := w.under.Write(p)
		errno, _ := mapIOError(err)
		w.s.writeRecord(w.kind, w.id, 0, p, n, errno)
		return n, err
	}
	// Replay: the recorded side effect is verified but never re-executed.
	n, errno := w.s.writeExpect(w.kind, w.id, 0, p)
	if errno != 0 {
		return n, experimentalsys.Errno(errno)
	}
	return n, nil
}

func mapIOError(err error) (uint16, bool) {
	if err == nil {
		return 0, false
	}
	if errors.Is(err, io.EOF) {
		return 0, true
	}
	return uint16(experimentalsys.UnwrapOSError(err)), false
}
