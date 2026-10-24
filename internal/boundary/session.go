package boundary

import (
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"sync"
	"sync/atomic"

	topwazero "github.com/tetratelabs/wazero/sys"
)

// Mode selects recording or replaying.
type Mode uint8

const (
	// ModeRecord writes a versioned execution log.
	ModeRecord Mode = iota + 1
	// ModeReplay validates against and serves values from an execution log.
	ModeReplay
)

// Options configures a session.
type Options struct {
	// MemoryIntegrity hashes the full guest memory after every WASI host
	// call and verifies the hash on replay. Defaults to true.
	MemoryIntegrity bool
}

// Session is a single, linear execution log shared by the resource doubles
// and host-function interceptors installed for one runtime lifetime. A
// session serializes one boundary call at a time; concurrent independent
// calls must use independent sessions (and therefore independent logs and
// runtimes).
type Session struct {
	mode Mode
	opts Options

	// recording side
	w        io.Writer
	logHash  hash.Hash
	closeMut sync.Once
	closeErr error

	// replay side
	frames     []rawFrame
	evPos      int
	sawTrailer bool

	mu      sync.Mutex
	closed  bool
	busy    bool // a boundary call is in progress
	started bool // header/manifest/runtime/config established

	active atomic.Bool // true between boundary enter/exit (lock-free read for doubles)

	depth   uint32
	parents []uint64
	seq     uint64 // next event sequence number
	events  uint64 // number of event frames emitted/consumed
	fileSeq uint32 // next wrapped file id

	// verr is the first replay verification failure of the in-flight call.
	verr error

	// writeErr is the first log writer failure (record mode); after it is
	// set event emission becomes a no-op and the boundary fails closed.
	writeErr error

	manifest Manifest
	runtime  RuntimeFP
	config   ConfigFP
	flags    uint16
}

type sessionKey struct{}

// NewSession creates a recording or replaying session.
func NewSession(mode Mode, stream io.Writer, frames []rawFrame, opts Options) *Session {
	s := &Session{mode: mode, opts: opts, frames: frames}
	if mode == ModeRecord {
		s.w = stream
		s.logHash = sha256.New()
	}
	return s
}

// WithSession attaches a session to a context. The same armed context must
// be used for host module compilation, guest compilation, instantiation and
// calls.
func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// SessionFromContext returns the attached session or nil (default off).
func SessionFromContext(ctx context.Context) *Session {
	if ctx == nil {
		return nil
	}
	if s, ok := ctx.Value(sessionKey{}).(*Session); ok {
		return s
	}
	return nil
}

// Mode reports the session mode.
func (s *Session) Mode() Mode { return s.mode }

// ---------------------------------------------------------------------------
// lifecycle hooks (wired into the root wazero package)
// ---------------------------------------------------------------------------

// OnGuestCompiled is invoked when a guest module is compiled. On record it
// writes the header, manifest and runtime preface records; on replay it
// validates them before any instantiation can happen.
func (s *Session) OnGuestCompiled(m Manifest, rt RuntimeFP) (err error) {
	defer guardEntry(&err)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fail(KindState, StageSession, -1, -1, "session closed")
	}
	if s.started {
		// Only the first guest compilation establishes the preface.
		return nil
	}
	if s.mode == ModeRecord {
		if err := s.writePreface(m, rt); err != nil {
			return err
		}
	} else {
		if err := s.verifyPreface(m, rt); err != nil {
			return err
		}
	}
	s.manifest = m
	s.runtime = rt
	s.started = true
	return nil
}

// OnGuestInstantiated is invoked right before a guest module (including its
// start functions) is instantiated.
func (s *Session) OnGuestInstantiated(c ConfigFP) (err error) {
	defer guardEntry(&err)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fail(KindState, StageSession, -1, -1, "session closed")
	}
	if !s.started {
		return fail(KindState, StageSession, -1, -1, "guest module was compiled without an attached session")
	}
	if s.mode == ModeRecord {
		var e encBuffer
		encodeConfig(&e, c)
		if err := writeFrame(s.w, s.logHash, rtConfig, e.b); err != nil {
			return err
		}
	} else {
		f, err := s.nextPreface(rtConfig)
		if err != nil {
			return err
		}
		if got := decodeConfig(f.payload); !configEqual(got, c) {
			return fail(KindModuleConfig, StageConfig, -1, f.offset,
				"module configuration differs from the recorded run")
		}
		s.config = c
	}
	s.config = c
	return nil
}

// Finalize writes (record) or verifies (replay) the trailer.
func (s *Session) Finalize() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	if s.mode == ModeRecord {
		if s.writeErr != nil {
			s.closeErr = &ReplayError{Kind: KindState, Stage: StageEvent, EventSeq: int64(s.seq),
				Detail: "execution log writer failed", Err: s.writeErr}
			return s.closeErr
		}
		var e encBuffer
		e.u64(s.events)
		e.hash([32]byte(s.logHash.Sum(nil)))
		if err := writeFrame(s.w, discardHash{}, rtTrailer, e.b); err != nil {
			s.closeErr = err
			return err
		}
		return nil
	}
	// Replay: the trailer frame is held outside s.frames.
	if !s.sawTrailer {
		return fail(KindLogTruncated, StageTrailer, -1, -1, "log ends without a trailer")
	}
	if s.evPos != len(s.frames) {
		return fail(KindCallOrder, StageEvent, int64(s.seq), -1,
			"replay consumed %d of %d events; call sequence changed", s.evPos, len(s.frames))
	}
	return nil
}

type discardHash struct{}

func (discardHash) Write(p []byte) (int, error) { return len(p), nil }
func (discardHash) Sum(b []byte) []byte         { return nil }
func (discardHash) Reset()                      {}
func (discardHash) Size() int                   { return 32 }
func (discardHash) BlockSize() int              { return 0 }

// ---------------------------------------------------------------------------
// preface encoding
// ---------------------------------------------------------------------------

func (s *Session) writePreface(m Manifest, rt RuntimeFP) error {
	flags := uint16(0)
	if s.opts.MemoryIntegrity {
		flags |= FlagMemoryIntegrity
	}
	s.flags = flags

	var h encBuffer
	h.b = append(h.b, LogMagic...)
	h.u16(LogVersion)
	h.u16(flags)
	h.u32(0) // reserved
	if err := writeFrame(s.w, s.logHash, rtHeader, h.b); err != nil {
		return err
	}

	var me encBuffer
	me.hash(m.ModuleSHA)
	me.u32(uint32(len(m.Sigs)))
	for _, sig := range m.Sigs {
		me.boolean(sig.Import)
		me.str(sig.Module)
		me.str(sig.Name)
		me.bytes(sig.Params)
		me.bytes(sig.Results)
	}
	if err := writeFrame(s.w, s.logHash, rtManifest, me.b); err != nil {
		return err
	}

	var re encBuffer
	encodeRuntime(&re, rt)
	return writeFrame(s.w, s.logHash, rtRuntime, re.b)
}

func (s *Session) verifyPreface(m Manifest, rt RuntimeFP) error {
	// Header is decoded by NewReplayer into s.flags.
	f, err := s.nextPreface(rtManifest)
	if err != nil {
		return err
	}
	d := decBuffer{b: f.payload}
	gotSHA := d.hash()
	n := int(d.u32())
	var gotSigs []Sig
	for i := 0; i < n; i++ {
		gotSigs = append(gotSigs, Sig{
			Import:  d.boolean(),
			Module:  d.str(),
			Name:    d.str(),
			Params:  d.bytes(),
			Results: d.bytes(),
		})
	}
	if gotSHA != m.ModuleSHA {
		return fail(KindModuleDigest, StageManifest, -1, f.offset,
			"module binary sha256 %x does not match recorded %x", m.ModuleSHA[:8], gotSHA[:8])
	}
	if !sigsEqual(gotSigs, m.Sigs) {
		return fail(KindSignature, StageManifest, -1, f.offset,
			"imported/exported function signatures differ from the recorded module")
	}
	s.manifest = m

	f, err = s.nextPreface(rtRuntime)
	if err != nil {
		return err
	}
	if got := decodeRuntime(f.payload); got != rt {
		return fail(KindRuntimeConfig, StageRuntime, -1, f.offset,
			"runtime configuration differs: recorded %+v, replay %+v", got, rt)
	}
	s.runtime = rt
	return nil
}

func (s *Session) nextPreface(typ byte) (rawFrame, error) {
	if s.evPos >= len(s.frames) {
		return rawFrame{}, fail(KindLogTruncated, stageForType(typ), -1, -1,
			"log ends before expected preface record 0x%02x", typ)
	}
	f := s.frames[s.evPos]
	if f.typ != typ {
		if f.typ >= evCallEnter {
			return f, fail(KindCallOrder, stageForType(typ), -1, f.offset,
				"event stream starts before preface record 0x%02x is complete", typ)
		}
		return f, fail(KindCallOrder, stageForType(typ), -1, f.offset,
			"expected preface record 0x%02x, got 0x%02x", typ, f.typ)
	}
	s.evPos++
	return f, nil
}

func encodeRuntime(e *encBuffer, rt RuntimeFP) {
	e.str(rt.Engine)
	e.u64(rt.CoreFeatures)
	e.u32(rt.MemoryLimitPages)
	e.boolean(rt.MemoryCapacityFromMax)
	e.boolean(rt.EnsureTermination)
}

func decodeRuntime(b []byte) RuntimeFP {
	d := decBuffer{b: b}
	return RuntimeFP{
		Engine:                d.str(),
		CoreFeatures:          d.u64(),
		MemoryLimitPages:      d.u32(),
		MemoryCapacityFromMax: d.boolean(),
		EnsureTermination:     d.boolean(),
	}
}

func encodeConfig(e *encBuffer, c ConfigFP) {
	e.str(c.Name)
	e.boolean(c.NameSet)
	e.strList(c.StartFunctions)
	e.byteSliceList(c.Args)
	e.byteSliceList(c.Environ)
	e.strList(c.GuestPaths)
	e.u64(c.WalltimeResolution)
	e.u64(c.NanotimeResolution)
	e.boolean(c.HasCustomWalltime)
	e.boolean(c.HasCustomNanotime)
	e.boolean(c.HasCustomNanosleep)
	e.boolean(c.HasRandSource)
	e.boolean(c.HasStdin)
	e.boolean(c.HasStdout)
	e.boolean(c.HasStderr)
	e.boolean(c.HasTCPListeners)
}

func decodeConfig(b []byte) ConfigFP {
	d := decBuffer{b: b}
	return ConfigFP{
		Name:               d.str(),
		NameSet:            d.boolean(),
		StartFunctions:     d.strList(),
		Args:               d.byteSliceList(),
		Environ:            d.byteSliceList(),
		GuestPaths:         d.strList(),
		WalltimeResolution: d.u64(),
		NanotimeResolution: d.u64(),
		HasCustomWalltime:  d.boolean(),
		HasCustomNanotime:  d.boolean(),
		HasCustomNanosleep: d.boolean(),
		HasRandSource:      d.boolean(),
		HasStdin:           d.boolean(),
		HasStdout:          d.boolean(),
		HasStderr:          d.boolean(),
		HasTCPListeners:    d.boolean(),
	}
}

// ---------------------------------------------------------------------------
// event primitives
// ---------------------------------------------------------------------------

func (s *Session) parentTop() uint64 {
	if len(s.parents) == 0 {
		return 0
	}
	return s.parents[len(s.parents)-1]
}

// emitEvent writes an event with the common header (seq, depth, parent).
// Callers hold s.mu. Writer failures fail the session closed instead of
// panicking, so guests and engines keep their normal error propagation.
func (s *Session) emitEvent(typ byte, body []byte) {
	if s.writeErr != nil {
		return
	}
	var e encBuffer
	e.u64(s.seq)
	e.u32(s.depth)
	e.u64(s.parentTop())
	e.b = append(e.b, body...)
	if err := writeFrame(s.w, s.logHash, typ, e.b); err != nil {
		s.writeErr = err
		s.closed = true
		return
	}
	s.seq++
	s.events++
}

// expectEvent reads the next event and verifies type and sequence position.
// Depth/parent are returned for structural verification by the caller.
// Callers hold s.mu.
func (s *Session) expectEvent(typ byte) (*decBuffer, uint32, uint64, error) {
	if s.evPos >= len(s.frames) {
		return nil, 0, 0, fail(KindLogTruncated, StageEvent, int64(s.seq), -1,
			"log ended while expecting event 0x%02x", typ)
	}
	f := s.frames[s.evPos]
	if f.typ != typ {
		return nil, 0, 0, fail(KindCallOrder, StageEvent, int64(s.seq), f.offset,
			"expected event 0x%02x at position %d, got 0x%02x", typ, s.seq, f.typ)
	}
	d := &decBuffer{b: f.payload}
	seq := d.u64()
	depth := d.u32()
	parent := d.u64()
	if seq != s.seq {
		return nil, 0, 0, fail(KindCallOrder, StageEvent, int64(s.seq), f.offset,
			"event sequence position changed: log has %d, replay expects %d", seq, s.seq)
	}
	s.evPos++
	s.seq++
	s.events++
	return d, depth, parent, nil
}

// verifyNest checks the event nesting against the current state.
func (s *Session) verifyNest(depth uint32, parent uint64, wantDepth uint32, what string) error {
	if depth != wantDepth {
		return fail(KindNested, StageEvent, int64(s.seq-1), -1,
			"%s nesting depth changed: recorded %d, replay %d", what, depth, wantDepth)
	}
	if parent != s.parentTop() {
		return fail(KindNested, StageEvent, int64(s.seq-1), -1,
			"%s parent event changed: recorded #%d, replay #%d", what, parent, s.parentTop())
	}
	return nil
}

// classifyError maps a call error to the recorded class + code/message.
func classifyError(err error, ctx context.Context) (class byte, code uint32, msg string) {
	if err == nil {
		return classOK, 0, ""
	}
	// A caller-canceled context takes precedence: with close-on-context-done
	// the engine surfaces that as a module ExitError, but the guest-observable
	// cause is the cancellation.
	if ctx != nil && ctx.Err() != nil {
		return classCanceled, 0, ctx.Err().Error()
	}
	var ee *topwazero.ExitError
	if errors.As(err, &ee) {
		return classExit, ee.ExitCode(), ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return classCanceled, 0, err.Error()
	}
	var pe *hostPanicError
	if errors.As(err, &pe) {
		return classPanic, 0, pe.Error()
	}
	return classTrap, 0, err.Error()
}

// hostPanicError marks errors reconstructed from an aborted host call.
type hostPanicError struct{ msg string }

func (e *hostPanicError) Error() string { return e.msg }

var _ hash.Hash = discardHash{}
