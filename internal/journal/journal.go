// Package journal implements the engine-independent core of the default-off
// Function.Call record/replay mechanism.
//
// A Recording is an immutable, integrity-checked execution journal for exactly
// one api.Function.Call invocation. It captures every external interaction
// that can influence the result of the Wasm execution:
//
//   - calls to imported (host) functions, in invocation order, including
//     nested calls, their parameters, results and failures,
//   - the memory effects (page-granular diffs) and memory growth caused by
//     those host interactions,
//   - and the terminal state of the call: normal return, module exit, trap or
//     Context cancellation.
//
// WASI time and random sources are host functions, so their results are
// journaled through the same mechanism without special casing the time or
// randomness sources.
//
// The format is identical for the interpreter and compiler engines because
// events are taken at the shared host-function boundary, which is the only
// boundary that exists in both engines.
package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// FormatVersion is the version of the journal binary format. It is bumped
// whenever the on-disk layout changes.
const FormatVersion uint16 = 1

var magic = [4]byte{'W', 'Z', 'J', 'R'}

// Sentinel errors returned when loading or verifying a Recording.
var (
	// ErrFormat is returned when the data does not carry the journal magic.
	ErrFormat = errors.New("journal: unrecognized record format")
	// ErrVersion is returned when the record was produced by an incompatible
	// journal format version.
	ErrVersion = errors.New("journal: incompatible record version")
	// ErrTruncated is returned when the record ends before its terminal event
	// or integrity trailer, which means the producing call did not finish
	// recording (bounded storage, I/O cutoff, ...).
	ErrTruncated = errors.New("journal: truncated record")
	// ErrIntegrity is returned when the checksum embedded in the record does
	// not match its contents, indicating corruption or tampering.
	ErrIntegrity = errors.New("journal: integrity check failed")
	// ErrIncomplete is returned when attempting to replay a recording that
	// never reached a terminal event (it was muted or aborted).
	ErrIncomplete = errors.New("journal: record is incomplete and cannot be replayed")

	// errRecordingLimit is panicked inside the engine when the abort failure
	// policy is triggered. It is converted into a normal error by the
	// top-level Record helper.
	errRecordingLimit = errors.New("journal: recording bound exceeded")
	// errReplayAbort is panicked inside the engine when replay detects a
	// divergence. The top-level Replay helper surfaces the detailed DiffError.
	errReplayAbort = errors.New("journal: replay aborted")
)

// Status is the terminal state of a recorded Function.Call.
type Status uint8

const (
	// StatusNone is the state of a recording that has not been sealed yet.
	StatusNone Status = iota
	// StatusCompleted means the call returned normally.
	StatusCompleted
	// StatusExited means the module was closed via proc_exit / CloseWithExitCode.
	StatusExited
	// StatusTrap means the call ended with an unreachable, runtime trap or any
	// non-exit error.
	StatusTrap
	// StatusContextCanceled means the call ended because ctx was canceled.
	StatusContextCanceled
	// StatusContextDeadline means the call ended because ctx reached its deadline.
	StatusContextDeadline
	// StatusTruncated means a configured bound was hit while recording.
	StatusTruncated
)

// String implements fmt.Stringer.
func (s Status) String() string {
	switch s {
	case StatusCompleted:
		return "completed"
	case StatusExited:
		return "exited"
	case StatusTrap:
		return "trap"
	case StatusContextCanceled:
		return "context canceled"
	case StatusContextDeadline:
		return "context deadline exceeded"
	case StatusTruncated:
		return "truncated"
	default:
		return "none"
	}
}

// FailurePolicy decides what the recorder does when a configured bound is
// reached.
type FailurePolicy uint8

const (
	// FailurePolicyAbort aborts the recorded Function.Call with an error and
	// seals the recording with StatusTruncated.
	FailurePolicyAbort FailurePolicy = iota
	// FailurePolicyContinue finishes the Function.Call normally but mutes the
	// recorder; the resulting recording has StatusTruncated and cannot be
	// replayed.
	FailurePolicyContinue
)

// DiffError is returned by Replay when the execution diverges from the
// recording. Index is the zero-based root host-event index at which the
// divergence was observed, or -1 for header/terminal mismatches.
type DiffError struct {
	Index int
	// Field names the divergent part, e.g. "module", "function", "params",
	// "results", "memory", "signature", "order", "terminal" or "header".
	Field string
	Want  string
	Got   string
}

func newDiff(index int, field, format string, args ...interface{}) *DiffError {
	return &DiffError{Index: index, Field: field, Got: fmt.Sprintf(format, args...)}
}

// NewDiffError constructs a locatable divergence error. It is exported for the
// public journal package which cannot use the unexported constructor.
func NewDiffError(index int, field, want, got string) *DiffError {
	return &DiffError{Index: index, Field: field, Want: want, Got: got}
}

// Error implements error.
func (e *DiffError) Error() string {
	where := "terminal"
	if e.Index >= 0 {
		where = fmt.Sprintf("host event #%d", e.Index)
	} else if e.Field == "header" || e.Field == "signature" {
		where = "record header"
	}
	if e.Want != "" {
		return fmt.Sprintf("journal: replay divergence at %s: %s mismatch: want %s, got %s",
			where, e.Field, e.Want, e.Got)
	}
	return fmt.Sprintf("journal: replay divergence at %s: %s: %s", where, e.Field, e.Got)
}

// Is supports errors.Is targeting a DiffError value.
func (e *DiffError) Is(target error) bool {
	_, ok := target.(*DiffError)
	return ok
}

// ImportSig is the recorded identity of one imported function (and, for
// non-function imports, its kind and name).
type ImportSig struct {
	Kind    byte
	Module  string
	Name    string
	Params  []byte
	Results []byte
}

const (
	externFunc   byte = 1
	externTable  byte = 2
	externMemory byte = 3
	externGlobal byte = 4
	externTag    byte = 5
)

// Header identifies what was recorded and under which configuration. It is
// checked before any replayed host interaction is driven.
type Header struct {
	WazeroVersion      string
	Engine             string // "interpreter" or "compiler"
	Features           uint64
	RuntimeDigest      [32]byte
	ModuleConfigDigest [32]byte
	ModuleID           [32]byte
	ModuleName         string
	FunctionName       string
	InitPages          uint32
	InitMemoryHash     [32]byte
	Imports            []ImportSig
	Params             []uint64
}

// PanicClass classifies a failure raised by a host function.
type PanicClass uint8

const (
	panicNone PanicClass = iota
	// panicExit is *sys.ExitError.
	panicExit
	// panicErrno is experimental/sys.Errno (WASI style errno panic).
	panicErrno
	// panicString is a non-error string panic.
	panicString
	// panicOther is any other panic or error.
	panicOther
)

// HostEvent is one recorded host-function interaction. Children holds host
// interactions issued re-entrantly (host function calling back into Wasm that
// calls another host function). Children are recorded for inspection but are
// never driven on replay: their effects are contained in the parent event's
// results and memory patches.
type HostEvent struct {
	Module string
	Name   string

	Params  []uint64
	Results []uint64

	PanicClass   PanicClass
	PanicValue   uint64
	PanicMessage string

	// PrePages and PostPages checkpoint the caller memory size around the
	// interaction. Patches are page-granular new contents (64KiB pages, the
	// final page may be shorter).
	PrePages  uint32
	PostPages uint32
	Patches   []MemoryPatch

	Children []*HostEvent

	// preHashes is the per-page FNV hash before the call; recording only.
	preHashes map[uint32]uint64
}

// MemoryPatch records the new full contents of one memory page after a host
// interaction.
type MemoryPatch struct {
	Page uint32
	Data []byte
}

// EndEvent is the sealed terminal state of the call.
type EndEvent struct {
	Status      Status
	ExitCode    uint32
	TrapMessage string
	Results     []uint64
	Pages       uint32
	MemoryHash  [32]byte
}

const (
	kindHost byte = 1
	kindEnd  byte = 2
)

// Options configures a Recorder session.
type Options struct {
	MaxBytes      int
	MaxEvents     int
	FailurePolicy FailurePolicy
}

// Recording is an immutable, sealed execution record.
type Recording struct {
	header Header
	roots  []*HostEvent
	end    EndEvent

	// raw is the canonical serialized bytes; it is never mutated after seal.
	raw []byte
}

// Header returns a copy of the record header.
func (r *Recording) Header() Header {
	h := r.header
	h.Imports = append([]ImportSig(nil), r.header.Imports...)
	h.Params = append([]uint64(nil), r.header.Params...)
	return h
}

// Status returns the terminal status of the record.
func (r *Recording) Status() Status { return r.end.Status }

// EventCount returns the number of root host events. Nested events are not
// counted.
func (r *Recording) EventCount() int { return len(r.roots) }

// ExitCode returns the exit code when Status is StatusExited.
func (r *Recording) ExitCode() uint32 { return r.end.ExitCode }

// RootEvents returns the root events for inspection. The returned slice and
// the events must be treated as read-only.
func (r *Recording) RootEvents() []*HostEvent { return r.roots }

// End returns a copy of the terminal event.
func (r *Recording) End() EndEvent {
	e := r.end
	e.Results = append([]uint64(nil), r.end.Results...)
	return e
}

// MarshalBinary returns the canonical serialized record. The returned bytes
// are a copy and may be retained by the caller.
func (r *Recording) MarshalBinary() ([]byte, error) {
	if len(r.raw) == 0 {
		return nil, ErrIncomplete
	}
	out := make([]byte, len(r.raw))
	copy(out, r.raw)
	return out, nil
}

// Verify checks the record status and integrity. It returns ErrTruncated for
// truncated records, ErrIncomplete for unsealed records and ErrIntegrity for
// tampered contents.
func (r *Recording) Verify() error {
	if r.end.Status == StatusNone {
		return ErrIncomplete
	}
	if err := verifyRaw(r.raw); err != nil {
		return err
	}
	if r.end.Status == StatusTruncated {
		return ErrTruncated
	}
	return nil
}

// UnmarshalRecording parses and verifies a serialized recording.
func UnmarshalRecording(data []byte) (*Recording, error) {
	hdr, roots, end, err := decodeRecording(data)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, len(data))
	copy(raw, data)
	return &Recording{header: hdr, roots: roots, end: *end, raw: raw}, nil
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

func appendU8(b *bytes.Buffer, v byte) { b.WriteByte(v) }
func appendU16(b *bytes.Buffer, v uint16) {
	var t [2]byte
	binary.LittleEndian.PutUint16(t[:], v)
	b.Write(t[:])
}
func appendU32(b *bytes.Buffer, v uint32) {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], v)
	b.Write(t[:])
}
func appendU64(b *bytes.Buffer, v uint64) {
	var t [8]byte
	binary.LittleEndian.PutUint64(t[:], v)
	b.Write(t[:])
}
func appendBytes(b *bytes.Buffer, p []byte)  { appendU32(b, uint32(len(p))); b.Write(p) }
func appendString(b *bytes.Buffer, s string) { appendU32(b, uint32(len(s))); b.WriteString(s) }

func appendU64s(b *bytes.Buffer, vs []uint64) {
	appendU32(b, uint32(len(vs)))
	var t [8]byte
	for _, v := range vs {
		binary.LittleEndian.PutUint64(t[:], v)
		b.Write(t[:])
	}
}

func appendHash(b *bytes.Buffer, h [32]byte) { b.Write(h[:]) }

func encodeHeader(h *Header) []byte {
	var b bytes.Buffer
	appendString(&b, h.WazeroVersion)
	appendString(&b, h.Engine)
	appendU64(&b, h.Features)
	appendHash(&b, h.RuntimeDigest)
	appendHash(&b, h.ModuleConfigDigest)
	appendHash(&b, h.ModuleID)
	appendString(&b, h.ModuleName)
	appendString(&b, h.FunctionName)
	appendU32(&b, h.InitPages)
	appendHash(&b, h.InitMemoryHash)
	appendU32(&b, uint32(len(h.Imports)))
	for _, im := range h.Imports {
		appendU8(&b, im.Kind)
		appendString(&b, im.Module)
		appendString(&b, im.Name)
		appendBytes(&b, im.Params)
		appendBytes(&b, im.Results)
	}
	appendU64s(&b, h.Params)
	return b.Bytes()
}

func encodeHostEvent(ev *HostEvent) []byte {
	var b bytes.Buffer
	appendString(&b, ev.Module)
	appendString(&b, ev.Name)
	appendU64s(&b, ev.Params)
	appendU64s(&b, ev.Results)
	appendU8(&b, byte(ev.PanicClass))
	appendU64(&b, ev.PanicValue)
	appendString(&b, ev.PanicMessage)
	appendU32(&b, ev.PrePages)
	appendU32(&b, ev.PostPages)
	appendU32(&b, uint32(len(ev.Patches)))
	for _, p := range ev.Patches {
		appendU32(&b, p.Page)
		appendBytes(&b, p.Data)
	}
	appendU32(&b, uint32(len(ev.Children)))
	for _, c := range ev.Children {
		appendBytes(&b, encodeHostEvent(c))
	}
	return b.Bytes()
}

func encodeEnd(e *EndEvent) []byte {
	var b bytes.Buffer
	appendU8(&b, byte(e.Status))
	appendU32(&b, e.ExitCode)
	appendString(&b, e.TrapMessage)
	appendU64s(&b, e.Results)
	appendU32(&b, e.Pages)
	appendHash(&b, e.MemoryHash)
	return b.Bytes()
}

// seal serializes the recording and appends the integrity trailer.
// Framing: each frame is [kind u8][u32 len][payload]; the header uses the
// reserved kind 0.
func seal(hdr *Header, roots []*HostEvent, end *EndEvent) (*Recording, error) {
	var out bytes.Buffer
	out.Write(magic[:])
	appendU16(&out, FormatVersion)
	appendFrame(&out, 0, encodeHeader(hdr))
	for _, ev := range roots {
		appendFrame(&out, kindHost, encodeHostEvent(ev))
	}
	appendFrame(&out, kindEnd, encodeEnd(end))
	sum := sha256.Sum256(out.Bytes())
	out.Write(sum[:])

	// Decode once to make sure the producer never emits an unreadable record.
	rh, rr, re, err := decodeRecording(out.Bytes())
	if err != nil {
		return nil, err
	}
	return &Recording{header: rh, roots: rr, end: *re, raw: out.Bytes()}, nil
}

func appendFrame(b *bytes.Buffer, kind byte, payload []byte) {
	appendU8(b, kind)
	appendU32(b, uint32(len(payload)))
	b.Write(payload)
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

type reader struct {
	b []byte
	p int
}

func (r *reader) u8() (byte, bool) {
	if r.p+1 > len(r.b) {
		return 0, false
	}
	v := r.b[r.p]
	r.p++
	return v, true
}

func (r *reader) u16() (uint16, bool) {
	if r.p+2 > len(r.b) {
		return 0, false
	}
	v := binary.LittleEndian.Uint16(r.b[r.p:])
	r.p += 2
	return v, true
}

func (r *reader) u32() (uint32, bool) {
	if r.p+4 > len(r.b) {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(r.b[r.p:])
	r.p += 4
	return v, true
}

func (r *reader) u64() (uint64, bool) {
	if r.p+8 > len(r.b) {
		return 0, false
	}
	v := binary.LittleEndian.Uint64(r.b[r.p:])
	r.p += 8
	return v, true
}

func (r *reader) hash() ([32]byte, bool) {
	var h [32]byte
	if r.p+32 > len(r.b) {
		return h, false
	}
	copy(h[:], r.b[r.p:r.p+32])
	r.p += 32
	return h, true
}

func (r *reader) bytes() ([]byte, bool) {
	n, ok := r.u32()
	if !ok || uint64(r.p)+uint64(n) > uint64(len(r.b)) {
		return nil, false
	}
	v := r.b[r.p : r.p+int(n)]
	r.p += int(n)
	return v, true
}

func (r *reader) str() (string, bool) {
	v, ok := r.bytes()
	return string(v), ok
}

func (r *reader) u64s() ([]uint64, bool) {
	n, ok := r.u32()
	if !ok {
		return nil, false
	}
	if uint64(r.p)+uint64(n)*8 > uint64(len(r.b)) {
		return nil, false
	}
	vs := make([]uint64, n)
	for i := range vs {
		vs[i] = binary.LittleEndian.Uint64(r.b[r.p:])
		r.p += 8
	}
	return vs, true
}

func verifyRaw(raw []byte) error {
	if len(raw) < len(magic)+2+sha256.Size {
		return ErrTruncated
	}
	body := raw[:len(raw)-sha256.Size]
	sum := sha256.Sum256(body)
	if !bytes.Equal(sum[:], raw[len(raw)-sha256.Size:]) {
		return ErrIntegrity
	}
	return nil
}

func decodeRecording(raw []byte) (Header, []*HostEvent, *EndEvent, error) {
	var hdr Header
	if len(raw) < len(magic)+2+sha256.Size {
		return hdr, nil, nil, ErrTruncated
	}
	if !bytes.Equal(raw[:len(magic)], magic[:]) {
		return hdr, nil, nil, ErrFormat
	}
	// Structural completeness is checked before the checksum: a record that
	// does not parse to its terminal frame is truncated, while a complete but
	// checksum-invalid record is tampered.
	r := &reader{b: raw[:len(raw)-sha256.Size]}
	r.p = len(magic)
	ver, ok := r.u16()
	if !ok {
		return hdr, nil, nil, ErrTruncated
	}

	sawHeader := false
	var roots []*HostEvent
	var end *EndEvent
	for {
		kind, ok := r.u8()
		if !ok {
			return hdr, nil, nil, ErrTruncated
		}
		payload, ok := r.bytes()
		if !ok {
			return hdr, nil, nil, ErrTruncated
		}
		pr := &reader{b: payload}
		switch kind {
		case 0:
			if sawHeader {
				return hdr, nil, nil, ErrFormat
			}
			h, err := decodeHeader(pr)
			if err != nil {
				return hdr, nil, nil, err
			}
			hdr = h
			sawHeader = true
		case kindHost:
			ev, err := decodeHostEvent(pr)
			if err != nil {
				return hdr, nil, nil, err
			}
			roots = append(roots, ev)
		case kindEnd:
			e, err := decodeEnd(pr)
			if err != nil {
				return hdr, nil, nil, err
			}
			end = &e
			if r.p != len(r.b) {
				return hdr, nil, nil, ErrFormat
			}
			if !sawHeader {
				return hdr, nil, nil, ErrFormat
			}
			// Complete structure: integrity first, then format compatibility.
			sum := sha256.Sum256(raw[:len(raw)-sha256.Size])
			if !bytes.Equal(sum[:], raw[len(raw)-sha256.Size:]) {
				return hdr, nil, nil, ErrIntegrity
			}
			if ver != FormatVersion {
				return hdr, nil, nil, fmt.Errorf("%w: record version %d, supported %d", ErrVersion, ver, FormatVersion)
			}
			return hdr, roots, end, nil
		default:
			return hdr, nil, nil, ErrFormat
		}
	}
}

func decodeHeader(r *reader) (Header, error) {
	var h Header
	var ok bool
	if h.WazeroVersion, ok = r.str(); !ok {
		return h, ErrTruncated
	}
	if h.Engine, ok = r.str(); !ok {
		return h, ErrTruncated
	}
	if h.Features, ok = r.u64(); !ok {
		return h, ErrTruncated
	}
	if h.RuntimeDigest, ok = r.hash(); !ok {
		return h, ErrTruncated
	}
	if h.ModuleConfigDigest, ok = r.hash(); !ok {
		return h, ErrTruncated
	}
	if h.ModuleID, ok = r.hash(); !ok {
		return h, ErrTruncated
	}
	if h.ModuleName, ok = r.str(); !ok {
		return h, ErrTruncated
	}
	if h.FunctionName, ok = r.str(); !ok {
		return h, ErrTruncated
	}
	if h.InitPages, ok = r.u32(); !ok {
		return h, ErrTruncated
	}
	if h.InitMemoryHash, ok = r.hash(); !ok {
		return h, ErrTruncated
	}
	n, ok := r.u32()
	if !ok {
		return h, ErrTruncated
	}
	h.Imports = make([]ImportSig, n)
	for i := range h.Imports {
		if h.Imports[i].Kind, ok = r.u8(); !ok {
			return h, ErrTruncated
		}
		if h.Imports[i].Module, ok = r.str(); !ok {
			return h, ErrTruncated
		}
		if h.Imports[i].Name, ok = r.str(); !ok {
			return h, ErrTruncated
		}
		if h.Imports[i].Params, ok = r.bytes(); !ok {
			return h, ErrTruncated
		}
		if h.Imports[i].Results, ok = r.bytes(); !ok {
			return h, ErrTruncated
		}
	}
	if h.Params, ok = r.u64s(); !ok {
		return h, ErrTruncated
	}
	return h, nil
}

func decodeHostEvent(r *reader) (*HostEvent, error) {
	ev := &HostEvent{}
	var ok bool
	if ev.Module, ok = r.str(); !ok {
		return nil, ErrTruncated
	}
	if ev.Name, ok = r.str(); !ok {
		return nil, ErrTruncated
	}
	if ev.Params, ok = r.u64s(); !ok {
		return nil, ErrTruncated
	}
	if ev.Results, ok = r.u64s(); !ok {
		return nil, ErrTruncated
	}
	c, ok := r.u8()
	if !ok {
		return nil, ErrTruncated
	}
	ev.PanicClass = PanicClass(c)
	if ev.PanicValue, ok = r.u64(); !ok {
		return nil, ErrTruncated
	}
	if ev.PanicMessage, ok = r.str(); !ok {
		return nil, ErrTruncated
	}
	if ev.PrePages, ok = r.u32(); !ok {
		return nil, ErrTruncated
	}
	if ev.PostPages, ok = r.u32(); !ok {
		return nil, ErrTruncated
	}
	np, ok := r.u32()
	if !ok {
		return nil, ErrTruncated
	}
	ev.Patches = make([]MemoryPatch, np)
	for i := range ev.Patches {
		if ev.Patches[i].Page, ok = r.u32(); !ok {
			return nil, ErrTruncated
		}
		if ev.Patches[i].Data, ok = r.bytes(); !ok {
			return nil, ErrTruncated
		}
	}
	nc, ok := r.u32()
	if !ok {
		return nil, ErrTruncated
	}
	ev.Children = make([]*HostEvent, nc)
	for i := range ev.Children {
		// Children were encoded as length-prefixed blobs.
		cb, ok := r.bytes()
		if !ok {
			return nil, ErrTruncated
		}
		child, err := decodeHostEvent(&reader{b: cb})
		if err != nil {
			return nil, err
		}
		ev.Children[i] = child
	}
	return ev, nil
}

func decodeEnd(r *reader) (EndEvent, error) {
	var e EndEvent
	var ok bool
	s, ok := r.u8()
	if !ok {
		return e, ErrTruncated
	}
	e.Status = Status(s)
	if e.ExitCode, ok = r.u32(); !ok {
		return e, ErrTruncated
	}
	if e.TrapMessage, ok = r.str(); !ok {
		return e, ErrTruncated
	}
	if e.Results, ok = r.u64s(); !ok {
		return e, ErrTruncated
	}
	if e.Pages, ok = r.u32(); !ok {
		return e, ErrTruncated
	}
	if e.MemoryHash, ok = r.hash(); !ok {
		return e, ErrTruncated
	}
	return e, nil
}

// ---------------------------------------------------------------------------
// Session state machine
// ---------------------------------------------------------------------------

type mode uint8

const (
	modeRecord mode = iota + 1
	modeReplay
)

type frame struct {
	ev     *HostEvent
	parent *frame
}

// Session is the per-Function.Call journal state carried through ctx.
type Session struct {
	mode mode
	o    Options

	// recording state
	hdr       *Header
	roots     []*HostEvent
	top       *frame
	muted     bool
	truncated bool
	bytesUsed int

	// replay state
	rec    *Recording
	cursor int
	diff   *DiffError
	// cancelTrigger, when set, is invoked right after the last root event was
	// driven, to reproduce a recorded Context cancellation deterministically.
	cancelTrigger func()

	// finished records that seal/finish was called.
	finished bool
}

// ContextKey is the ctx key under which a Session is carried.
type ContextKey struct{}

// WithSession returns a child context carrying the session.
func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, ContextKey{}, s)
}

// FromContext returns the active journal session, or nil. When nil, journal
// wrappers take a direct-call path.
func FromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(ContextKey{}).(*Session)
	return s
}

// NewRecordSession starts a recording session.
func NewRecordSession(hdr Header, o Options) *Session {
	if o.MaxBytes < 0 {
		o.MaxBytes = 0
	}
	if o.MaxEvents < 0 {
		o.MaxEvents = 0
	}
	s := &Session{mode: modeRecord, o: o, hdr: &hdr}
	s.bytesUsed = len(magic) + 2 + 4 + len(encodeHeader(&hdr)) + sha256.Size
	return s
}

// NewReplaySession prepares a replay session. The caller must already have
// verified the recording and matched its header.
func NewReplaySession(rec *Recording, cancelTrigger func()) (*Session, error) {
	if err := rec.Verify(); err != nil {
		return nil, err
	}
	if rec.end.Status == StatusTruncated || rec.end.Status == StatusNone {
		return nil, ErrIncomplete
	}
	return &Session{
		mode:          modeReplay,
		rec:           rec,
		cancelTrigger: cancelTrigger,
	}, nil
}

// Diff returns the divergence recorded during replay, if any.
func (s *Session) Diff() *DiffError { return s.diff }

func (s *Session) fail(d *DiffError) {
	if s.diff == nil {
		s.diff = d
	}
}

// enterRecord opens a host interaction frame.
func (s *Session) enterRecord(module, name string, params []uint64, pre map[uint32]uint64, prePages uint32) *HostEvent {
	ev := &HostEvent{
		Module:    module,
		Name:      name,
		Params:    cloneU64(params),
		PrePages:  prePages,
		preHashes: pre,
	}
	if s.top != nil {
		s.top.ev.Children = append(s.top.ev.Children, ev)
	} else if !s.muted {
		if s.o.MaxEvents > 0 && len(s.roots) >= s.o.MaxEvents {
			s.boundReached()
		}
		if !s.muted {
			s.roots = append(s.roots, ev)
		}
	}
	s.top = &frame{ev: ev, parent: s.top}
	return ev
}

// exitRecord closes the current host interaction frame and applies bounded
// storage accounting for root events.
func (s *Session) exitRecord(ev *HostEvent) {
	if s.top != nil && s.top.ev == ev {
		s.top = s.top.parent
	}
	if ev.preHashes != nil {
		ev.preHashes = nil
	}
	// Root events are the only events that count towards the bounds.
	if s.top == nil && !s.muted && len(s.roots) > 0 && s.roots[len(s.roots)-1] == ev {
		s.bytesUsed += 5 + len(encodeHostEvent(ev))
		if s.o.MaxBytes > 0 && s.bytesUsed > s.o.MaxBytes {
			s.boundReached()
			if s.muted && s.o.FailurePolicy == FailurePolicyContinue {
				// Drop the oversized event; the record is already unusable.
				s.roots = s.roots[:len(s.roots)-1]
			}
		}
	}
}

func (s *Session) boundReached() {
	if s.truncated {
		return
	}
	s.truncated = true
	if s.o.FailurePolicy == FailurePolicyAbort {
		panic(errRecordingLimit)
	}
	s.muted = true
}

// Truncated reports whether the recording hit a configured bound.
func (s *Session) Truncated() bool { return s.truncated }

// enterReplay matches and returns the next root event. It panics with
// errReplayAbort on divergence; the detailed DiffError is kept on the
// session.
func (s *Session) enterReplay(module, name string, params []uint64) *HostEvent {
	if s.diff != nil {
		panic(errReplayAbort)
	}
	if s.top != nil {
		// Host functions are never executed on replay, so a nested frame means
		// an interaction occurred that has no place in the root stream.
		s.fail(newDiff(s.cursor, "order", "unexpected nested host call %q.%q while replaying an event", module, name))
		panic(errReplayAbort)
	}
	if s.cursor >= len(s.rec.roots) {
		s.fail(newDiff(s.cursor, "order", "unexpected host call %q.%q: recording has %d event(s)", module, name, len(s.rec.roots)))
		panic(errReplayAbort)
	}
	ev := s.rec.roots[s.cursor]
	if ev.Module != module || ev.Name != name {
		d := newDiff(s.cursor, "function", "")
		d.Want = fmt.Sprintf("%s.%s", ev.Module, ev.Name)
		d.Got = fmt.Sprintf("%s.%s", module, name)
		s.fail(d)
		panic(errReplayAbort)
	}
	if !equalU64(ev.Params, params) {
		d := newDiff(s.cursor, "params", "")
		d.Want = fmtU64(ev.Params)
		d.Got = fmtU64(params)
		s.fail(d)
		panic(errReplayAbort)
	}
	s.top = &frame{ev: ev, parent: nil}
	return ev
}

// exitReplay closes the current replay frame and arms the cancellation
// trigger after the final root event.
func (s *Session) exitReplay(ev *HostEvent) {
	if s.top != nil && s.top.ev == ev {
		s.top = s.top.parent
	}
	s.cursor++
	if s.cancelTrigger != nil && s.cursor == len(s.rec.roots) {
		t := s.cancelTrigger
		s.cancelTrigger = nil
		t()
	}
}

// FinishReplay verifies that every recorded root interaction was driven.
func (s *Session) FinishReplay() error {
	if s.diff != nil {
		return s.diff
	}
	if s.cursor != len(s.rec.roots) {
		return newDiff(s.cursor, "order", "recording has %d unconsumed host event(s)", len(s.rec.roots)-s.cursor)
	}
	return nil
}

// Seal finalizes a recording session and returns the immutable Recording.
func (s *Session) Seal(end EndEvent) (*Recording, error) {
	s.finished = true
	if s.truncated {
		end.Status = StatusTruncated
	}
	return seal(s.hdr, s.roots, &end)
}

func cloneU64(in []uint64) []uint64 {
	if len(in) == 0 {
		return nil
	}
	out := make([]uint64, len(in))
	copy(out, in)
	return out
}

func equalU64(a, b []uint64) bool {
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

func fmtU64(vs []uint64) string {
	return fmt.Sprintf("%v", vs)
}
