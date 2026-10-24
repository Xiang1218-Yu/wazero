// Package boundary adds default-off external boundary execution recording
// and deterministic replay to wazero.
//
// Tests and failure reproductions often need to repeat the same WebAssembly
// invocation while clocks, random sources, standard input, file reads and
// host function results would otherwise make the result non-reproducible.
// This package lets a caller attach a versioned execution log to one or a
// group of api.Function.Call invocations and later replay them
// deterministically.
//
// # What is recorded
//
// Everything guest-observable at the external boundary: wall/monotonic
// clocks, random bytes, stdin and file reads, filesystem queries, WASI
// interactions, arbitrary host function parameters/results/aborts, errors,
// call nesting and call boundaries. Write-class side effects (stdout,
// stderr, file writes and filesystem mutations) are recorded as length plus
// a content digest on record, and verified but never re-executed on replay.
//
// # Validation
//
// Before a replay starts, the module binary SHA-256, imported/exported
// function signatures, runtime configuration (engine, features, limits),
// module configuration (args, env, preopens, clocks, start functions) and the
// log format version/magic are validated. During replay every event is
// checked by sequence number: event type, parameter digest, return length,
// result values, guest memory integrity and nested call relationships.
// Truncated logs, unknown event types, parameter mismatches, read overflow,
// call reordering, divergent context cancellation and side effect mismatch
// all return a structured *ReplayError carrying the event position.
//
// # Safety
//
// Recording never modifies user-provided Readers, Writers, ModuleConfigs or
// host objects: wrappers are new values. Replay never invokes user host
// functions and never performs real writes or filesystem mutations.
//
// When no session is attached to a context, wazero behavior (WASI, host
// functions, random source, clocks, filesystems, error propagation and
// performance) is completely unchanged.
package boundary

import (
	"context"
	"io"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	ib "github.com/tetratelabs/wazero/internal/boundary"
)

// ReplayError is the structured error returned for record/replay failures.
// It always carries the event position (EventSeq; -1 for preface failures).
// Inspect with errors.As and match on Kind constants.
type ReplayError = ib.ReplayError

// ErrorKind classifies a structured record/replay failure.
type ErrorKind = ib.ErrorKind

// Error kind constants for use with errors.Is / (*ReplayError).Kind.
const (
	KindFormatVersion    = ib.KindFormatVersion
	KindLogTruncated     = ib.KindLogTruncated
	KindUnknownEventType = ib.KindUnknownEventType
	KindModuleDigest     = ib.KindModuleDigest
	KindSignature        = ib.KindSignature
	KindRuntimeConfig    = ib.KindRuntimeConfig
	KindModuleConfig     = ib.KindModuleConfig
	KindCallOrder        = ib.KindCallOrder
	KindNested           = ib.KindNested
	KindParamMismatch    = ib.KindParamMismatch
	KindResultMismatch   = ib.KindResultMismatch
	KindReadOverflow     = ib.KindReadOverflow
	KindSideEffect       = ib.KindSideEffect
	KindContextCanceled  = ib.KindContextCanceled
	KindTrailer          = ib.KindTrailer
	KindState            = ib.KindState
)

// options are shared by Recorder and Replayer.
type options struct {
	memoryIntegrity bool
}

func defaultOptions() options { return options{memoryIntegrity: true} }

// Option configures a Recorder or Replayer.
type Option func(*options)

// WithMemoryIntegrity toggles hashing the full guest memory after every WASI
// host call (default enabled). A replay always follows the flag stored in
// the log header.
func WithMemoryIntegrity(enabled bool) Option {
	return func(o *options) { o.memoryIntegrity = enabled }
}

// ---------------------------------------------------------------------------
// Recorder
// ---------------------------------------------------------------------------

// Recorder writes a versioned execution log for one or a group of calls. A
// Recorder serializes one in-flight boundary call at a time; for concurrent
// independent calls create an independent Recorder (and runtime) per call.
type Recorder struct {
	s *ib.Session
}

// NewRecorder creates a recording session writing to w.
func NewRecorder(w io.Writer, opts ...Option) *Recorder {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return &Recorder{s: ib.NewSession(ib.ModeRecord, w, nil, ib.Options{MemoryIntegrity: o.memoryIntegrity})}
}

// Attach arms a context with the recorder. The returned context must be used
// when (in this order) compiling host modules such as WASI, compiling the
// guest module, instantiating it and invoking api.Function.Call.
func (r *Recorder) Attach(ctx context.Context) context.Context {
	return ib.WithSession(ctx, r.s)
}

// Call records one api.Function.Call boundary.
func (r *Recorder) Call(ctx context.Context, fn api.Function, params ...uint64) ([]uint64, error) {
	return ib.BoundaryCall(ctx, fn, params)
}

// CallWithStack records one api.Function.CallWithStack boundary.
func (r *Recorder) CallWithStack(ctx context.Context, fn api.Function, stack []uint64) error {
	return ib.BoundaryCallWithStack(ctx, fn, stack)
}

// Close commits the trailer and releases the recorder. After Close no
// further calls may be recorded.
func (r *Recorder) Close() error { return r.s.Finalize() }

// ---------------------------------------------------------------------------
// Replayer
// ---------------------------------------------------------------------------

// Replayer serves deterministic values from a versioned execution log.
type Replayer struct {
	s *ib.Session
}

// NewReplayer reads and fully validates the log framing, header, trailer
// event count and whole-log digest before any replay can start.
func NewReplayer(r io.Reader, opts ...Option) (*Replayer, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	s, err := ib.OpenReplay(raw, ib.Options{MemoryIntegrity: o.memoryIntegrity})
	if err != nil {
		return nil, err
	}
	return &Replayer{s: s}, nil
}

// Attach arms a context with the replayer, mirroring Recorder.Attach.
func (r *Replayer) Attach(ctx context.Context) context.Context {
	return ib.WithSession(ctx, r.s)
}

// Verify explicitly checks the module binary digest and the
// imported/exported function signatures against the log before instantiation.
// CompileModule with an attached context performs the same checks (plus
// runtime configuration); Verify is useful to fail before instantiating.
//
// Call it after the module was compiled with the attached context, passing
// the same binary bytes and the CompiledModule.
func (r *Replayer) Verify(binary []byte, cm wazero.CompiledModule) error {
	return r.s.VerifyPublic(binary, boundarySigs(cm))
}

// Call replays one api.Function.Call boundary, returning a structured
// *ReplayError if any recorded invariant diverges.
func (r *Replayer) Call(ctx context.Context, fn api.Function, params ...uint64) (results []uint64, err error) {
	return ib.BoundaryCall(ctx, fn, params)
}

// CallWithStack replays one api.Function.CallWithStack boundary.
func (r *Replayer) CallWithStack(ctx context.Context, fn api.Function, stack []uint64) error {
	return ib.BoundaryCallWithStack(ctx, fn, stack)
}

// Close verifies the trailer and that every recorded event was consumed.
func (r *Replayer) Close() error { return r.s.Finalize() }
