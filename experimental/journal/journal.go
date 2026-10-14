// Package journal provides default-off recording and deterministic replay of
// individual api.Function.Call invocations.
//
// # Overview
//
// A [Recorder.Record] performs a Function.Call while building an immutable
// [Recording] of every external interaction that can influence its result:
//
//   - the module identity, enabled features, runtime/module configuration and
//     import signature manifest,
//   - imported (host) function invocations in order, including nested calls,
//     their parameters, results and failures,
//   - the memory effects and memory growth caused by those interactions (this
//     is what captures WASI clock/random values, file reads and similar
//     memory-mediated inputs),
//   - and the terminal state: normal return, module exit, trap or Context
//     cancellation.
//
// A replay drives the recorded non-deterministic inputs back into a
// re-instantiated module without ever invoking the user-provided host
// functions, so host-side effects are never repeated. Divergences (call
// order, parameters, results, memory operations, terminal state) stop the
// replay immediately with a locatable [DiffError].
//
// Because events are captured at the host-function boundary shared by the
// interpreter and the compiler, both engines produce and consume the exact
// same record format.
//
// # Enabling
//
// The feature is default-off and adds no allocation or behavior change when
// not enabled. Host modules must be compiled with an enabled context so their
// Go functions are wrapped with the inert journal interceptor:
//
//	ctx := journal.Enable(context.Background())
//	r := wazero.NewRuntime(ctx)
//	wasi_snapshot_preview1.MustInstantiate(ctx, r) // compiled with wrappers
//	// ... compile and instantiate the guest module as usual.
//
// Recording is per-Call and does not require any further setup:
//
//	rec := journal.NewRecorder()
//	results, rec1, err := rec.Record(ctx, mod, fn, params...)
//
// Replay typically runs against a freshly instantiated module:
//
//	results2, err := journal.Replay(ctx, mod2, rec1, fn2, params...)
//
// Recordings are binary blobs with an embedded format version and integrity
// checksum ([Recording.MarshalBinary] / [UnmarshalRecording]).
package journal

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tetratelabs/wazero/api"
	ij "github.com/tetratelabs/wazero/internal/journal"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// Status is the terminal state of a recording.
//
// This is a type alias so consumers can use the constants of this package.
type Status = ij.Status

const (
	// StatusCompleted means the call returned normally.
	StatusCompleted = ij.StatusCompleted
	// StatusExited means the module was closed via proc_exit or
	// CloseWithExitCode.
	StatusExited = ij.StatusExited
	// StatusTrap means the call ended with a trap or non-exit error.
	StatusTrap = ij.StatusTrap
	// StatusContextCanceled means the call ended with context.Canceled.
	StatusContextCanceled = ij.StatusContextCanceled
	// StatusContextDeadline means the call ended with context.DeadlineExceeded.
	StatusContextDeadline = ij.StatusContextDeadline
	// StatusTruncated means a configured recording bound was hit.
	StatusTruncated = ij.StatusTruncated
)

// FailurePolicy decides what happens when a configured bound is reached.
type FailurePolicy = ij.FailurePolicy

const (
	// FailurePolicyAbort aborts the recorded call and seals a truncated
	// recording. This is the default.
	FailurePolicyAbort = ij.FailurePolicyAbort
	// FailurePolicyContinue lets the call finish normally but mutes the
	// recorder; the resulting recording cannot be replayed.
	FailurePolicyContinue = ij.FailurePolicyContinue
)

// Sentinel errors. Replays wrap these in [DiffError] where applicable.
var (
	// ErrTruncated is returned for cut-off or bound-truncated records.
	ErrTruncated = ij.ErrTruncated
	// ErrVersion is returned for incompatible record format versions.
	ErrVersion = ij.ErrVersion
	// ErrIntegrity is returned for checksum failures.
	ErrIntegrity = ij.ErrIntegrity
	// ErrIncomplete is returned for records lacking a terminal event.
	ErrIncomplete = ij.ErrIncomplete
)

// DiffError locates a replay divergence. Index is the zero-based root host
// event index, or -1 for header/terminal mismatches.
type DiffError = ij.DiffError

// Enable opts in to journal instrumentation for host modules compiled while
// the returned context is active. It is safe to chain with other experimental
// context options. Host modules compiled without an enabled context are not
// instrumented and keep their exact original behavior and performance.
func Enable(ctx context.Context) context.Context {
	return ij.Enable(ctx)
}

// Option configures a Recorder.
type Option func(*options)

type options = ij.Options

// WithMaxBytes bounds the serialized size of a recording. Zero disables the
// byte bound.
func WithMaxBytes(n int) Option {
	return func(o *options) { o.MaxBytes = n }
}

// WithMaxEvents bounds the number of root host interactions in a recording.
// Zero disables the event-count bound.
func WithMaxEvents(n int) Option {
	return func(o *options) { o.MaxEvents = n }
}

// WithFailurePolicy selects the behavior when a bound is reached.
func WithFailurePolicy(p FailurePolicy) Option {
	return func(o *options) { o.FailurePolicy = p }
}

// Recorder creates recordings. A Recorder is safe for reuse across unrelated
// calls but must not be shared concurrently for simultaneous calls.
type Recorder struct {
	o options
}

// NewRecorder returns a Recorder with the given options.
func NewRecorder(opts ...Option) *Recorder {
	r := &Recorder{o: options{FailurePolicy: FailurePolicyAbort}}
	for _, opt := range opts {
		opt(&r.o)
	}
	return r
}

// Recording is an immutable, sealed execution record.
type Recording struct {
	r *ij.Recording
}

// MarshalBinary returns a copy of the canonical serialized record.
func (r *Recording) MarshalBinary() ([]byte, error) { return r.r.MarshalBinary() }

// UnmarshalRecording parses and verifies a serialized recording. It fails
// with ErrVersion, ErrTruncated or ErrIntegrity when the blob is not a valid,
// complete record.
func UnmarshalRecording(data []byte) (*Recording, error) {
	rec, err := ij.UnmarshalRecording(data)
	if err != nil {
		return nil, err
	}
	return &Recording{r: rec}, nil
}

// Verify re-checks status and integrity.
func (r *Recording) Verify() error { return r.r.Verify() }

// Status returns the terminal status of the record.
func (r *Recording) Status() Status { return r.r.Status() }

// EventCount returns the number of recorded root host interactions.
func (r *Recording) EventCount() int { return r.r.EventCount() }

// ExitCode returns the exit code when Status is StatusExited.
func (r *Recording) ExitCode() uint32 { return r.r.ExitCode() }

// RootEventNames returns the "module.function" names of recorded root host
// interactions, in invocation order.
func (r *Recording) RootEventNames() []string {
	events := r.r.RootEvents()
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.Module + "." + e.Name
	}
	return out
}

// Results returns the recorded top-level results.
func (r *Recording) Results() []uint64 {
	return r.r.End().Results
}

// Record performs fn.Call(ctx, params...) while recording. The returned
// recording is always non-nil (even when the call errors) and sealed; err is
// exactly the error the underlying Function.Call returned.
//
// mod must be the module instance fn belongs to. The same restrictions as a
// normal Function.Call apply; in particular, recordings of calls that exit or
// trap should be made against a freshly instantiated module.
func (r *Recorder) Record(ctx context.Context, mod api.Module, fn api.Function, params ...uint64) (results []uint64, rec *Recording, err error) {
	inst, err0 := assertModule(mod)
	if err0 != nil {
		return nil, nil, err0
	}
	hdr := ij.BuildHeader(inst, fn, params)
	sess := ij.NewRecordSession(hdr, r.o)
	ctx = ij.WithSession(ctx, sess)

	results, callErr := fn.Call(ctx, params...)
	rec = r.seal(sess, inst, results, callErr)
	return results, rec, callErr
}

// RecordWithStack is the CallWithStack variant of Record. The stack layout is
// identical to api.Function.CallWithStack.
func (r *Recorder) RecordWithStack(ctx context.Context, mod api.Module, fn api.Function, stack []uint64) (rec *Recording, err error) {
	inst, err0 := assertModule(mod)
	if err0 != nil {
		return nil, err0
	}
	pn := len(fn.Definition().ParamTypes())
	var params []uint64
	if pn > 0 {
		if len(stack) < pn {
			return nil, errors.New("journal: stack smaller than the function parameter count")
		}
		params = stack[:pn]
	}
	hdr := ij.BuildHeader(inst, fn, params)
	sess := ij.NewRecordSession(hdr, r.o)
	ctx = ij.WithSession(ctx, sess)

	callErr := fn.CallWithStack(ctx, stack)
	var results []uint64
	if callErr == nil {
		results = resultSlice(stack, fn)
	}
	return r.seal(sess, inst, results, callErr), callErr
}

// Replay replays rec against fn without invoking host functions. The returned
// error is nil for normally completed calls and the original kind of error
// (e.g. *sys.ExitError) for recorded exits/traps/cancellations; any divergence
// is reported as *DiffError.
//
// mod must be a module instance matching the record (same binary, features,
// import signatures and initial memory state). It should normally be freshly
// instantiated.
func Replay(ctx context.Context, mod api.Module, rec *Recording, fn api.Function, params ...uint64) (results []uint64, err error) {
	inst, err0 := assertModule(mod)
	if err0 != nil {
		return nil, err0
	}
	d, ctx2, sess, err0 := beginReplay(ctx, inst, rec, fn, params)
	if err0 != nil {
		return nil, err0
	}
	if d != nil {
		return nil, d
	}
	results, callErr := fn.Call(ctx2, params...)
	if d := finishReplay(sess, inst, rec, callErr, results); d != nil {
		return nil, d
	}
	return results, callErr
}

// ReplayWithStack is the CallWithStack variant of Replay.
func ReplayWithStack(ctx context.Context, mod api.Module, rec *Recording, fn api.Function, stack []uint64) error {
	inst, err0 := assertModule(mod)
	if err0 != nil {
		return err0
	}
	pn := len(fn.Definition().ParamTypes())
	var params []uint64
	if pn > 0 {
		if len(stack) < pn {
			return errors.New("journal: stack smaller than the function parameter count")
		}
		params = stack[:pn]
	}
	d, ctx2, sess, err0 := beginReplay(ctx, inst, rec, fn, params)
	if err0 != nil {
		return err0
	}
	if d != nil {
		return d
	}
	callErr := fn.CallWithStack(ctx2, stack)
	var results []uint64
	if callErr == nil {
		results = resultSlice(stack, fn)
	}
	return finishReplay(sess, inst, rec, callErr, results)
}

func assertModule(mod api.Module) (*wasm.ModuleInstance, error) {
	inst, ok := ij.AssertInstance(mod)
	if !ok {
		return nil, errors.New("journal: api.Module is not an instantiated wazero module")
	}
	return inst, nil
}

func sealRecording(sess *ij.Session, inst *wasm.ModuleInstance, results []uint64, callErr error) *Recording {
	status, exitCode, message := ij.ClassifyTerminal(callErr)
	pages, hash := ij.FinalMemory(inst)
	sealed, err := sess.Seal(ij.EndEvent{
		Status:      status,
		ExitCode:    exitCode,
		TrapMessage: message,
		Results:     results,
		Pages:       pages,
		MemoryHash:  hash,
	})
	if err != nil {
		// Seal only fails on an internal codec bug; surface an empty record.
		panic(err)
	}
	return &Recording{r: sealed}
}

func (r *Recorder) seal(sess *ij.Session, inst *wasm.ModuleInstance, results []uint64, callErr error) *Recording {
	return sealRecording(sess, inst, results, callErr)
}

// beginReplay validates the record against the current module and starts a
// replay session. The returned context must be used for the Function.Call.
func beginReplay(ctx context.Context, inst *wasm.ModuleInstance, rec *Recording, fn api.Function, params []uint64,
) (*DiffError, context.Context, *ij.Session, error) {
	if rec == nil || rec.r == nil {
		return nil, ctx, nil, errors.New("journal: nil recording")
	}
	if err := rec.r.Verify(); err != nil {
		return nil, ctx, nil, err
	}
	want := rec.r.Header()
	got := ij.BuildHeader(inst, fn, params)
	if d := ij.CompareHeader(want, got); d != nil {
		return d, ctx, nil, nil
	}
	if !equalParams(want.Params, params) {
		// CompareHeader does not cover top-level call parameters.
		return ij.NewDiffError(-1, "params", fmtParams(want.Params), fmtParams(params)), ctx, nil, nil
	}

	// Reproduce a recorded cancellation deterministically. With zero recorded
	// host interactions it is fired before the call; otherwise it is fired by
	// the session right after the last recorded root interaction was driven.
	var trigger func()
	end := rec.r.End()
	if end.Status == ij.StatusContextCanceled || end.Status == ij.StatusContextDeadline {
		rctx := newReplayCancelContext(ctx, end.Status == ij.StatusContextDeadline)
		ctx = rctx
		trigger = rctx.cancel
		if rec.r.EventCount() == 0 {
			rctx.cancel()
		}
	}

	sess, err := ij.NewReplaySession(rec.r, trigger)
	if err != nil {
		return nil, ctx, nil, err
	}
	return nil, ij.WithSession(ctx, sess), sess, nil
}

func finishReplay(sess *ij.Session, inst *wasm.ModuleInstance, rec *Recording, callErr error, results []uint64) error {
	if sess != nil {
		if d := sess.Diff(); d != nil {
			return d
		}
		if d := sess.FinishReplay(); d != nil {
			return d
		}
	}
	d := ij.CompareTerminal(rec.r.End(), callErr, results, inst)
	return diffOrNil(d)
}

func diffOrNil(d *ij.DiffError) error {
	if d == nil {
		return nil
	}
	return d
}

func resultSlice(stack []uint64, fn api.Function) []uint64 {
	rn := len(fn.Definition().ResultTypes())
	if rn == 0 || len(stack) < rn {
		return nil
	}
	return stack[len(stack)-rn:]
}

func equalParams(a, b []uint64) bool {
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

func fmtParams(p []uint64) string {
	return fmt.Sprintf("%v", p)
}

// replayCancelContext is a cancellable context whose Err reports
// context.DeadlineExceeded when replay needs to reproduce that terminal code.
type replayCancelContext struct {
	parent   context.Context
	ch       chan struct{}
	deadline bool
	forward  sync.Once
}

func newReplayCancelContext(parent context.Context, deadline bool) *replayCancelContext {
	return &replayCancelContext{parent: parent, ch: make(chan struct{}), deadline: deadline}
}

func (c *replayCancelContext) Deadline() (time.Time, bool) { return time.Time{}, false }

func (c *replayCancelContext) Done() <-chan struct{} {
	c.forward.Do(func() {
		// Propagate a real cancellation of the parent context.
		if d := c.parent.Done(); d != nil {
			go func() {
				select {
				case <-d:
					c.cancel()
				case <-c.ch:
				}
			}()
		}
	})
	return c.ch
}

func (c *replayCancelContext) Err() error {
	select {
	case <-c.ch:
		if c.deadline {
			return context.DeadlineExceeded
		}
		return context.Canceled
	default:
		return nil
	}
}

func (c *replayCancelContext) Value(key any) any { return c.parent.Value(key) }

func (c *replayCancelContext) cancel() {
	select {
	case <-c.ch:
	default:
		close(c.ch)
	}
}
