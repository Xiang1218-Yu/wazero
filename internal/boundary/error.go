// Package boundary implements default-off external boundary execution
// recording and deterministic replay for wazero.
//
// A Session records every guest-observable interaction with the outside
// world (clocks, random bytes, input reads, WASI queries, host function
// results, write side effects, errors and call nesting) into a versioned
// execution log, or replays the same interactions from such a log without
// re-triggering real external side effects.
//
// The package itself exposes no user-facing API: it is wired into the root
// wazero package through opt-in context hooks and is consumed by the public
// experimental/boundary package. When no session is attached to a context,
// wazero behavior is completely unchanged.
package boundary

import (
	"errors"
	"fmt"
)

// ErrorKind classifies a structured record/replay failure.
type ErrorKind string

// Kinds of structured errors. Every replay failure carries the kind, the
// validation stage and the event sequence number (event position).
const (
	// KindFormatVersion: log magic/format version is missing or unsupported.
	KindFormatVersion ErrorKind = "log_format_version"
	// KindLogTruncated: log ends in the middle of a frame or the trailer is
	// missing/incomplete.
	KindLogTruncated ErrorKind = "log_truncated"
	// KindUnknownEventType: a frame carries an event/record type this
	// implementation does not know.
	KindUnknownEventType ErrorKind = "unknown_event_type"
	// KindModuleDigest: module binary SHA-256 differs from the manifest.
	KindModuleDigest ErrorKind = "module_digest_mismatch"
	// KindSignature: imported/exported function signatures differ.
	KindSignature ErrorKind = "signature_mismatch"
	// KindRuntimeConfig: engine kind, core features or runtime limits differ.
	KindRuntimeConfig ErrorKind = "runtime_config_mismatch"
	// KindModuleConfig: module configuration (args, env, preopens, clocks,
	// start functions, ...) differs.
	KindModuleConfig ErrorKind = "module_config_mismatch"
	// KindCallOrder: event type or identity at the next position differs.
	KindCallOrder ErrorKind = "call_order_mismatch"
	// KindNested: nesting depth or parent event differs.
	KindNested ErrorKind = "nested_call_mismatch"
	// KindParamMismatch: parameter digest/count differs.
	KindParamMismatch ErrorKind = "parameter_mismatch"
	// KindResultMismatch: result length, digest or guest memory differs.
	KindResultMismatch ErrorKind = "result_mismatch"
	// KindReadOverflow: replay requested more/different input than recorded.
	KindReadOverflow ErrorKind = "read_overflow"
	// KindSideEffect: write side effect payload/length differs, or a recorded
	// side-effect failure cannot be reproduced.
	KindSideEffect ErrorKind = "side_effect_mismatch"
	// KindContextCanceled: context cancellation state differs between record
	// and replay.
	KindContextCanceled ErrorKind = "context_canceled"
	// KindTrailer: trailer event count or whole-log digest differs.
	KindTrailer ErrorKind = "trailer_mismatch"
	// KindState: the session was used in an invalid way (closed, busy with a
	// concurrent call, log header not yet established, ...).
	KindState ErrorKind = "session_state"
)

// Validation stages at which a failure can be reported.
const (
	StageHeader   = "header"
	StageManifest = "manifest"
	StageRuntime  = "runtime"
	StageConfig   = "module_config"
	StageEvent    = "event"
	StageTrailer  = "trailer"
	StageSession  = "session"
)

// ReplayError is the structured error returned for every record/replay
// validation failure. It always carries the failing event position
// (EventSeq; -1 when the failure occurs before the first event) and can be
// inspected with errors.As.
type ReplayError struct {
	// Kind is one of the Kind* constants.
	Kind ErrorKind
	// Stage is one of the Stage* constants.
	Stage string
	// EventSeq is the zero-based event position at which the failure was
	// detected, or -1 for preface/trailer failures with no event position.
	EventSeq int64
	// ByteOffset is the log byte offset associated with the failure, or -1.
	ByteOffset int64
	// Detail is a human readable explanation.
	Detail string
	// Err wraps an underlying error, if any.
	Err error
}

// Error implements error.
func (e *ReplayError) Error() string {
	pos := fmt.Sprintf("event#%d", e.EventSeq)
	if e.EventSeq < 0 {
		pos = "preface"
	}
	s := fmt.Sprintf("boundary replay error[%s/%s @%s]: %s", e.Stage, e.Kind, pos, e.Detail)
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

// Unwrap implements errors.Unwrap.
func (e *ReplayError) Unwrap() error { return e.Err }

// Is supports errors.Is against errors carrying the same Kind, e.g.
// errors.Is(err, &ReplayError{Kind: KindLogTruncated}).
func (e *ReplayError) Is(target error) bool {
	t, ok := target.(*ReplayError)
	if !ok {
		return false
	}
	return t.Kind == "" || t.Kind == e.Kind
}

func fail(kind ErrorKind, stage string, seq int64, offset int64, detail string, args ...any) error {
	return &ReplayError{
		Kind:       kind,
		Stage:      stage,
		EventSeq:   seq,
		ByteOffset: offset,
		Detail:     fmt.Sprintf(detail, args...),
	}
}

// AsError unwraps a *ReplayError or returns nil.
func AsError(err error) *ReplayError {
	var re *ReplayError
	if errors.As(err, &re) {
		return re
	}
	return nil
}
