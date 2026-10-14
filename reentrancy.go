package wazero

import (
	"context"
	"errors"

	"github.com/tetratelabs/wazero/internal/reentrancy"
	"github.com/tetratelabs/wazero/internal/wasmruntime"
	"github.com/tetratelabs/wazero/sys"
)

// ReentrancyPolicy configures host callback reentrancy control.
//
// Host functions can call guest exports while guest code is still on the
// stack: that callback may re-enter the same module instance, enter another
// module instance, recurse or form a cycle. ReentrancyPolicy decides which of
// these nested guest executions are admitted.
//
// The policy is evaluated at every guest execution segment: the root
// api.Function.Call is depth 0 (always admitted), the first guest invocation
// made by a host function is depth 1, and so on. Pure guest-to-guest calls,
// including cross-module imports, do not add depth.
//
// Policies can be supplied at three scopes, with precedence:
//
//   - call entry: WithReentrancyPolicy, applies to a single api.Function.Call;
//   - module instance: ModuleConfig.WithReentrancyPolicy, used when the module
//     instance is the target of a host-driven reentry;
//   - runtime: RuntimeConfig.WithReentrancyControl, the default for everything
//     instantiated by the runtime.
//
// The feature is disabled by default. Enabling it without tightening any
// knob (see the permissive policy used by WithReentrancyControl) preserves all
// existing behavior. See ClassifyCallError for the error categories produced
// while the feature is enabled.
type ReentrancyPolicy = reentrancy.Policy

// ReentrancyError is returned when a nested guest execution is rejected by the
// active reentrancy policy.
//
// Engine recovery never wraps policy errors with generic recovery text, so
// the value returned from api.Function.Call is directly assignable via
// errors.As. If user code panics with the error, it remains discoverable
// because wrappers use %w.
type ReentrancyError = reentrancy.PolicyError

// ReentrancyReason identifies the specific policy that rejected a segment.
type ReentrancyReason = reentrancy.Reason

// PermissiveReentrancyPolicy allows every kind of host callback reentry:
// same-module and cross-module, unlimited depth, cycle detection off. It is
// intended for RuntimeConfig.WithReentrancyControl when the feature should be
// active (chain binding, cancellation checks, error classification) without
// restricting any existing workload.
func PermissiveReentrancyPolicy() ReentrancyPolicy {
	return reentrancy.PermissivePolicy()
}

// Reentrancy reasons returned in ReentrancyError.Reason.
const (
	// ReasonSameModuleDenied means a host callback tried to re-enter a module
	// instance that was already active while AllowSameModuleReentry was false.
	ReasonSameModuleDenied = reentrancy.ReasonSameModuleDenied

	// ReasonCrossModuleDenied means a host callback tried to enter another
	// module instance while AllowCrossModuleReentry was false.
	ReasonCrossModuleDenied = reentrancy.ReasonCrossModuleDenied

	// ReasonMaxDepthExceeded means the nesting exceeded MaxReentryDepth.
	ReasonMaxDepthExceeded = reentrancy.ReasonMaxDepthExceeded

	// ReasonCycleDetected means the same (module instance, function) node was
	// already active on the chain and DetectCycles was true.
	ReasonCycleDetected = reentrancy.ReasonCycleDetected
)

// WithReentrancyPolicy attaches a call-entry policy override to ctx.
//
// The override replaces the effective policy only for the next
// api.Function.Call receiving this context. It does not propagate to nested
// callbacks issued by host functions during that call; those fall back to the
// target instance and runtime policies.
//
// This has no effect unless the runtime was created with
// RuntimeConfig.WithReentrancyControl.
func WithReentrancyPolicy(ctx context.Context, policy ReentrancyPolicy) context.Context {
	return reentrancy.WithEntryPolicy(ctx, policy)
}

// ReentrancyCallDepth returns the number of active guest execution segments
// visible from ctx.
//
// It reports 0 outside guest execution, 1 inside a host function invoked by
// the root segment, and grows for nested host callbacks. It is always 0 when
// the feature is disabled or the context does not carry a call chain (for
// example when a host function dropped the context wazero passed to it).
func ReentrancyCallDepth(ctx context.Context) int {
	return reentrancy.Depth(ctx)
}

// CallErrorKind categorizes an error returned from api.Function.Call while
// reentrancy control is enabled. It is returned by ClassifyCallError.
type CallErrorKind int

const (
	// CallErrorNone is returned for a nil error.
	CallErrorNone CallErrorKind = iota

	// CallErrorPolicyRejected means a ReentrancyError rejected a nested guest
	// segment before any guest instruction executed.
	CallErrorPolicyRejected

	// CallErrorContextCanceled means the context was canceled or reached its
	// deadline. This covers both direct boundary cancellation and the
	// sys.ExitError emitted by WithCloseOnContextDone using a reserved exit
	// code.
	CallErrorContextCanceled

	// CallErrorGuestTrap means the guest trapped (unreachable, out-of-bounds
	// memory access, integer divide by zero, ...).
	CallErrorGuestTrap

	// CallErrorHostFunction means a function defined via HostFunctionBuilder
	// panicked, or another host-side error that is not a trap, policy rejection
	// or module exit occurred.
	CallErrorHostFunction

	// CallErrorModuleExited means the module was closed with an exit code
	// (including proc_exit) during the call.
	CallErrorModuleExited
)

// String implements fmt.Stringer.
func (k CallErrorKind) String() string {
	switch k {
	case CallErrorPolicyRejected:
		return "policy rejected"
	case CallErrorContextCanceled:
		return "context canceled"
	case CallErrorGuestTrap:
		return "guest trap"
	case CallErrorHostFunction:
		return "host function error"
	case CallErrorModuleExited:
		return "module exited"
	default:
		return "none"
	}
}

// ClassifyCallError maps an api.Function.Call error to the five failure
// categories the reentrancy control surface distinguishes:
//
//   - CallErrorPolicyRejected: errors.As (*ReentrancyError);
//   - CallErrorContextCanceled: errors.Is context.Canceled/DeadlineExceeded,
//     including the reserved sys.ExitError cancellation codes;
//   - CallErrorModuleExited: any other *sys.ExitError;
//   - CallErrorGuestTrap: errors.Is a wazero runtime trap sentinel such as
//     wasmruntime-style "unreachable" or "out of bounds memory access";
//   - CallErrorHostFunction: remaining recovered host errors.
//
// nil maps to CallErrorNone. Classification is also usable when the feature is
// disabled; reentrancy-specific categories simply never occur.
func ClassifyCallError(err error) CallErrorKind {
	if err == nil {
		return CallErrorNone
	}

	var policyErr *ReentrancyError
	if errors.As(err, &policyErr) {
		return CallErrorPolicyRejected
	}

	var exitErr *sys.ExitError
	if errors.As(err, &exitErr) {
		switch exitErr.ExitCode() {
		case sys.ExitCodeContextCanceled, sys.ExitCodeDeadlineExceeded:
			return CallErrorContextCanceled
		default:
			return CallErrorModuleExited
		}
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return CallErrorContextCanceled
	}

	for _, trap := range trapSentinels {
		if errors.Is(err, trap) {
			return CallErrorGuestTrap
		}
	}
	return CallErrorHostFunction
}

// trapSentinels is the full set of guest trap errors engines panic with. It
// stays in evaluation order independent from error wrapping depth.
var trapSentinels = []error{
	wasmruntime.ErrRuntimeStackOverflow,
	wasmruntime.ErrRuntimeInvalidConversionToInteger,
	wasmruntime.ErrRuntimeIntegerOverflow,
	wasmruntime.ErrRuntimeIntegerDivideByZero,
	wasmruntime.ErrRuntimeUnreachable,
	wasmruntime.ErrRuntimeOutOfBoundsMemoryAccess,
	wasmruntime.ErrRuntimeInvalidTableAccess,
	wasmruntime.ErrRuntimeIndirectCallTypeMismatch,
	wasmruntime.ErrRuntimeUnalignedAtomic,
	wasmruntime.ErrRuntimeExpectedSharedMemory,
	wasmruntime.ErrRuntimeTooManyWaiters,
	wasmruntime.ErrRuntimeUncaughtException,
	wasmruntime.ErrRuntimeNullReference,
}
