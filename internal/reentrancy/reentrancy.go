// Package reentrancy implements the engine-independent host callback
// reentrancy control core: policy, feature gate and per-call-chain state.
//
// # Design notes
//
// A call chain models the Go-visible execution boundaries of a single
// api.Function.Call:
//
//   - A "guest segment" begins whenever Go enters guest execution, i.e. the
//     root api.Function.Call and every guest invocation a host function makes
//     through another api.Function.Call. Pure guest->guest calls (including
//     cross-module imports) stay inside the same segment and are not counted.
//   - A "host entry" is every transition from executing guest code to a host
//     (Go) function. Host entries bind the ongoing chain onto the context
//     passed to the host function and unbind it on return.
//
// The chain is carried exclusively by context.Context: each top-level guest
// invocation owns a private chain, so concurrent module instances on separate
// goroutines never share state. The package deliberately uses no goroutines,
// mutexes or global registries.
package reentrancy

import (
	"context"
	"errors"
	"fmt"
)

// Policy decides whether a new guest segment is admitted to a call chain.
//
// A zero Policy denies all reentry. When the feature is enabled without an
// explicit policy (see Control), the permissive default is used instead, see
// PermissivePolicy.
type Policy struct {
	// AllowSameModuleReentry permits a host callback to re-enter the same
	// module instance that is already active on the chain.
	AllowSameModuleReentry bool

	// AllowCrossModuleReentry permits a host callback to enter a different
	// module instance while a chain is active.
	AllowCrossModuleReentry bool

	// MaxReentryDepth bounds guest segment depth. The root segment is depth
	// 0, the first host-driven reentry is depth 1, and so on. Zero means
	// unlimited.
	MaxReentryDepth uint32

	// DetectCycles rejects reentry when the node identified by
	// (module instance, function index) is already active on the chain,
	// even if same-module reentry is otherwise allowed.
	DetectCycles bool
}

// PermissivePolicy is the default policy once the feature is enabled: every
// kind of reentry is allowed, depth is unlimited and cycles are not detected.
func PermissivePolicy() Policy {
	return Policy{
		AllowSameModuleReentry:  true,
		AllowCrossModuleReentry: true,
	}
}

// Control is the store-scoped, immutable feature gate and default policy.
type Control struct {
	enabled       bool
	defaultPolicy Policy
}

// NewControl creates a feature gate. When disabled, all boundary operations
// are no-ops and allocate nothing.
func NewControl(enabled bool, defaultPolicy Policy) Control {
	return Control{enabled: enabled, defaultPolicy: defaultPolicy}
}

// Enabled reports whether host callback reentrancy control is switched on.
func (c Control) Enabled() bool { return c.enabled }

// Default returns the runtime-wide fallback policy.
func (c Control) Default() Policy { return c.defaultPolicy }

// Reason explains why a new guest segment was rejected.
type Reason int

const (
	// ReasonSameModuleDenied: the target module instance is already active on
	// the chain and Policy.AllowSameModuleReentry is false.
	ReasonSameModuleDenied Reason = iota + 1

	// ReasonCrossModuleDenied: a chain is active, the target is a different
	// module instance and Policy.AllowCrossModuleReentry is false.
	ReasonCrossModuleDenied

	// ReasonMaxDepthExceeded: entering the segment would exceed
	// Policy.MaxReentryDepth.
	ReasonMaxDepthExceeded

	// ReasonCycleDetected: the (module instance, function) node is already
	// active on the chain and Policy.DetectCycles is true.
	ReasonCycleDetected
)

// String implements fmt.Stringer.
func (r Reason) String() string {
	switch r {
	case ReasonSameModuleDenied:
		return "same-module reentry"
	case ReasonCrossModuleDenied:
		return "cross-module reentry"
	case ReasonMaxDepthExceeded:
		return "max reentry depth"
	case ReasonCycleDetected:
		return "reentrancy cycle"
	default:
		return "unknown reentrancy violation"
	}
}

// PolicyError is returned (or propagated through panic) when a guest segment
// is rejected by the active reentrancy policy. It is never wrapped with the
// generic "recovered by wazero" text by engine recovery, so callers can
// errors.As it directly; it also remains discoverable when user code panics
// with it, because engine wrappers use %w.
type PolicyError struct {
	// Reason is the specific policy that rejected the segment.
	Reason Reason

	// ModuleName is the name of the target module instance (best effort).
	ModuleName string

	// EntryName is the debug name of the target function.
	EntryName string

	// Depth is the segment depth that was attempted.
	Depth int
}

// Error implements error.
func (e *PolicyError) Error() string {
	if e.Reason == ReasonCycleDetected {
		return fmt.Sprintf("reentrancy control rejected %s: module %q function %q is already active on the call chain (depth %d)",
			e.Reason, e.ModuleName, e.EntryName, e.Depth)
	}
	return fmt.Sprintf("reentrancy control rejected %s: target module %q entry %q (depth %d)",
		e.Reason, e.ModuleName, e.EntryName, e.Depth)
}

type (
	chainKey       struct{}
	entryPolicyKey struct{}
)

// guestFrame identifies one guest execution segment.
type guestFrame struct {
	// module is the identity of a *wasm.ModuleInstance. It is compared for
	// identity only and must never be dereferenced.
	module uintptr
	// fn is the module-wide function index of the segment entry.
	fn uint32
}

// hostFrame marks one guest->host transition. It is used for bookkeeping and
// diagnostics only; policies admit guest segments, not host entries.
type hostFrame struct {
	hostModule   uintptr
	hostFn       uint32
	callerModule uintptr
	callerFn     uint32
}

// chain is the per-top-level-call mutable state, carried by context.
//
// A chain value is used by exactly one logical call sequence (and therefore
// one goroutine at a time, in line with the documented non-goroutine-safety
// of api.Function.Call); it needs no synchronization.
type chain struct {
	guest []guestFrame
	host  []hostFrame
}

// suppressEntryPolicyContext hides a per-entry policy from downstream values,
// so an entry override only applies to the single Call it was attached to and
// never to nested callbacks reached through host functions.
type suppressEntryPolicyContext struct {
	context.Context
}

func (s suppressEntryPolicyContext) Value(key any) any {
	if key == (entryPolicyKey{}) {
		return nil
	}
	return s.Context.Value(key)
}

var _ context.Context = suppressEntryPolicyContext{}

// noopLeave is returned on no-op and rejection paths so callers can always
// defer the returned function without a nil check.
func noopLeave() {}

// WithEntryPolicy attaches a policy that replaces the effective policy for a
// single api.Function.Call (the "call entry" configuration scope). The
// override does not propagate to nested callbacks issued by host functions.
func WithEntryPolicy(ctx context.Context, p Policy) context.Context {
	policy := p // copy so later caller mutation cannot change the stored value
	return context.WithValue(ctx, entryPolicyKey{}, &policy)
}

// entryPolicyFromContext returns the per-entry override, if any.
func entryPolicyFromContext(ctx context.Context) (Policy, bool) {
	if p, ok := ctx.Value(entryPolicyKey{}).(*Policy); ok && p != nil {
		return *p, true
	}
	return Policy{}, false
}

// Depth returns the number of active guest segments visible from ctx.
//
// It is zero for a top-level guest invocation; inside a host function called
// by the root segment it is one, and increases for nested callbacks. It is
// always zero when the feature is disabled or ctx carries no chain.
func Depth(ctx context.Context) int {
	if ctx == nil {
		return 0
	}
	if ch, ok := ctx.Value(chainKey{}).(*chain); ok && ch != nil {
		return len(ch.guest)
	}
	return 0
}

// BeginGuestSegment is invoked by engines immediately before executing guest
// code for an api.Function.Call. It returns a context carrying the chain and
// a leave function that MUST be invoked (typically deferred) when the segment
// ends.
//
// When the feature is disabled this is a zero-allocation no-op. On rejection
// no frame is pushed, no guest instruction has executed and the returned leave
// is a no-op.
func BeginGuestSegment(
	ctx context.Context,
	ctrl Control,
	instancePolicy *Policy,
	moduleID uintptr,
	fnIndex uint32,
	moduleName, entryName string,
) (context.Context, func(), error) {
	if !ctrl.enabled {
		return ctx, noopLeave, nil
	}

	// Rejection must happen before new guest execution; a canceled context is
	// reported directly (the module is NOT closed by this feature).
	if err := ctx.Err(); err != nil {
		return ctx, noopLeave, err
	}

	root := false
	ch, _ := ctx.Value(chainKey{}).(*chain)
	if ch == nil {
		ch = &chain{}
		root = true
	}
	// Remember whether the entry carries a per-entry override: it must be
	// consumed for this segment but hidden from downstream host callbacks.
	_, hasEntryOverride := entryPolicyFromContext(ctx)

	depth := len(ch.guest)

	// Resolve effective policy: entry override > module instance > runtime.
	policy := ctrl.defaultPolicy
	if instancePolicy != nil {
		policy = *instancePolicy
	}
	if override, ok := entryPolicyFromContext(ctx); ok {
		policy = override
	}

	if depth > 0 {
		// Order is part of the documented semantics:
		// depth -> same-module -> cross-module -> cycle.
		if policy.MaxReentryDepth != 0 && uint32(depth) > policy.MaxReentryDepth {
			return ctx, noopLeave, &PolicyError{
				Reason: ReasonMaxDepthExceeded, ModuleName: moduleName,
				EntryName: entryName, Depth: depth,
			}
		}

		sameModule := false
		for i := range ch.guest {
			if ch.guest[i].module == moduleID {
				sameModule = true
				break
			}
		}
		if sameModule {
			if !policy.AllowSameModuleReentry {
				return ctx, noopLeave, &PolicyError{
					Reason: ReasonSameModuleDenied, ModuleName: moduleName,
					EntryName: entryName, Depth: depth,
				}
			}
		} else if !policy.AllowCrossModuleReentry {
			return ctx, noopLeave, &PolicyError{
				Reason: ReasonCrossModuleDenied, ModuleName: moduleName,
				EntryName: entryName, Depth: depth,
			}
		}

		if policy.DetectCycles {
			for i := range ch.guest {
				if ch.guest[i].module == moduleID && ch.guest[i].fn == fnIndex {
					return ctx, noopLeave, &PolicyError{
						Reason: ReasonCycleDetected, ModuleName: moduleName,
						EntryName: entryName, Depth: depth,
					}
				}
			}
		}
	}

	ch.guest = append(ch.guest, guestFrame{module: moduleID, fn: fnIndex})

	if root {
		ctx = context.WithValue(ctx, chainKey{}, ch)
	}
	// The entry override, if any, was consumed for this segment only; hide it
	// from nested callbacks issued through host functions.
	if hasEntryOverride {
		ctx = suppressEntryPolicyContext{Context: ctx}
	}

	leave := func() {
		ch.guest = ch.guest[:len(ch.guest)-1]
	}
	return ctx, leave, nil
}

// BindHostEntry is invoked by engines immediately before a host function body
// (and its listener) runs. It returns the context bound to the active call
// chain and a leave function that MUST be invoked when the host function
// returns or panics.
//
// When the feature is disabled, or Go calls a host export directly without an
// active guest chain, this is a no-op. A canceled context aborts with a panic
// carrying context.Canceled/DeadlineExceeded before any host side effect;
// engines convert that panic at their call boundary.
func BindHostEntry(
	ctx context.Context,
	ctrl Control,
	hostModuleID uintptr,
	hostFnIndex uint32,
	callerModuleID uintptr,
	callerFnIndex uint32,
) (context.Context, func()) {
	if !ctrl.enabled {
		return ctx, noopLeave
	}
	ch, _ := ctx.Value(chainKey{}).(*chain)
	if ch == nil {
		// Go invoking a host export directly is not a guest->host callback.
		return ctx, noopLeave
	}

	if err := ctx.Err(); err != nil {
		panic(err)
	}

	ch.host = append(ch.host, hostFrame{
		hostModule:   hostModuleID,
		hostFn:       hostFnIndex,
		callerModule: callerModuleID,
		callerFn:     callerFnIndex,
	})
	leave := func() {
		ch.host = ch.host[:len(ch.host)-1]
	}
	return ctx, leave
}

// AsDirectAbort classifies a recovered panic value that engines must propagate
// verbatim (without stack-trace wrapping): a *PolicyError, or context
// cancellation. It returns the policy error and/or the cancellation error;
// both are nil when the value is unrelated.
func AsDirectAbort(recovered any) (*PolicyError, error) {
	switch v := recovered.(type) {
	case *PolicyError:
		return v, nil
	case error:
		if errors.Is(v, context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(v, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
	}
	return nil, nil
}
