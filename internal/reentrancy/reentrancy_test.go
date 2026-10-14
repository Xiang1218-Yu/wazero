package reentrancy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"unsafe"
)

func testModuleIDs(n int) []uintptr {
	holders := make([]byte, n)
	ids := make([]uintptr, n)
	for i := range holders {
		ids[i] = uintptr(unsafe.Pointer(&holders[i]))
	}
	return ids
}

func TestDisabledControlIsNoop(t *testing.T) {
	ids := testModuleIDs(2)
	ctx := context.Background()

	allocs := testing.AllocsPerRun(100, func() {
		_, leave, err := BeginGuestSegment(ctx, NewControl(false, Policy{}), nil, ids[0], 0, "m", "m.f")
		if err != nil {
			t.Fatalf("disabled begin must not err: %v", err)
		}
		leave()
		hctx, hleave := BindHostEntry(ctx, NewControl(false, Policy{}), ids[1], 0, ids[0], 0)
		if hctx != ctx {
			t.Fatal("disabled host bind must return the same context")
		}
		hleave()
		if Depth(ctx) != 0 {
			t.Fatal("disabled chain depth must stay zero")
		}
	})
	if allocs != 0 {
		t.Fatalf("disabled path must allocate nothing, got %v", allocs)
	}
}

func TestPolicyMatrix(t *testing.T) {
	ids := testModuleIDs(3)
	modA, modB, modC := ids[0], ids[1], ids[2]

	type tc struct {
		name       string
		policy     Policy
		chain      []guestFrame // existing guest segments
		target     uintptr
		fn         uint32
		wantReason Reason // 0 = admitted
	}
	cases := []tc{
		{
			name:   "root always admitted",
			policy: Policy{}, // zero: deny all reentry, but root is not reentry
			target: modA, fn: 0,
		},
		{
			name:   "permissive same module same fn",
			policy: PermissivePolicy(),
			chain:  []guestFrame{{module: modA, fn: 0}},
			target: modA, fn: 0,
		},
		{
			name:   "deny same module",
			policy: Policy{AllowSameModuleReentry: false, AllowCrossModuleReentry: true},
			chain:  []guestFrame{{module: modA, fn: 0}},
			target: modA, fn: 1,
			wantReason: ReasonSameModuleDenied,
		},
		{
			name:   "allow same module different fn",
			policy: Policy{AllowSameModuleReentry: true, AllowCrossModuleReentry: false},
			chain:  []guestFrame{{module: modA, fn: 0}},
			target: modA, fn: 1,
		},
		{
			name:   "deny cross module",
			policy: Policy{AllowSameModuleReentry: true, AllowCrossModuleReentry: false},
			chain:  []guestFrame{{module: modA, fn: 0}},
			target: modB, fn: 0,
			wantReason: ReasonCrossModuleDenied,
		},
		{
			name:   "allow cross module",
			policy: Policy{AllowSameModuleReentry: false, AllowCrossModuleReentry: true},
			chain:  []guestFrame{{module: modA, fn: 0}},
			target: modB, fn: 0,
		},
		{
			name:   "same compiled module different instance is cross",
			policy: Policy{AllowSameModuleReentry: true, AllowCrossModuleReentry: false},
			chain:  []guestFrame{{module: modA, fn: 0}},
			target: modC, fn: 0,
			wantReason: ReasonCrossModuleDenied,
		},
		{
			name:   "depth 1 admits depth 1 rejects depth 2",
			policy: Policy{AllowSameModuleReentry: true, AllowCrossModuleReentry: true, MaxReentryDepth: 1},
			chain:  []guestFrame{{module: modA, fn: 0}, {module: modB, fn: 0}},
			target: modC, fn: 0,
			wantReason: ReasonMaxDepthExceeded,
		},
		{
			name:   "depth 1 admits single reentry",
			policy: Policy{AllowSameModuleReentry: true, AllowCrossModuleReentry: true, MaxReentryDepth: 1},
			chain:  []guestFrame{{module: modA, fn: 0}},
			target: modB, fn: 0,
		},
		{
			name:   "cycle same fn rejected",
			policy: Policy{AllowSameModuleReentry: true, AllowCrossModuleReentry: true, DetectCycles: true},
			chain:  []guestFrame{{module: modA, fn: 7}, {module: modB, fn: 2}},
			target: modA, fn: 7,
			wantReason: ReasonCycleDetected,
		},
		{
			name:   "same module different fn is not a cycle",
			policy: Policy{AllowSameModuleReentry: true, AllowCrossModuleReentry: true, DetectCycles: true},
			chain:  []guestFrame{{module: modA, fn: 7}},
			target: modA, fn: 8,
		},
		{
			name:   "same-module denial takes documented precedence over cycle",
			policy: Policy{AllowSameModuleReentry: false, AllowCrossModuleReentry: true, DetectCycles: true},
			chain:  []guestFrame{{module: modA, fn: 7}},
			target: modA, fn: 7,
			wantReason: ReasonSameModuleDenied,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ch := &chain{guest: append([]guestFrame(nil), c.chain...)}
			ctx := context.WithValue(context.Background(), chainKey{}, ch)
			_, _, err := BeginGuestSegment(ctx, NewControl(true, c.policy), nil,
				c.target, c.fn, "target", "target.fn")
			if c.wantReason == 0 {
				if err != nil {
					t.Fatalf("expected admission, got %v", err)
				}
			} else {
				var pe *PolicyError
				if !errors.As(err, &pe) {
					t.Fatalf("expected *PolicyError, got %T: %v", err, err)
				}
				if pe.Reason != c.wantReason {
					t.Fatalf("want reason %v, got %v", c.wantReason, pe.Reason)
				}
				if pe.Depth != len(c.chain) {
					t.Fatalf("error depth = %d, want %d", pe.Depth, len(c.chain))
				}
			}
		})
	}
}

func TestDepthZeroMeansUnlimited(t *testing.T) {
	ids := testModuleIDs(64)
	ctrl := NewControl(true, PermissivePolicy())
	ctx, leave, err := BeginGuestSegment(context.Background(), ctrl, nil, ids[0], 0, "m0", "f")
	if err != nil {
		t.Fatal(err)
	}
	defer leave()
	for i := 1; i < len(ids); i++ {
		var leave2 func()
		ctx, leave2, err = BeginGuestSegment(ctx, ctrl, nil, ids[i], 0, fmt.Sprintf("m%d", i), "f")
		if err != nil {
			t.Fatalf("depth %d unexpectedly rejected: %v", i, err)
		}
		defer leave2()
		if got := Depth(ctx); got != i+1 {
			t.Fatalf("depth = %d, want %d", got, i+1)
		}
	}
}

func TestHostBindAndLeaveBalance(t *testing.T) {
	ids := testModuleIDs(2)
	ctrl := NewControl(true, PermissivePolicy())

	ctx, leaveRoot, err := BeginGuestSegment(context.Background(), ctrl, nil, ids[0], 0, "A", "A.f")
	if err != nil {
		t.Fatal(err)
	}
	if Depth(ctx) != 1 {
		t.Fatalf("root segment depth = %d, want 1", Depth(ctx))
	}

	// Two sequential host callbacks must not accumulate host frames.
	for i := 0; i < 2; i++ {
		hctx, hleave := BindHostEntry(ctx, ctrl, ids[1], uint32(i), ids[0], 0)
		if Depth(hctx) != 1 {
			t.Fatalf("host callback depth = %d, want 1", Depth(hctx))
		}
		hleave()
	}

	// Nested host->guest segment increases depth and unwinds cleanly.
	hctx, hleave := BindHostEntry(ctx, ctrl, ids[1], 3, ids[0], 0)
	ctx2, leaveSeg, err := BeginGuestSegment(hctx, ctrl, nil, ids[1], 4, "B", "B.g")
	if err != nil {
		t.Fatal(err)
	}
	if Depth(ctx2) != 2 {
		t.Fatalf("nested segment depth = %d, want 2", Depth(ctx2))
	}
	leaveSeg()
	hleave()
	leaveRoot()

	if Depth(context.WithValue(context.Background(), chainKey{}, &chain{})) != 0 {
		t.Fatal("empty chain must report zero depth")
	}
}

func TestHostBindPanicUnwindsChain(t *testing.T) {
	ids := testModuleIDs(2)
	ctrl := NewControl(true, PermissivePolicy())
	ctx, leaveRoot, _ := BeginGuestSegment(context.Background(), ctrl, nil, ids[0], 0, "A", "A.f")
	hctx, hleave := BindHostEntry(ctx, ctrl, ids[1], 0, ids[0], 0)
	ctx2, leaveSeg, _ := BeginGuestSegment(hctx, ctrl, nil, ids[1], 0, "B", "B.f")

	chain := ctx2.Value(chainKey{}).(*chain)
	func() {
		defer func() {
			_ = recover()
			// Defers run in LIFO order, unwinding exactly as the engines do
			// when a panic propagates through guest frames.
		}()
		defer leaveRoot()
		defer hleave()
		defer leaveSeg()
		panic("host body panicked")
	}()

	if len(chain.guest) != 0 || len(chain.host) != 0 {
		t.Fatalf("chain not drained after panic unwinding: %+v", chain)
	}
}

func TestEmptyChainReusedBehavesAsRoot(t *testing.T) {
	ids := testModuleIDs(1)
	ctrl := NewControl(true, Policy{AllowCrossModuleReentry: false})

	ctx1, leave1, err := BeginGuestSegment(context.Background(), ctrl, nil, ids[0], 0, "A", "A.f")
	if err != nil {
		t.Fatal(err)
	}
	leave1()

	// Same chain-bearing ctx after complete unwind admits a new root even
	// though the policy would deny cross-module reentry.
	_, leave2, err := BeginGuestSegment(ctx1, ctrl, nil, ids[0], 1, "A", "A.g")
	if err != nil {
		t.Fatalf("fresh root on drained chain must be admitted, got %v", err)
	}
	leave2()
}

func TestCancellation(t *testing.T) {
	ids := testModuleIDs(2)
	ctrl := NewControl(true, PermissivePolicy())

	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := BeginGuestSegment(cctx, ctrl, nil, ids[0], 0, "A", "f"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled at guest entry, got %v", err)
	}

	ctx, leave, _ := BeginGuestSegment(context.Background(), ctrl, nil, ids[0], 0, "A", "f")
	defer leave()
	func() {
		defer func() {
			r := recover()
			if pe, ce := AsDirectAbort(r); pe != nil || ce != context.Canceled {
				t.Fatalf("want direct-abort context.Canceled, got pe=%v ce=%v", pe, ce)
			}
		}()
		cctx2, cancel2 := context.WithCancel(ctx)
		cancel2()
		_, hleave := BindHostEntry(cctx2, ctrl, ids[1], 0, ids[0], 0)
		hleave()
		t.Fatal("host bind must panic on canceled context")
	}()

	// DeadlineExceeded is recognized too.
	if pe, ce := AsDirectAbort(context.DeadlineExceeded); pe != nil || ce != context.DeadlineExceeded {
		t.Fatalf("want deadline abort, got %v %v", pe, ce)
	}
	if pe, ce := AsDirectAbort(&PolicyError{Reason: ReasonCycleDetected}); pe == nil || ce != nil {
		t.Fatalf("want policy error direct abort, got %v %v", pe, ce)
	}
	if pe, ce := AsDirectAbort("unrelated"); pe != nil || ce != nil {
		t.Fatalf("unrelated panic must not be a direct abort, got %v %v", pe, ce)
	}
}

func TestPolicyPrecedenceEntryOverInstanceOverDefault(t *testing.T) {
	ids := testModuleIDs(2)
	strict := Policy{AllowSameModuleReentry: false, AllowCrossModuleReentry: false}
	loose := PermissivePolicy()
	ctrl := NewControl(true, strict)

	// Default denies cross module.
	ctx, leave, _ := BeginGuestSegment(context.Background(), ctrl, nil, ids[0], 0, "A", "f")
	defer leave()
	if _, _, err := BeginGuestSegment(ctx, ctrl, nil, ids[1], 0, "B", "f"); err == nil {
		t.Fatal("default policy should deny cross module")
	}

	// Instance policy loosens.
	instance := loose
	if _, leave2, err := BeginGuestSegment(ctx, ctrl, &instance, ids[1], 0, "B", "f"); err != nil {
		t.Fatalf("instance policy should allow, got %v", err)
	} else {
		leave2()
	}

	// Entry policy overrides instance policy for a single call.
	entryStrict := WithEntryPolicy(ctx, strict)
	if _, _, err := BeginGuestSegment(entryStrict, ctrl, &loose, ids[1], 0, "B", "f"); err == nil {
		t.Fatal("entry policy must take precedence over instance policy")
	}
}

func TestEntryPolicyDoesNotPropagateToNestedCallbacks(t *testing.T) {
	ids := testModuleIDs(3)
	strict := Policy{AllowSameModuleReentry: false, AllowCrossModuleReentry: false}
	ctrl := NewControl(true, PermissivePolicy())

	// Root carries a strict one-shot override.
	ctx, leave, err := BeginGuestSegment(WithEntryPolicy(context.Background(), strict), ctrl, nil, ids[0], 0, "A", "f")
	if err != nil {
		t.Fatal(err)
	}
	defer leave()

	// The ctx handed to host functions (and used for nested calls) must not
	// carry the override: nested reentry follows the permissive default.
	if _, ok := entryPolicyFromContext(ctx); ok {
		t.Fatal("entry override leaked into downstream context")
	}
	hctx, hleave := BindHostEntry(ctx, ctrl, ids[1], 0, ids[0], 0)
	defer hleave()
	_, leaveNested, err := BeginGuestSegment(hctx, ctrl, nil, ids[2], 0, "C", "f")
	if err != nil {
		t.Fatalf("nested callback must use permissive default, got %v", err)
	}
	leaveNested()
}

func TestConcurrentChainsAreIndependent(t *testing.T) {
	ids := testModuleIDs(2)
	ctrl := NewControl(true, PermissivePolicy())

	var wg sync.WaitGroup
	for g := 0; g < 100; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, leave, err := BeginGuestSegment(context.Background(), ctrl, nil, ids[0], 0, "A", "f")
			if err != nil {
				t.Errorf("root: %v", err)
				return
			}
			for i := 0; i < 10; i++ {
				hctx, hleave := BindHostEntry(ctx, ctrl, ids[1], uint32(i), ids[0], 0)
				ctx2, leave2, err := BeginGuestSegment(hctx, ctrl, nil, ids[1], uint32(i), "B", "b")
				if err != nil {
					t.Errorf("nested: %v", err)
					return
				}
				if Depth(ctx2) != 2 {
					t.Errorf("depth = %d, want 2", Depth(ctx2))
				}
				leave2()
				hleave()
			}
			leave()
		}()
	}
	wg.Wait()
}
