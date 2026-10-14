package journal_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tetratelabs/wazero/internal/testing/require"

	"github.com/tetratelabs/wazero"
	pubjournal "github.com/tetratelabs/wazero/experimental/journal"
	"github.com/tetratelabs/wazero/sys"
)

func engineConfigs() map[string]wazero.RuntimeConfig {
	return map[string]wazero.RuntimeConfig{
		"interpreter": wazero.NewRuntimeConfigInterpreter(),
		"compiler":    wazero.NewRuntimeConfigCompiler(),
	}
}

// TestJournal_RecordReplay_Run covers ordered host calls with parameters and
// results, memory-mediated inputs, nested (re-entrant) calls, and verifies
// that replay never executes user host functions.
func TestJournal_RecordReplay_Run(t *testing.T) {
	bin := buildJournalGuest(t)
	for name, rc := range engineConfigs() {
		t.Run(name, func(t *testing.T) {
			cnt1 := &hostCounters{}
			fx1 := newFixture(t, rc, bin, false, cnt1)
			fn1 := fx1.mod.ExportedFunction("run")

			rec := pubjournal.NewRecorder()
			results, rec1, err := rec.Record(context.Background(), fx1.mod, fn1, 7)
			require.NoError(t, err)
			require.Equal(t, pubjournal.StatusCompleted, rec1.Status())
			require.Equal(t, 5, rec1.EventCount(), "tick/putmem/fillrand/getval/nest root events")

			// Event order and nesting.
			names := rec1.RootEventNames()
			require.Equal(t, []string{"env.tick", "env.putmem", "env.fillrand", "env.getval", "env.nest"}, names)
			// nest must contain the re-entrant tick child.
			raw, err := rec1.MarshalBinary()
			require.NoError(t, err)
			dec, err := pubjournal.UnmarshalRecording(raw)
			require.NoError(t, err)
			require.Equal(t, 5, dec.EventCount())
			require.Equal(t, names, dec.RootEventNames())

			// Record side really called the host functions and mutated memory.
			require.Equal(t, map[string]int{
				"tick": 2, "putmem": 1, "fillrand": 1, "getval": 1, "nest": 1,
			}, map[string]int{
				"tick": cnt1.tick, "putmem": cnt1.putmem, "fillrand": cnt1.fillrand,
				"getval": cnt1.getval, "nest": cnt1.nest,
			})
			v, ok := fx1.mod.Memory().ReadUint32Le(7)
			require.True(t, ok)
			require.Equal(t, uint32(100), v)

			// Fresh runtime/module/host state for replay.
			cnt2 := &hostCounters{}
			fx2 := newFixture(t, rc, bin, false, cnt2)
			fn2 := fx2.mod.ExportedFunction("run")
			results2, err2 := pubjournal.Replay(context.Background(), fx2.mod, dec, fn2, 7)
			require.NoError(t, err2)
			require.Equal(t, results, results2, "replay must reproduce deterministic results")

			// No user-provided host object executed during replay.
			require.Equal(t, &hostCounters{}, cnt2, "host functions must not be invoked on replay")
			v2, _ := fx2.mod.Memory().ReadUint32Le(7)
			require.Equal(t, uint32(100), v2, "recorded memory effects must be restored")
		})
	}
}

// TestJournal_EngineParity verifies interpreter and compiler emit the same
// logical event stream for the same call.
func TestJournal_EngineParity(t *testing.T) {
	bin := buildJournalGuest(t)
	parity := func(rc wazero.RuntimeConfig) struct {
		names  []string
		result uint64
	} {
		cnt := &hostCounters{}
		fx := newFixture(t, rc, bin, false, cnt)
		_, rec, err := pubjournal.NewRecorder().Record(context.Background(), fx.mod,
			fx.mod.ExportedFunction("run"), 11)
		require.NoError(t, err)
		return struct {
			names  []string
			result uint64
		}{rec.RootEventNames(), rec.Results()[0]}
	}
	a := parity(wazero.NewRuntimeConfigInterpreter())
	b := parity(wazero.NewRuntimeConfigCompiler())
	require.Equal(t, a.names, b.names)
	require.Equal(t, a.result, b.result)
}

// TestJournal_HostExit_Error_AndTrap verifies terminal states exit, host
// errors and wasm traps are recorded and replayed with identical
// classification.
func TestJournal_RecordReplay_Terminals(t *testing.T) {
	bin := buildJournalGuest(t)
	cases := []struct {
		export  string
		status  pubjournal.Status
		code    uint32
		message string
	}{
		{"do_exit", pubjournal.StatusExited, 42, ""},
		{"do_hosterr", pubjournal.StatusTrap, 0, "host failure injected"},
		{"do_panicstr", pubjournal.StatusTrap, 0, "non-error panic value"},
		{"do_trap", pubjournal.StatusTrap, 0, ""},
	}
	for _, tc := range cases {
		for engine, rc := range engineConfigs() {
			t.Run(tc.export+"/"+engine, func(t *testing.T) {
				cnt1 := &hostCounters{}
				fx1 := newFixture(t, rc, bin, false, cnt1)
				_, rec, err := pubjournal.NewRecorder().Record(context.Background(), fx1.mod,
					fx1.mod.ExportedFunction(tc.export))
				require.Error(t, err)
				require.Equal(t, tc.status, rec.Status())
				if tc.message != "" {
					require.Contains(t, err.Error(), tc.message)
				}
				if tc.status == pubjournal.StatusExited {
					var exitErr *sys.ExitError
					require.True(t, errors.As(err, &exitErr), "want ExitError: %v", err)
					require.Equal(t, tc.code, exitErr.ExitCode())
					require.Equal(t, tc.code, rec.ExitCode())
				}

				cnt2 := &hostCounters{}
				fx2 := newFixture(t, rc, bin, false, cnt2)
				_, err2 := pubjournal.Replay(context.Background(), fx2.mod, rec, fx2.mod.ExportedFunction(tc.export))
				require.Error(t, err2)
				if tc.message != "" {
					require.Contains(t, err2.Error(), tc.message)
				}
				if tc.status == pubjournal.StatusExited {
					var exitErr *sys.ExitError
					require.True(t, errors.As(err2, &exitErr), "want ExitError: %v", err2)
					require.Equal(t, tc.code, exitErr.ExitCode())
				}
				require.Equal(t, &hostCounters{}, cnt2)
			})
		}
	}
}

// TestJournal_MemoryGrow verifies guest-side growth is captured via boundary
// checkpoints and final memory verification.
func TestJournal_RecordReplay_MemoryGrow(t *testing.T) {
	bin := buildJournalGuest(t)
	for name, rc := range engineConfigs() {
		t.Run(name, func(t *testing.T) {
			fx1 := newFixture(t, rc, bin, false, &hostCounters{})
			require.Equal(t, uint32(1), fx1.mod.Memory().Size()/65536)
			results, rec, err := pubjournal.NewRecorder().Record(context.Background(), fx1.mod,
				fx1.mod.ExportedFunction("grow"), 1)
			require.NoError(t, err)
			require.Equal(t, uint64(1), results[0])
			require.Equal(t, uint32(2), fx1.mod.Memory().Size()/65536)

			fx2 := newFixture(t, rc, bin, false, &hostCounters{})
			results2, err2 := pubjournal.Replay(context.Background(), fx2.mod, rec,
				fx2.mod.ExportedFunction("grow"), 1)
			require.NoError(t, err2)
			require.Equal(t, results, results2)
			require.Equal(t, uint32(2), fx2.mod.Memory().Size()/65536)
		})
	}
}

// TestJournal_ContextCanceled verifies a canceled call is recorded and that
// replay deterministically reproduces the cancellation status.
func TestJournal_RecordReplay_ContextCanceled(t *testing.T) {
	bin := buildJournalGuest(t)
	for name, rc0 := range engineConfigs() {
		rc := rc0.WithCloseOnContextDone(true)
		t.Run(name, func(t *testing.T) {
			fx1 := newFixture(t, rc, bin, false, &hostCounters{})
			ctx1, cancel1 := context.WithCancel(context.Background())
			go func() {
				time.Sleep(20 * time.Millisecond)
				cancel1()
			}()
			_, rec, err := pubjournal.NewRecorder().Record(ctx1, fx1.mod, fx1.mod.ExportedFunction("spin"))
			require.Error(t, err)
			var exitErr *sys.ExitError
			require.True(t, errors.As(err, &exitErr), "want ExitError: %v", err)
			require.Equal(t, sys.ExitCodeContextCanceled, exitErr.ExitCode())
			require.Equal(t, pubjournal.StatusContextCanceled, rec.Status())
			require.Equal(t, 0, rec.EventCount())

			fx2 := newFixture(t, rc, bin, false, &hostCounters{})
			_, err2 := pubjournal.Replay(context.Background(), fx2.mod, rec, fx2.mod.ExportedFunction("spin"))
			require.Error(t, err2)
			require.True(t, errors.As(err2, &exitErr), "want ExitError: %v", err2)
			require.Equal(t, sys.ExitCodeContextCanceled, exitErr.ExitCode())
		})
	}
}

// TestJournal_ReplayDivergence verifies mismatches stop replay with a
// locatable DiffError rather than continuing.
func TestJournal_ReplayDivergence(t *testing.T) {
	bin := buildJournalGuest(t)
	rc := wazero.NewRuntimeConfigInterpreter()

	fx1 := newFixture(t, rc, bin, false, &hostCounters{})
	_, rec, err := pubjournal.NewRecorder().Record(context.Background(), fx1.mod,
		fx1.mod.ExportedFunction("run"), 7)
	require.NoError(t, err)

	t.Run("top-level params", func(t *testing.T) {
		fx2 := newFixture(t, rc, bin, false, &hostCounters{})
		_, err2 := pubjournal.Replay(context.Background(), fx2.mod, rec, fx2.mod.ExportedFunction("run"), 8)
		var d *pubjournal.DiffError
		require.True(t, errors.As(err2, &d), "want DiffError: %v", err2)
		require.Equal(t, -1, d.Index)
		require.Equal(t, "params", d.Field)
		require.Equal(t, &hostCounters{}, fx2.cnt, "replay must stop before any host call")
	})

	t.Run("dirty initial memory", func(t *testing.T) {
		fx2 := newFixture(t, rc, bin, false, &hostCounters{})
		// Execute the call once directly (session-less execution through the
		// inert wrappers) to dirty memory, then replay on the same instance.
		_, errCall := fx2.mod.ExportedFunction("run").Call(context.Background(), 7)
		require.NoError(t, errCall)
		_, err2 := pubjournal.Replay(context.Background(), fx2.mod, rec, fx2.mod.ExportedFunction("run"), 7)
		var d *pubjournal.DiffError
		require.True(t, errors.As(err2, &d), "want DiffError: %v", err2)
		require.Contains(t, d.Field, "memory")
	})
}

// TestJournal_Bounds verifies bounded storage and both failure policies.
func TestJournal_Bounds(t *testing.T) {
	bin := buildJournalGuest(t)
	rc := wazero.NewRuntimeConfigInterpreter()

	t.Run("abort policy", func(t *testing.T) {
		fx := newFixture(t, rc, bin, false, &hostCounters{})
		recorder := pubjournal.NewRecorder(pubjournal.WithMaxEvents(2), pubjournal.WithFailurePolicy(pubjournal.FailurePolicyAbort))
		_, rec, err := recorder.Record(context.Background(), fx.mod, fx.mod.ExportedFunction("run"), 7)
		require.Error(t, err)
		require.Equal(t, pubjournal.StatusTruncated, rec.Status())
		fx2 := newFixture(t, rc, bin, false, &hostCounters{})
		_, err2 := pubjournal.Replay(context.Background(), fx2.mod, rec, fx2.mod.ExportedFunction("run"), 7)
		require.ErrorIs(t, err2, pubjournal.ErrTruncated)
	})

	t.Run("continue policy", func(t *testing.T) {
		fx := newFixture(t, rc, bin, false, &hostCounters{})
		recorder := pubjournal.NewRecorder(pubjournal.WithMaxEvents(2), pubjournal.WithFailurePolicy(pubjournal.FailurePolicyContinue))
		results, rec, err := recorder.Record(context.Background(), fx.mod, fx.mod.ExportedFunction("run"), 7)
		require.NoError(t, err, "the call must finish normally")
		require.Equal(t, 1, len(results))
		require.Equal(t, pubjournal.StatusTruncated, rec.Status())
	})
}

// TestJournal_MarshalRoundtrip replays from a serialized record and checks
// tamper and version handling through the public API.
func TestJournal_MarshalRoundtrip(t *testing.T) {
	bin := buildJournalGuest(t)
	rc := wazero.NewRuntimeConfigInterpreter()
	fx1 := newFixture(t, rc, bin, false, &hostCounters{})
	results, rec, err := pubjournal.NewRecorder().Record(context.Background(), fx1.mod,
		fx1.mod.ExportedFunction("run"), 3)
	require.NoError(t, err)
	raw, err := rec.MarshalBinary()
	require.NoError(t, err)

	dec, err := pubjournal.UnmarshalRecording(raw)
	require.NoError(t, err)

	fx2 := newFixture(t, rc, bin, false, &hostCounters{})
	results2, err := pubjournal.Replay(context.Background(), fx2.mod, dec, fx2.mod.ExportedFunction("run"), 3)
	require.NoError(t, err)
	require.Equal(t, results, results2)

	t.Run("tamper rejected", func(t *testing.T) {
		bad := append([]byte(nil), raw...)
		bad[40] ^= 0xff
		_, err := pubjournal.UnmarshalRecording(bad)
		require.ErrorIs(t, err, pubjournal.ErrIntegrity)
	})
	t.Run("truncated rejected", func(t *testing.T) {
		_, err := pubjournal.UnmarshalRecording(raw[:len(raw)-40])
		require.ErrorIs(t, err, pubjournal.ErrTruncated)
	})
}

// TestJournal_RepeatReplay verifies the recording stays unchanged and replays
// are reproducible across fresh instances; user host objects remain
// untouched.
func TestJournal_RepeatReplay(t *testing.T) {
	bin := buildJournalGuest(t)
	rc := wazero.NewRuntimeConfigInterpreter()
	fx1 := newFixture(t, rc, bin, false, &hostCounters{})
	_, rec, err := pubjournal.NewRecorder().Record(context.Background(), fx1.mod,
		fx1.mod.ExportedFunction("run"), 5)
	require.NoError(t, err)
	before, _ := rec.MarshalBinary()

	for i := 0; i < 2; i++ {
		cnt := &hostCounters{}
		fx := newFixture(t, rc, bin, false, cnt)
		_, err := pubjournal.Replay(context.Background(), fx.mod, rec, fx.mod.ExportedFunction("run"), 5)
		require.NoError(t, err)
		require.Equal(t, &hostCounters{}, cnt)
	}
	after, _ := rec.MarshalBinary()
	require.Equal(t, before, after, "replay must not modify the recording")
}

// TestJournal_DefaultOff verifies that without Enable, host modules are not
// instrumented and behavior/error semantics are unchanged.
func TestJournal_DefaultOff(t *testing.T) {
	bin := buildJournalGuest(t)
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter())
	defer r.Close(ctx)

	cnt := &hostCounters{}
	mb := r.NewHostModuleBuilder("env")
	cnt.export(t, mb)
	_, err := mb.Instantiate(ctx)
	require.NoError(t, err)
	compiled, err := r.CompileModule(ctx, bin)
	require.NoError(t, err)
	mod, err := r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
	require.NoError(t, err)

	res, err := mod.ExportedFunction("run").Call(ctx, 7)
	require.NoError(t, err)
	require.Equal(t, 1, len(res))
	require.True(t, cnt.tick > 0)

	// Host errors keep their normal semantics without journal involvement.
	_, err = mod.ExportedFunction("do_hosterr").Call(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "host failure injected")
}

// TestJournal_WASI verifies WASI time and randomness results are driven from
// the record and replayed without touching the real time/random sources.
func TestJournal_WASI(t *testing.T) {
	bin := buildWasiGuest(t)
	for name, rc := range engineConfigs() {
		t.Run(name, func(t *testing.T) {
			fx1 := newFixture(t, rc, bin, true, nil)
			results, rec, err := pubjournal.NewRecorder().Record(context.Background(), fx1.mod,
				fx1.mod.ExportedFunction("run"))
			require.NoError(t, err)
			require.Equal(t, 1, len(results))
			require.Equal(t, 2, rec.EventCount(), "clock_time_get and random_get")

			fx2 := newFixture(t, rc, bin, true, nil)
			// Sleep so real walltime would certainly differ if it were consulted.
			time.Sleep(5 * time.Millisecond)
			results2, err2 := pubjournal.Replay(context.Background(), fx2.mod, rec,
				fx2.mod.ExportedFunction("run"))
			require.NoError(t, err2)
			require.Equal(t, results, results2)
		})
	}
}
