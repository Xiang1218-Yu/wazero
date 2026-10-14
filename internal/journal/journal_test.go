package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero/internal/wasm"
	"github.com/tetratelabs/wazero/sys"
)

func sampleHeader() Header {
	return Header{
		WazeroVersion: "test",
		Engine:        "interpreter",
		Features:      1,
		ModuleName:    "guest",
		FunctionName:  "guest.run",
		Imports: []ImportSig{
			{Kind: externFunc, Module: "env", Name: "a", Params: []byte{0x7f}, Results: []byte{0x7f}},
		},
		Params: []uint64{42},
	}
}

func sampleEnd() EndEvent {
	return EndEvent{Status: StatusCompleted, Results: []uint64{7}, Pages: 1}
}

func TestRecording_Roundtrip(t *testing.T) {
	root1 := &HostEvent{
		Module: "env", Name: "a",
		Params: []uint64{1}, Results: []uint64{2},
		PrePages: 1, PostPages: 1,
		Patches: []MemoryPatch{{Page: 0, Data: []byte("hello")}},
		Children: []*HostEvent{{
			Module: "env", Name: "b", Params: []uint64{9}, Results: nil,
			PanicClass: panicExit, PanicValue: 42, PanicMessage: "exit",
		}},
	}
	rec := sealSample([]*HostEvent{root1}, sampleEnd())
	if err := rec.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	raw, err := rec.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := UnmarshalRecording(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.EventCount() != 1 || got.Status() != StatusCompleted {
		t.Fatalf("unexpected record: count=%d status=%s", got.EventCount(), got.Status())
	}
	g0 := got.RootEvents()[0]
	if g0.Module != "env" || g0.Name != "a" || g0.Children[0].PanicValue != 42 {
		t.Fatalf("event tree mismatch: %+v", g0)
	}
	if string(g0.Patches[0].Data) != "hello" {
		t.Fatalf("patch mismatch")
	}
	// MarshalBinary must return an independent copy.
	raw2, _ := rec.MarshalBinary()
	raw2[len(raw2)-1] ^= 0xff
	if err := rec.Verify(); err != nil {
		t.Fatalf("record must be immutable: %v", err)
	}
}

func TestRecording_IntegrityAndTruncation(t *testing.T) {
	rec := sealSample(nil, sampleEnd())
	raw, _ := rec.MarshalBinary()

	t.Run("tamper", func(t *testing.T) {
		bad := bytes.Clone(raw)
		bad[40] ^= 0xff // flip a header payload byte; structure stays intact
		if _, err := UnmarshalRecording(bad); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("want ErrIntegrity, got %v", err)
		}
	})
	t.Run("cut trailer", func(t *testing.T) {
		// Remove the trailer plus part of the terminal frame.
		if _, err := UnmarshalRecording(raw[:len(raw)-40]); !errors.Is(err, ErrTruncated) {
			t.Fatalf("want ErrTruncated, got %v", err)
		}
	})
	t.Run("cut before end", func(t *testing.T) {
		// Drop the end frame and trailer.
		if _, err := UnmarshalRecording(raw[:len(magic)+2]); !errors.Is(err, ErrTruncated) {
			t.Fatalf("want ErrTruncated, got %v", err)
		}
	})
	t.Run("bad magic", func(t *testing.T) {
		bad := bytes.Clone(raw)
		bad[0] = 'X'
		if _, err := UnmarshalRecording(bad); !errors.Is(err, ErrFormat) {
			t.Fatalf("want ErrFormat, got %v", err)
		}
	})
	t.Run("bad version", func(t *testing.T) {
		// A future producer writes a new version with a correct checksum.
		bad := bytes.Clone(raw)
		binary.LittleEndian.PutUint16(bad[len(magic):], FormatVersion+99)
		sum := sha256.Sum256(bad[:len(bad)-32])
		copy(bad[len(bad)-32:], sum[:])
		if _, err := UnmarshalRecording(bad); !errors.Is(err, ErrVersion) {
			t.Fatalf("want ErrVersion, got %v", err)
		}
	})
}

func TestRecording_Bounds_Events(t *testing.T) {
	o := Options{MaxEvents: 1, FailurePolicy: FailurePolicyAbort}
	s := NewRecordSession(sampleHeader(), o)

	ev := s.enterRecord("env", "a", []uint64{1}, nil, 0)
	s.exitRecord(ev)

	func() {
		defer func() {
			if r := recover(); !errors.Is(asErr(r), errRecordingLimit) {
				t.Fatalf("want errRecordingLimit panic, got %v", r)
			}
		}()
		ev2 := s.enterRecord("env", "b", nil, nil, 0)
		s.exitRecord(ev2)
	}()
	if !s.Truncated() {
		t.Fatal("session must be marked truncated")
	}
	end := sampleEnd()
	rec, err := s.Seal(EndEvent{Status: StatusCompleted})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status() != StatusTruncated {
		t.Fatalf("want truncated status, got %s", rec.Status())
	}
	_ = end
}

func TestRecording_Bounds_Bytes_Continue(t *testing.T) {
	o := Options{MaxBytes: 1, FailurePolicy: FailurePolicyContinue}
	s := NewRecordSession(sampleHeader(), o)
	ev := s.enterRecord("env", "a", []uint64{1, 2, 3}, nil, 0)
	ev.Results = []uint64{9}
	s.exitRecord(ev)
	if !s.Truncated() || !s.muted {
		t.Fatal("want muted truncated session")
	}
	// Further interactions pass through without being recorded.
	ev2 := s.enterRecord("env", "b", nil, nil, 0)
	s.exitRecord(ev2)
	rec, _ := s.Seal(EndEvent{Status: StatusCompleted})
	if rec.Status() != StatusTruncated {
		t.Fatalf("want truncated, got %s", rec.Status())
	}
	if err := verifyRaw(rec.raw); err != nil {
		t.Fatalf("truncated record should still pass integrity: %v", err)
	}
	if _, err := NewReplaySession(rec, nil); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated records cannot be replayed: %v", err)
	}
}

func TestReplay_Divergence(t *testing.T) {
	ev := &HostEvent{Module: "env", Name: "a", Params: []uint64{1}, Results: []uint64{2}, PostPages: 0}
	rec := sealSample([]*HostEvent{ev}, sampleEnd())

	t.Run("wrong function", func(t *testing.T) {
		s, _ := NewReplaySession(rec, nil)
		mustAbort(t, s, func() { s.enterReplay("env", "zzz", []uint64{1}) })
		if s.Diff().Field != "function" || s.Diff().Index != 0 {
			t.Fatalf("want function diff at 0, got %+v", s.Diff())
		}
	})
	t.Run("wrong params", func(t *testing.T) {
		s, _ := NewReplaySession(rec, nil)
		mustAbort(t, s, func() { s.enterReplay("env", "a", []uint64{2}) })
		if s.Diff().Field != "params" {
			t.Fatalf("want params diff, got %+v", s.Diff())
		}
	})
	t.Run("extra call", func(t *testing.T) {
		s, _ := NewReplaySession(rec, nil)
		got := s.enterReplay("env", "a", []uint64{1})
		s.exitReplay(got)
		mustAbort(t, s, func() { s.enterReplay("env", "a", []uint64{1}) })
		if !strings.Contains(s.Diff().Error(), "unexpected host call") {
			t.Fatalf("want order diff, got %v", s.Diff())
		}
	})
	t.Run("unconsumed events", func(t *testing.T) {
		s, _ := NewReplaySession(rec, nil)
		err := s.FinishReplay()
		var d *DiffError
		if !errors.As(err, &d) || d.Field != "order" {
			t.Fatalf("want order diff, got %v", err)
		}
	})
}

func TestReplay_NestedChildrenAreSkipped(t *testing.T) {
	parent := &HostEvent{
		Module: "env", Name: "a", Params: []uint64{1}, Results: []uint64{2},
		Children: []*HostEvent{{Module: "env", Name: "nested"}},
	}
	rec := sealSample([]*HostEvent{parent}, sampleEnd())
	s, _ := NewReplaySession(rec, nil)
	got := s.enterReplay("env", "a", []uint64{1})
	if got.Children[0].Name != "nested" {
		t.Fatal("nested event must be present in the record")
	}
	s.exitReplay(got)
	if err := s.FinishReplay(); err != nil {
		t.Fatalf("nested events must not need driving: %v", err)
	}
}

func TestMemory_DiffAndApply(t *testing.T) {
	mem := wasm.NewMemoryInstance(&wasm.Memory{Min: 2, Cap: 4, Max: 4}, nil, nopEngine{})

	pages, hashes := snapshotMemory(mem)
	if pages != 2 {
		t.Fatalf("want 2 pages, got %d", pages)
	}
	// Modify a byte deep in page 1 and grow by one page then modify it.
	copy(mem.Buffer[65536+10:], []byte("X"))
	mem.Buffer = append(mem.Buffer, make([]byte, 65536)...)
	mem.Cap = 3
	copy(mem.Buffer[2*65536+7:], []byte("Y"))

	post, patches := diffMemory(mem, hashes, pages)
	if post != 3 {
		t.Fatalf("want 3 post pages, got %d", post)
	}
	if len(patches) != 2 {
		t.Fatalf("want 2 patches, got %d", len(patches))
	}

	// Fresh memory, replay patches (including growth).
	fresh := wasm.NewMemoryInstance(&wasm.Memory{Min: 2, Cap: 4, Max: 4}, nil, nopEngine{})
	ev := &HostEvent{PrePages: 2, PostPages: 3, Patches: patches}
	s, _ := NewReplaySession(mustSeal(t), nil)
	applyMemory(s, ev, fresh)
	if string(fresh.Buffer[65536+10:65536+11]) != "X" ||
		string(fresh.Buffer[2*65536+7:2*65536+8]) != "Y" {
		t.Fatal("replayed patches do not match")
	}
}

type nopEngine struct{ wasm.ModuleEngine }

func (nopEngine) MemoryGrown() {}

func TestPanicClassification(t *testing.T) {
	ev := &HostEvent{}
	classifyPanic(sys.NewExitError(7), ev)
	if ev.PanicClass != panicExit || ev.PanicValue != 7 {
		t.Fatalf("exit classify: %+v", ev)
	}
	if p, ok := reconstructPanic(ev).(*sys.ExitError); !ok || p.ExitCode() != 7 {
		t.Fatal("exit reconstruction failed")
	}

	ev = &HostEvent{}
	classifyPanic(errors.New("boom"), ev)
	if ev.PanicClass != panicOther || ev.PanicMessage != "boom" {
		t.Fatalf("error classify: %+v", ev)
	}
}

func mustAbort(t *testing.T, _ *Session, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); !errors.Is(asErr(r), errReplayAbort) {
			t.Fatalf("want errReplayAbort, got %v", r)
		}
	}()
	fn()
}

func mustSeal(t *testing.T) *Recording {
	t.Helper()
	rec := sealSample(nil, sampleEnd())
	return rec
}

func ptr(e EndEvent) *EndEvent { return &e }

func sealSample(roots []*HostEvent, end EndEvent) *Recording {
	h := sampleHeader()
	rec, err := seal(&h, roots, &end)
	if err != nil {
		panic(err)
	}
	return rec
}

func asErr(v interface{}) error {
	if v == nil {
		return nil
	}
	if e, ok := v.(error); ok {
		return e
	}
	return errors.New("non-error panic")
}
