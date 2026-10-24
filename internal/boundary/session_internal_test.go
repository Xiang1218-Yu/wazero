package boundary

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// resignInternal recomputes the trailer whole-log digest after tampering.
func resignInternal(raw []byte, t *testing.T) []byte {
	t.Helper()
	out := append([]byte(nil), raw...)
	off := 0
	for {
		n := int(binary.LittleEndian.Uint32(out[off+1:]))
		next := off + 5 + n
		if next == len(out) {
			break
		}
		off = next
	}
	sum := sha256.Sum256(out[:off])
	copy(out[off+5+8:], sum[:])
	return out
}

func newTestPreface(t *testing.T) (*Session, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	o := Options{MemoryIntegrity: true}
	s := NewSession(ModeRecord, &buf, nil, o)
	err := s.OnGuestCompiled(Manifest{
		ModuleSHA: digestBytes([]byte("module")),
		Sigs: []Sig{{Import: true, Module: "env", Name: "f",
			Params: []byte{0x7f}, Results: []byte{0x7f}}},
	}, RuntimeFP{Engine: "interpreter", CoreFeatures: 42})
	if err != nil {
		t.Fatalf("OnGuestCompiled: %v", err)
	}
	if err := s.OnGuestInstantiated(ConfigFP{Name: "m", StartFunctions: []string{"_start"}}); err != nil {
		t.Fatalf("OnGuestInstantiated: %v", err)
	}
	return s, &buf
}

func TestLogRoundTrip(t *testing.T) {
	s, buf := newTestPreface(t)

	// Simulate one boundary with a host call and a clock read.
	s.mu.Lock()
	s.busy = true
	s.active.Store(true)
	s.depth = 1
	var enter encBuffer
	enter.str("m\x00f")
	enter.bytes([]byte{})
	enter.u32(0)
	enter.hash(digestWords(nil))
	s.emitEvent(evCallEnter, enter.b)
	s.parents = append(s.parents, s.seq-1)

	s.depth = 2
	var he encBuffer
	he.str("env")
	he.str("f")
	he.bytes([]byte{0x7f})
	he.bytes([]byte{0x7f})
	he.u32(1)
	he.hash(digestWords([]uint64{9}))
	s.emitEvent(evHostEnter, he.b)
	s.parents = append(s.parents, s.seq-1)

	var wt encBuffer
	wt.i64(123)
	wt.i32(4)
	s.emitEvent(evWall, wt.b)
	s.popHost()

	var hx encBuffer
	hx.u8(0)
	hx.str("")
	hx.words([]uint64{7})
	hx.hash(digestWords([]uint64{7}))
	hx.u32(0)
	hx.hash([32]byte{})
	s.emitEvent(evHostExit, hx.b)
	s.popHost()

	var cx encBuffer
	encodeCallExit(&cx, []uint64{7}, nil, nil)
	s.emitEvent(evCallExit, cx.b)
	s.busy = false
	s.active.Store(false)
	s.mu.Unlock()

	if err := s.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	rp, err := OpenReplay(buf.Bytes(), Options{})
	if err != nil {
		t.Fatalf("OpenReplay: %v", err)
	}
	if rp.Flags()&FlagMemoryIntegrity == 0 {
		t.Fatalf("memory integrity flag lost")
	}
}

func TestOpenReplayBadMagic(t *testing.T) {
	sp, buf := newTestPreface(t)
	requireNoErr(t, sp.Finalize())
	raw := append([]byte(nil), buf.Bytes()...)
	// Frame layout: frame type byte at 0, payload (starting with the 4 byte
	// magic) at offset 5. Corrupt the magic and re-sign the trailer so the
	// semantic header check (rather than transport integrity) is exercised.
	raw[5] = 'X'
	raw = resignInternal(raw, t)
	if _, err := OpenReplay(raw, Options{}); err == nil {
		t.Fatalf("expected bad magic error")
	} else if re := AsError(err); re == nil || re.Kind != KindFormatVersion {
		t.Fatalf("expected format version error, got %v", err)
	}

	// An unknown frame type byte is rejected before the header is read.
	badType := append([]byte(nil), buf.Bytes()...)
	badType[0] = 0x7F
	if _, err := OpenReplay(badType, Options{}); err == nil {
		t.Fatalf("expected unknown type error")
	} else if re := AsError(err); re == nil || re.Kind != KindUnknownEventType {
		t.Fatalf("expected unknown event type error, got %v", err)
	}
}

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenReplayTruncated(t *testing.T) {
	sp, buf := newTestPreface(t)
	requireNoErr(t, sp.Finalize())
	raw := buf.Bytes()
	for _, cut := range []int{3, 6, len(raw) - 2} {
		if _, err := OpenReplay(raw[:cut], Options{}); err == nil {
			t.Fatalf("cut=%d: expected truncation error", cut)
		} else if re := AsError(err); re == nil || re.Kind != KindLogTruncated {
			t.Fatalf("cut=%d: expected truncation, got %v", cut, err)
		}
	}
}

func TestReplayFinalizeRequiresFullConsumption(t *testing.T) {
	s, buf := newTestPreface(t)
	s.mu.Lock()
	s.emitEvent(evCallEnter, nil)
	s.mu.Unlock()
	if err := s.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	rp, err := OpenReplay(buf.Bytes(), Options{})
	if err != nil {
		t.Fatalf("OpenReplay: %v", err)
	}
	if err := rp.Finalize(); err == nil {
		t.Fatalf("expected unconsumed event error")
	} else if re := AsError(err); re == nil || re.Kind != KindCallOrder {
		t.Fatalf("expected call order error, got %v", err)
	}
}

func TestSessionRejectsBusyBoundary(t *testing.T) {
	s, _ := newTestPreface(t)
	s.mu.Lock()
	s.busy = true
	err := s.beginBoundary("m\x00f", nil, 0, nil, digestWords(nil))
	s.busy = false
	s.mu.Unlock()
	if re := AsError(err); re == nil || re.Kind != KindState {
		t.Fatalf("expected busy session state error, got %v", err)
	}
}
