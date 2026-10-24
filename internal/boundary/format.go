package boundary

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
)

// LogMagic is the 4 byte preamble of every execution log.
const LogMagic = "WZRB"

// LogVersion is the current (and first) versioned log format.
const LogVersion uint16 = 1

// FlagMemoryIntegrity enables full guest-memory hashing after WASI host
// calls.
const FlagMemoryIntegrity uint16 = 1 << 0

// Framed record types. Values 1..9 are preface/trailer records, values
// 10..31 are per-event records whose payload begins with the common event
// header (seq, depth, parent).
const (
	rtHeader   byte = 1
	rtManifest byte = 2
	rtRuntime  byte = 3
	rtConfig   byte = 4
	rtTrailer  byte = 5

	evCallEnter byte = 10
	evCallExit  byte = 11
	evHostEnter byte = 12
	evHostExit  byte = 13
	evWall      byte = 14
	evNano      byte = 15
	evSleep     byte = 16
	evBytes     byte = 17
	evWrite     byte = 18
	evOpen      byte = 19
	evStat      byte = 20
	evFSOp      byte = 21
)

// Byte stream kinds for evBytes.
const (
	bytesRand  byte = 1
	bytesStdin byte = 2
	bytesFile  byte = 3
)

// Byte stream kinds for evWrite.
const (
	writeStdout byte = 4
	writeStderr byte = 5
	writeFile   byte = 6
)

// Stat scopes for evStat.
const (
	statFile  byte = 0
	statPath  byte = 1
	statLstat byte = 2
)

// Filesystem operations for evFSOp.
const (
	fsOpMkdir byte = iota + 1
	fsOpChmod
	fsOpRename
	fsOpRmdir
	fsOpUnlink
	fsOpLink
	fsOpSymlink
	fsOpReadlink
	fsOpUtimens
	fsOpFileTruncate
	fsOpFileReaddir
	fsOpFileClose
)

// Boundary error classes recorded in evCallExit / evHostExit.
const (
	classOK       byte = 0
	classExit     byte = 1 // sys.ExitError (module exit)
	classCanceled byte = 2 // context canceled / deadline exceeded
	classTrap     byte = 3 // guest trap
	classPanic    byte = 4 // host function panic
	classOther    byte = 5 // any other error
)

// ---------------------------------------------------------------------------
// stateless little-endian payload builders / readers
// ---------------------------------------------------------------------------

type encBuffer struct{ b []byte }

func (e *encBuffer) u8(v byte)    { e.b = append(e.b, v) }
func (e *encBuffer) u16(v uint16) { e.b = binary.LittleEndian.AppendUint16(e.b, v) }
func (e *encBuffer) u32(v uint32) { e.b = binary.LittleEndian.AppendUint32(e.b, v) }
func (e *encBuffer) u64(v uint64) { e.b = binary.LittleEndian.AppendUint64(e.b, v) }
func (e *encBuffer) i64(v int64)  { e.u64(uint64(v)) }
func (e *encBuffer) i32(v int32)  { e.u32(uint32(v)) }
func (e *encBuffer) boolean(v bool) {
	if v {
		e.u8(1)
	} else {
		e.u8(0)
	}
}
func (e *encBuffer) bytes(v []byte)  { e.u32(uint32(len(v))); e.b = append(e.b, v...) }
func (e *encBuffer) str(v string)    { e.u32(uint32(len(v))); e.b = append(e.b, v...) }
func (e *encBuffer) hash(v [32]byte) { e.b = append(e.b, v[:]...) }
func (e *encBuffer) words(vs []uint64) {
	e.u32(uint32(len(vs)))
	for _, v := range vs {
		e.u64(v)
	}
}

func (e *encBuffer) strList(vs []string) {
	e.u32(uint32(len(vs)))
	for _, v := range vs {
		e.str(v)
	}
}

func (e *encBuffer) byteSliceList(vs [][]byte) {
	e.u32(uint32(len(vs)))
	for _, v := range vs {
		e.bytes(v)
	}
}

type decBuffer struct {
	b      []byte
	offset int
}

func (d *decBuffer) u8() byte {
	if d.offset+1 > len(d.b) {
		d.trunc()
	}
	v := d.b[d.offset]
	d.offset++
	return v
}

func (d *decBuffer) u16() uint16 {
	if d.offset+2 > len(d.b) {
		d.trunc()
	}
	v := binary.LittleEndian.Uint16(d.b[d.offset:])
	d.offset += 2
	return v
}

func (d *decBuffer) u32() uint32 {
	if d.offset+4 > len(d.b) {
		d.trunc()
	}
	v := binary.LittleEndian.Uint32(d.b[d.offset:])
	d.offset += 4
	return v
}

func (d *decBuffer) u64() uint64 {
	if d.offset+8 > len(d.b) {
		d.trunc()
	}
	v := binary.LittleEndian.Uint64(d.b[d.offset:])
	d.offset += 8
	return v
}

func (d *decBuffer) i64() int64    { return int64(d.u64()) }
func (d *decBuffer) i32() int32    { return int32(d.u32()) }
func (d *decBuffer) boolean() bool { return d.u8() != 0 }

func (d *decBuffer) bytes() []byte {
	n := int(d.u32())
	if n < 0 || d.offset+n > len(d.b) {
		d.trunc()
	}
	v := d.b[d.offset : d.offset+n]
	d.offset += n
	return v
}

func (d *decBuffer) str() string {
	return string(d.bytes())
}

func (d *decBuffer) hash() [32]byte {
	var out [32]byte
	if d.offset+32 > len(d.b) {
		d.trunc()
	}
	copy(out[:], d.b[d.offset:d.offset+32])
	d.offset += 32
	return out
}

func (d *decBuffer) words() []uint64 {
	n := int(d.u32())
	if n < 0 || d.offset+n*8 > len(d.b) {
		d.trunc()
	}
	vs := make([]uint64, n)
	for i := range vs {
		vs[i] = d.u64()
	}
	return vs
}

func (d *decBuffer) strList() []string {
	n := int(d.u32())
	vs := make([]string, n)
	for i := range vs {
		vs[i] = d.str()
	}
	return vs
}

func (d *decBuffer) byteSliceList() [][]byte {
	n := int(d.u32())
	vs := make([][]byte, n)
	for i := range vs {
		vs[i] = d.bytes()
	}
	return vs
}

func (d *decBuffer) trunc() {
	panic(errTruncatedPayload)
}

var errTruncatedPayload = fail(KindLogTruncated, StageEvent, -1, -1, "record payload truncated")

// ---------------------------------------------------------------------------
// framing
// ---------------------------------------------------------------------------

// writeFrame writes a single length-prefixed frame while updating the
// running log hash.
func writeFrame(w io.Writer, logHash io.Writer, typ byte, payload []byte) error {
	var hdr [5]byte
	hdr[0] = typ
	binary.LittleEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	logHash.Write(hdr[:])
	if len(payload) != 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
		logHash.Write(payload)
	}
	return nil
}

type rawFrame struct {
	typ     byte
	payload []byte
	offset  int64 // byte offset of the frame within the log
}

// readFrames parses all frames up to (and including) the trailer. Any
// trailing bytes or partial frames are reported as truncation errors. It
// also returns the SHA-256 over every frame byte preceding the trailer and
// the number of event frames (preface frames excluded), which the trailer
// must match.
func readFrames(raw []byte) (frames []rawFrame, trailerPayload []byte, logSHA [32]byte, eventCount uint64, err error) {
	h := sha256.New()
	off := 0
	for {
		if off == len(raw) {
			err = fail(KindLogTruncated, StageTrailer, -1, -1, "log ends without a trailer")
			return
		}
		if off+5 > len(raw) {
			err = fail(KindLogTruncated, StageTrailer, -1, int64(off), "truncated frame header")
			return
		}
		start := off
		typ := raw[off]
		n := int(binary.LittleEndian.Uint32(raw[off+1:]))
		off += 5
		if off+n > len(raw) {
			err = fail(KindLogTruncated, StageEvent, -1, int64(start), "frame body truncated")
			return
		}
		payload := raw[off : off+n]
		off += n
		if typ == rtTrailer {
			// The trailer frame itself is not covered by the pre-trailer hash.
			if off != len(raw) {
				err = fail(KindTrailer, StageTrailer, -1, int64(off), "%d unexpected byte(s) after trailer", len(raw)-off)
				return
			}
			logSHA = [32]byte(h.Sum(nil))
			return frames, payload, logSHA, eventCount, nil
		}
		h.Write(raw[start:off]) // hash frames preceding the trailer only
		if !knownType(typ) {
			err = fail(KindUnknownEventType, stageForType(typ), -1, int64(start), "unknown record type 0x%02x", typ)
			return
		}
		if typ >= evCallEnter {
			eventCount++
		}
		frames = append(frames, rawFrame{typ: typ, payload: payload, offset: int64(start)})
	}
}

func knownType(typ byte) bool {
	switch typ {
	case rtHeader, rtManifest, rtRuntime, rtConfig,
		evCallEnter, evCallExit, evHostEnter, evHostExit,
		evWall, evNano, evSleep, evBytes, evWrite, evOpen, evStat, evFSOp:
		return true
	}
	return false
}

func stageForType(typ byte) string {
	switch typ {
	case rtHeader:
		return StageHeader
	case rtManifest:
		return StageManifest
	case rtRuntime:
		return StageRuntime
	case rtConfig:
		return StageConfig
	default:
		return StageEvent
	}
}

// digestWords returns the SHA-256 digest of the little-endian encoded words.
func digestWords(vs []uint64) [32]byte {
	h := sha256.New()
	var buf [8]byte
	for _, v := range vs {
		binary.LittleEndian.PutUint64(buf[:], v)
		h.Write(buf[:])
	}
	return [32]byte(h.Sum(nil))
}

// digestBytes returns the SHA-256 digest of the byte slice.
func digestBytes(vs ...[]byte) [32]byte {
	h := sha256.New()
	for _, v := range vs {
		h.Write(v)
	}
	return [32]byte(h.Sum(nil))
}
