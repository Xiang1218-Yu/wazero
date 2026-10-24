package boundary

import (
	"bytes"
)

// OpenReplay fully decodes and validates a log's framing, header, trailer
// event count and whole-log digest. Preface semantic validation (manifest,
// runtime, config) happens later through OnGuestCompiled/OnGuestInstantiated.
func OpenReplay(raw []byte, opts Options) (sOut *Session, err error) {
	defer func() {
		if r := recover(); r != nil {
			if re, ok := replayPanicValue(r); ok {
				err = re
			} else {
				panic(r)
			}
		}
	}()
	if len(raw) < 5+4 {
		return nil, fail(KindLogTruncated, StageHeader, -1, int64(len(raw)), "log too short to contain a header")
	}
	frames, trailer, logSHA, eventCount, err := readFrames(raw)
	if err != nil {
		return nil, err
	}
	if len(frames) == 0 || frames[0].typ != rtHeader {
		return nil, fail(KindFormatVersion, StageHeader, -1, 0, "log does not begin with a header record")
	}
	hd := decBuffer{b: frames[0].payload}
	magic := string(hd.b[0:4])
	if magic != LogMagic {
		return nil, fail(KindFormatVersion, StageHeader, -1, 0, "bad log magic %q", magic)
	}
	hd.offset = 4
	version := hd.u16()
	if version != LogVersion {
		return nil, fail(KindFormatVersion, StageHeader, -1, frames[0].offset,
			"unsupported log format version %d (supported %d)", version, LogVersion)
	}
	flags := hd.u16()
	_ = hd.u32() // reserved

	td := decBuffer{b: trailer}
	wantCount := td.u64()
	wantSHA := td.hash()
	if wantCount != eventCount {
		return nil, fail(KindTrailer, StageTrailer, int64(eventCount), -1,
			"trailer reports %d events but %d event frames are present", wantCount, eventCount)
	}
	if wantSHA != logSHA {
		return nil, fail(KindTrailer, StageTrailer, -1, -1,
			"whole-log digest does not match trailer; the execution log is corrupted or truncated")
	}

	opts.MemoryIntegrity = flags&FlagMemoryIntegrity != 0
	s := NewSession(ModeReplay, nil, frames, opts)
	s.flags = flags
	s.sawTrailer = true
	// The header is consumed from the frame stream; manifest/runtime/config
	// are consumed by OnGuestCompiled/OnGuestInstantiated.
	s.evPos = 1
	return s, nil
}

// Flags returns the option flags recorded in the log header.
func (s *Session) Flags() uint16 { return s.flags }

func sigsEqual(a, b []Sig) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Import != b[i].Import || a[i].Module != b[i].Module || a[i].Name != b[i].Name {
			return false
		}
		if !bytes.Equal(a[i].Params, b[i].Params) || !bytes.Equal(a[i].Results, b[i].Results) {
			return false
		}
	}
	return true
}

func configEqual(a, b ConfigFP) bool {
	if a.Name != b.Name || a.NameSet != b.NameSet ||
		a.WalltimeResolution != b.WalltimeResolution ||
		a.NanotimeResolution != b.NanotimeResolution ||
		a.HasCustomWalltime != b.HasCustomWalltime ||
		a.HasCustomNanotime != b.HasCustomNanotime ||
		a.HasCustomNanosleep != b.HasCustomNanosleep ||
		a.HasRandSource != b.HasRandSource ||
		a.HasStdin != b.HasStdin ||
		a.HasStdout != b.HasStdout ||
		a.HasStderr != b.HasStderr ||
		a.HasTCPListeners != b.HasTCPListeners {
		return false
	}
	if !equalStringList(a.StartFunctions, b.StartFunctions) ||
		!equalStringList(a.GuestPaths, b.GuestPaths) {
		return false
	}
	if len(a.Args) != len(b.Args) || len(a.Environ) != len(b.Environ) {
		return false
	}
	for i := range a.Args {
		if !bytes.Equal(a.Args[i], b.Args[i]) {
			return false
		}
	}
	for i := range a.Environ {
		if !bytes.Equal(a.Environ[i], b.Environ[i]) {
			return false
		}
	}
	return true
}

func equalStringList(a, b []string) bool {
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
