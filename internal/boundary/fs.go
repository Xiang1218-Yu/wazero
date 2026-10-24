package boundary

import (
	"io/fs"

	experimentalsys "github.com/tetratelabs/wazero/experimental/sys"
	topsys "github.com/tetratelabs/wazero/sys"
)

// WrapFSList wraps guest preopens so file reads, writes and filesystem
// queries participate in the execution log.
func (s *Session) WrapFSList(fss []experimentalsys.FS) []experimentalsys.FS {
	if len(fss) == 0 {
		return fss
	}
	out := make([]experimentalsys.FS, len(fss))
	for i, f := range fss {
		if f == nil {
			out[i] = f
			continue
		}
		out[i] = &boundaryFS{FS: f, s: s}
	}
	return out
}

func (s *Session) nextFileID() uint32 {
	s.fileSeq++
	return s.fileSeq
}

// ---------------------------------------------------------------------------
// open / stat / fs-op events
// ---------------------------------------------------------------------------

func (s *Session) openRecord(id uint32, path string, flag uint32, perm uint32, errno uint16) {
	var e encBuffer
	e.u32(id)
	e.str(path)
	e.u32(flag)
	e.u32(perm)
	e.u16(errno)
	s.emitEvent(evOpen, e.b)
}

func (s *Session) openExpect(path string, flag, perm uint32) (uint32, uint16) {
	if s.verr != nil {
		return 0, 0
	}
	d, _, _, err := s.expectEvent(evOpen)
	if err != nil {
		s.fatal(err)
		return 0, 0
	}
	id := d.u32()
	gotPath := d.str()
	gotFlag := d.u32()
	gotPerm := d.u32()
	errno := d.u16()
	if gotPath != path || gotFlag != flag || gotPerm != perm {
		s.fatal(fail(KindParamMismatch, StageEvent, int64(s.seq-1), -1,
			"file open changed: recorded path=%q flag=%#o perm=%#o, replay path=%q flag=%#o perm=%#o",
			gotPath, gotFlag, gotPerm, path, flag, perm))
		return id, errno
	}
	return id, errno
}

func statEncode(e *encBuffer, st topsys.Stat_t) {
	e.u64(st.Dev)
	e.u64(uint64(st.Ino))
	e.u32(uint32(st.Mode))
	e.u64(st.Nlink)
	e.i64(st.Size)
	e.i64(int64(st.Atim))
	e.i64(int64(st.Mtim))
	e.i64(int64(st.Ctim))
}

func statDecode(d *decBuffer) topsys.Stat_t {
	return topsys.Stat_t{
		Dev:   d.u64(),
		Ino:   topsys.Inode(d.u64()),
		Mode:  fs.FileMode(d.u32()),
		Nlink: d.u64(),
		Size:  d.i64(),
		Atim:  topsys.EpochNanos(d.i64()),
		Mtim:  topsys.EpochNanos(d.i64()),
		Ctim:  topsys.EpochNanos(d.i64()),
	}
}

func (s *Session) statRecord(scope byte, id uint32, path string, st topsys.Stat_t, errno uint16) {
	var e encBuffer
	e.u8(scope)
	e.u32(id)
	e.str(path)
	statEncode(&e, st)
	e.u16(errno)
	s.emitEvent(evStat, e.b)
}

func (s *Session) statExpect(scope byte, id uint32, path string) (topsys.Stat_t, uint16) {
	if s.verr != nil {
		return topsys.Stat_t{}, 0
	}
	d, _, _, err := s.expectEvent(evStat)
	if err != nil {
		s.fatal(err)
		return topsys.Stat_t{}, 0
	}
	gotScope := d.u8()
	gotID := d.u32()
	gotPath := d.str()
	st := statDecode(d)
	errno := d.u16()
	if gotScope != scope || gotID != id || gotPath != path {
		s.fatal(fail(KindParamMismatch, StageEvent, int64(s.seq-1), -1,
			"file query changed: recorded scope=%d id=%d path=%q, replay scope=%d id=%d path=%q",
			gotScope, gotID, gotPath, scope, id, path))
	}
	return st, errno
}

func (s *Session) fsOpRecord(op byte, args [][]byte, custom []byte, result string, errno uint16) {
	var e encBuffer
	e.u8(op)
	e.u32(uint32(len(args)))
	for _, a := range args {
		e.bytes(a)
	}
	e.bytes(custom)
	e.str(result)
	e.u16(errno)
	s.emitEvent(evFSOp, e.b)
}

// fsOpExpect verifies the next mutating/query fs operation and returns its
// recorded result. Mutating operations MUST NOT be applied to the underlying
// host filesystem on replay.
func (s *Session) fsOpExpect(op byte, args [][]byte) (custom []byte, result string, errno uint16) {
	if s.verr != nil {
		return nil, "", 0
	}
	d, _, _, err := s.expectEvent(evFSOp)
	if err != nil {
		s.fatal(err)
		return nil, "", 0
	}
	gotOp := d.u8()
	nArgs := int(d.u32())
	var gotArgs [][]byte
	for i := 0; i < nArgs; i++ {
		gotArgs = append(gotArgs, d.bytes())
	}
	custom = d.bytes()
	result = d.str()
	errno = d.u16()
	if gotOp != op || !bytesListsEqual(gotArgs, args) {
		s.fatal(fail(KindParamMismatch, StageEvent, int64(s.seq-1), -1,
			"filesystem operation changed: recorded op=%d args=%q, replay op=%d args=%q",
			gotOp, gotArgs, op, args))
	}
	return
}

func bytesListsEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if string(a[i]) != string(b[i]) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// FS decorator
// ---------------------------------------------------------------------------

type boundaryFS struct {
	experimentalsys.FS
	s *Session
}

func writeIntent(flag experimentalsys.Oflag) bool {
	return flag&3 != experimentalsys.O_RDONLY ||
		flag&(experimentalsys.O_CREAT|experimentalsys.O_TRUNC|experimentalsys.O_APPEND) != 0
}

func (f *boundaryFS) OpenFile(path string, flag experimentalsys.Oflag, perm fs.FileMode) (experimentalsys.File, experimentalsys.Errno) {
	id := f.s.nextFileID()
	active := f.s.active.Load()
	if f.s.mode == ModeRecord {
		file, errno := f.FS.OpenFile(path, flag, perm)
		if active {
			f.s.openRecord(id, path, uint32(flag), uint32(perm), uint16(errno))
		}
		if errno == 0 {
			return &liveFile{File: file, s: f.s, id: id, path: path}, 0
		}
		return nil, errno
	}

	var errno uint16
	if active {
		recordedID, gotErrno := f.s.openExpect(path, uint32(flag), uint32(perm))
		errno = gotErrno
		if recordedID != id {
			f.s.fatal(fail(KindCallOrder, StageEvent, int64(f.s.seq-1), -1,
				"file open order changed: recorded file id %d, replay assigned %d", recordedID, id))
		}
	}
	if errno != 0 {
		return nil, experimentalsys.Errno(errno)
	}
	if !active {
		// Initialization-time open (preopen directory): open read-only on
		// the host FS like in record mode.
		file, e := f.FS.OpenFile(path, flag, perm)
		if e != 0 {
			return nil, e
		}
		return &replayFile{File: file, s: f.s, id: id, path: path, closeUnder: true}, 0
	}
	if writeIntent(flag) {
		// Never create/truncate/write anything on the host filesystem.
		return &replayFile{File: experimentalsys.UnimplementedFile{}, s: f.s, id: id, path: path}, 0
	}
	file, e := f.FS.OpenFile(path, flag, perm)
	if e != 0 {
		f.s.fatal(fail(KindSideEffect, StageEvent, int64(f.s.seq-1), -1,
			"replay open of %q failed on the host filesystem: %v", path, e))
		return &replayFile{File: experimentalsys.UnimplementedFile{}, s: f.s, id: id, path: path}, 0
	}
	return &replayFile{File: file, s: f.s, id: id, path: path, closeUnder: true}, 0
}

func (f *boundaryFS) Stat(path string) (topsys.Stat_t, experimentalsys.Errno) {
	if !f.s.active.Load() {
		return f.FS.Stat(path)
	}
	if f.s.mode == ModeRecord {
		st, errno := f.FS.Stat(path)
		f.s.statRecord(statPath, 0, path, st, uint16(errno))
		return st, errno
	}
	st, errno := f.s.statExpect(statPath, 0, path)
	return st, experimentalsys.Errno(errno)
}

func (f *boundaryFS) Lstat(path string) (topsys.Stat_t, experimentalsys.Errno) {
	if !f.s.active.Load() {
		return f.FS.Lstat(path)
	}
	if f.s.mode == ModeRecord {
		st, errno := f.FS.Lstat(path)
		f.s.statRecord(statLstat, 0, path, st, uint16(errno))
		return st, errno
	}
	st, errno := f.s.statExpect(statLstat, 0, path)
	return st, experimentalsys.Errno(errno)
}

func (f *boundaryFS) mutatingOp(op byte, args [][]byte, run func() experimentalsys.Errno) experimentalsys.Errno {
	if !f.s.active.Load() {
		return run()
	}
	if f.s.mode == ModeRecord {
		errno := run()
		f.s.fsOpRecord(op, args, nil, "", uint16(errno))
		return errno
	}
	_, _, errno := f.s.fsOpExpect(op, args)
	return experimentalsys.Errno(errno)
}

func (f *boundaryFS) Mkdir(path string, perm fs.FileMode) experimentalsys.Errno {
	return f.mutatingOp(fsOpMkdir, [][]byte{[]byte(path), u32bytes(uint32(perm))},
		func() experimentalsys.Errno { return f.FS.Mkdir(path, perm) })
}

func (f *boundaryFS) Chmod(path string, perm fs.FileMode) experimentalsys.Errno {
	return f.mutatingOp(fsOpChmod, [][]byte{[]byte(path), u32bytes(uint32(perm))},
		func() experimentalsys.Errno { return f.FS.Chmod(path, perm) })
}

func (f *boundaryFS) Rename(from, to string) experimentalsys.Errno {
	return f.mutatingOp(fsOpRename, [][]byte{[]byte(from), []byte(to)},
		func() experimentalsys.Errno { return f.FS.Rename(from, to) })
}

func (f *boundaryFS) Rmdir(path string) experimentalsys.Errno {
	return f.mutatingOp(fsOpRmdir, [][]byte{[]byte(path)},
		func() experimentalsys.Errno { return f.FS.Rmdir(path) })
}

func (f *boundaryFS) Unlink(path string) experimentalsys.Errno {
	return f.mutatingOp(fsOpUnlink, [][]byte{[]byte(path)},
		func() experimentalsys.Errno { return f.FS.Unlink(path) })
}

func (f *boundaryFS) Link(oldPath, newPath string) experimentalsys.Errno {
	return f.mutatingOp(fsOpLink, [][]byte{[]byte(oldPath), []byte(newPath)},
		func() experimentalsys.Errno { return f.FS.Link(oldPath, newPath) })
}

func (f *boundaryFS) Symlink(oldPath, linkName string) experimentalsys.Errno {
	return f.mutatingOp(fsOpSymlink, [][]byte{[]byte(oldPath), []byte(linkName)},
		func() experimentalsys.Errno { return f.FS.Symlink(oldPath, linkName) })
}

func (f *boundaryFS) Readlink(path string) (string, experimentalsys.Errno) {
	if !f.s.active.Load() {
		return f.FS.Readlink(path)
	}
	if f.s.mode == ModeRecord {
		out, errno := f.FS.Readlink(path)
		f.s.fsOpRecord(fsOpReadlink, [][]byte{[]byte(path)}, nil, out, uint16(errno))
		return out, errno
	}
	_, out, errno := f.s.fsOpExpect(fsOpReadlink, [][]byte{[]byte(path)})
	return out, experimentalsys.Errno(errno)
}

func (f *boundaryFS) Utimens(path string, atim, mtim int64) experimentalsys.Errno {
	return f.mutatingOp(fsOpUtimens,
		[][]byte{[]byte(path), i64bytes(atim), i64bytes(mtim)},
		func() experimentalsys.Errno { return f.FS.Utimens(path, atim, mtim) })
}

// ---------------------------------------------------------------------------
// File decorators
// ---------------------------------------------------------------------------

type liveFile struct {
	experimentalsys.File
	s    *Session
	id   uint32
	path string
}

type replayFile struct {
	experimentalsys.File
	s          *Session
	id         uint32
	path       string
	closeUnder bool
}

func (fl *liveFile) Read(p []byte) (int, experimentalsys.Errno) {
	n, errno := fl.File.Read(p)
	if fl.s.active.Load() {
		fl.s.bytesRecord(bytesFile, fl.id, 0, len(p), append([]byte(nil), p[:n]...), uint16(errno), false)
	}
	return n, errno
}

func (fl *liveFile) Pread(p []byte, off int64) (int, experimentalsys.Errno) {
	n, errno := fl.File.Pread(p, off)
	if fl.s.active.Load() {
		fl.s.bytesRecord(bytesFile, fl.id, off, len(p), append([]byte(nil), p[:n]...), uint16(errno), false)
	}
	return n, errno
}

func (fl *liveFile) Write(p []byte) (int, experimentalsys.Errno) {
	n, errno := fl.File.Write(p)
	if fl.s.active.Load() {
		fl.s.writeRecord(writeFile, fl.id, 0, p, n, uint16(errno))
	}
	return n, errno
}

func (fl *liveFile) Pwrite(p []byte, off int64) (int, experimentalsys.Errno) {
	n, errno := fl.File.Pwrite(p, off)
	if fl.s.active.Load() {
		fl.s.writeRecord(writeFile, fl.id, off, p, n, uint16(errno))
	}
	return n, errno
}

func (fl *liveFile) Stat() (topsys.Stat_t, experimentalsys.Errno) {
	st, errno := fl.File.Stat()
	if fl.s.active.Load() {
		fl.s.statRecord(statFile, fl.id, fl.path, st, uint16(errno))
	}
	return st, errno
}

func (fl *liveFile) Truncate(size int64) experimentalsys.Errno {
	errno := fl.File.Truncate(size)
	if fl.s.active.Load() {
		fl.s.fsOpRecord(fsOpFileTruncate, [][]byte{i64bytes(size)}, nil, "", uint16(errno))
	}
	return errno
}

func (fl *liveFile) Close() experimentalsys.Errno {
	errno := fl.File.Close()
	if fl.s.active.Load() {
		fl.s.fsOpRecord(fsOpFileClose, nil, nil, "", uint16(errno))
	}
	return errno
}

func (fl *liveFile) Readdir(n int) ([]experimentalsys.Dirent, experimentalsys.Errno) {
	dirents, errno := fl.File.Readdir(n)
	if fl.s.active.Load() {
		fl.s.fsOpRecord(fsOpFileReaddir, nil, readdirCustom(n, dirents), "", uint16(errno))
	}
	return dirents, errno
}

func (fr *replayFile) Read(p []byte) (int, experimentalsys.Errno) {
	if !fr.s.active.Load() {
		return fr.File.Read(p)
	}
	data, errno, _ := fr.s.bytesExpect(bytesFile, fr.id, 0, len(p))
	if fr.s.verr != nil {
		return 0, experimentalsys.EIO
	}
	copy(p, data)
	return len(data), experimentalsys.Errno(errno)
}

func (fr *replayFile) Pread(p []byte, off int64) (int, experimentalsys.Errno) {
	if !fr.s.active.Load() {
		return fr.File.Pread(p, off)
	}
	data, errno, _ := fr.s.bytesExpect(bytesFile, fr.id, off, len(p))
	if fr.s.verr != nil {
		return 0, experimentalsys.EIO
	}
	copy(p, data)
	return len(data), experimentalsys.Errno(errno)
}

func (fr *replayFile) Write(p []byte) (int, experimentalsys.Errno) {
	if !fr.s.active.Load() {
		return len(p), 0
	}
	n, errno := fr.s.writeExpect(writeFile, fr.id, 0, p)
	return n, experimentalsys.Errno(errno)
}

func (fr *replayFile) Pwrite(p []byte, off int64) (int, experimentalsys.Errno) {
	if !fr.s.active.Load() {
		return len(p), 0
	}
	n, errno := fr.s.writeExpect(writeFile, fr.id, off, p)
	return n, experimentalsys.Errno(errno)
}

func (fr *replayFile) Stat() (topsys.Stat_t, experimentalsys.Errno) {
	if !fr.s.active.Load() {
		return fr.File.Stat()
	}
	st, errno := fr.s.statExpect(statFile, fr.id, fr.path)
	return st, experimentalsys.Errno(errno)
}

func (fr *replayFile) Truncate(size int64) experimentalsys.Errno {
	if !fr.s.active.Load() {
		return fr.File.Truncate(size)
	}
	_, _, errno := fr.s.fsOpExpect(fsOpFileTruncate, [][]byte{i64bytes(size)})
	return experimentalsys.Errno(errno)
}

func (fr *replayFile) Readdir(n int) ([]experimentalsys.Dirent, experimentalsys.Errno) {
	if !fr.s.active.Load() {
		return fr.File.Readdir(n)
	}
	custom, _, errno := fr.s.fsOpExpect(fsOpFileReaddir, nil)
	wantN, wantCount, wantDigest := parseReaddirCustom(custom)
	if wantN != n {
		fr.s.fatal(fail(KindParamMismatch, StageEvent, int64(fr.s.seq-1), -1,
			"readdir argument changed: recorded %d, replay %d", wantN, n))
	}
	dirents, e := fr.File.Readdir(n)
	if e != experimentalsys.Errno(errno) {
		fr.s.fatal(fail(KindResultMismatch, StageEvent, int64(fr.s.seq-1), -1,
			"readdir errno changed: recorded %d, replay %d", errno, e))
	}
	if len(dirents) != wantCount || digestDirents(dirents) != wantDigest {
		fr.s.fatal(fail(KindResultMismatch, StageEvent, int64(fr.s.seq-1), -1,
			"directory contents differ from the recorded run"))
	}
	return dirents, e
}

func (fr *replayFile) Close() experimentalsys.Errno {
	if !fr.s.active.Load() {
		return fr.File.Close()
	}
	_, _, errno := fr.s.fsOpExpect(fsOpFileClose, nil)
	if fr.closeUnder {
		_ = fr.File.Close() // closing a replay-opened read-only handle is not a guest-visible side effect
	}
	return experimentalsys.Errno(errno)
}

// ---------------------------------------------------------------------------
// small encoding helpers
// ---------------------------------------------------------------------------

func u32bytes(v uint32) []byte {
	var b [4]byte
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	return b[:]
}

func i64bytes(v int64) []byte {
	var b [8]byte
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
	return b[:]
}

func readdirCustom(req int, dirents []experimentalsys.Dirent) []byte {
	var e encBuffer
	e.u32(uint32(req))
	e.u32(uint32(len(dirents)))
	e.hash(digestDirents(dirents))
	return e.b
}

func parseReaddirCustom(b []byte) (req, count int, dg [32]byte) {
	d := decBuffer{b: b}
	return int(d.u32()), int(d.u32()), d.hash()
}

func digestDirents(dirents []experimentalsys.Dirent) [32]byte {
	var e encBuffer
	for _, de := range dirents {
		e.str(de.Name)
		e.u32(uint32(de.Type))
	}
	return digestBytes(e.b)
}
