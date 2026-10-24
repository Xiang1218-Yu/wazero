package boundary

import (
	"crypto/sha256"
)

// VerifyPublic checks the given module binary and canonical signatures
// against the recorded manifest. It can be called either before or after the
// automatic compile-time validation.
func (s *Session) VerifyPublic(binary []byte, sigs []Sig) (err error) {
	defer guardEntry(&err)
	var mf rawFrame
	found := false
	for _, f := range s.frames {
		if f.typ == rtManifest {
			mf = f
			found = true
			break
		}
	}
	if !found {
		return fail(KindLogTruncated, StageManifest, -1, -1, "log has no manifest record")
	}
	d := decBuffer{b: mf.payload}
	wantSHA := d.hash()
	n := int(d.u32())
	gotSigs := make([]Sig, 0, n)
	for i := 0; i < n; i++ {
		gotSigs = append(gotSigs, Sig{
			Import:  d.boolean(),
			Module:  d.str(),
			Name:    d.str(),
			Params:  d.bytes(),
			Results: d.bytes(),
		})
	}
	gotSHA := sha256.Sum256(binary)
	if wantSHA != gotSHA {
		return fail(KindModuleDigest, StageManifest, -1, mf.offset,
			"module binary sha256 %x does not match recorded %x", gotSHA[:8], wantSHA[:8])
	}
	if !sigsEqual(gotSigs, sigs) {
		return fail(KindSignature, StageManifest, -1, mf.offset,
			"imported/exported function signatures differ from the recorded module")
	}
	return nil
}
