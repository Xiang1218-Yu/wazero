package boundary

// replayPanicValue reports whether a recovered value is a structured
// *ReplayError (as raised by truncated/malformed payload decoders).
func replayPanicValue(r any) (*ReplayError, bool) {
	if r == nil {
		return nil, false
	}
	if re, ok := r.(*ReplayError); ok {
		return re, true
	}
	return nil, false
}

// guardEntry converts structured decoder panics into returned errors at
// session entry points.
func guardEntry(errp *error) {
	if r := recover(); r != nil {
		if re, ok := replayPanicValue(r); ok {
			*errp = re
		} else {
			panic(r)
		}
	}
}
