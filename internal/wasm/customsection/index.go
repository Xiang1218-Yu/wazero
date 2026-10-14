// Package customsection implements an immutable, memory-bounded index of the
// custom sections contained in a WebAssembly binary.
//
// The index is built once, while the binary is decoded, and never copies a
// section payload to a caller directly: every Read, ReadRange or Decode
// allocates a fresh buffer, so independent callers can never share a buffer
// that one of them could mutate.
//
// The package is internal: the public API lives in the root wazero package.
package customsection

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"sync/atomic"
)

// Default limits applied when the caller leaves them unset. They exist to make
// sure a hostile binary cannot drive unbounded allocations.
const (
	// DefaultMaxSectionBytes bounds the payload of a single custom section.
	DefaultMaxSectionBytes = uint64(128 << 20) // 128 MiB
	// DefaultMaxTotalBytes bounds the sum of all indexed payload bytes.
	DefaultMaxTotalBytes = uint64(512 << 20) // 512 MiB
	// DefaultMaxSections bounds the number of custom sections indexed.
	DefaultMaxSections = 4096

	// maxIntBytes is the largest byte count representable as an int on every
	// platform wazero supports (32-bit int included). Indexed byte ranges must
	// never exceed it.
	maxIntBytes = uint64(math.MaxInt32)
)

// Sentinel errors. Callers can use errors.Is to detect them; wazero re-exports
// equivalents from its root package.
var (
	// ErrNotFound is returned when no section matches the requested ordinal,
	// name or digest.
	ErrNotFound = errors.New("custom section not found")

	// ErrClosed is returned after the owning CompiledModule or Runtime was
	// closed.
	ErrClosed = errors.New("custom section index closed")

	// ErrReaderClosed is returned when a reader is used after its own Close.
	ErrReaderClosed = errors.New("custom section reader closed")

	// ErrRange is returned when an offset/length pair does not fit inside the
	// targeted section.
	ErrRange = errors.New("custom section read range out of bounds")

	// ErrMalformedLength is returned when a section declares a payload larger
	// than the bytes left in the module. Crucially, this is detected *before*
	// any allocation, so a hostile length field cannot exhaust memory.
	ErrMalformedLength = errors.New("malformed custom section length")

	// ErrSectionTooLarge is returned when a payload exceeds MaxSectionBytes.
	ErrSectionTooLarge = errors.New("custom section exceeds the per-section size limit")

	// ErrTotalSizeLimit is returned when indexed payloads would exceed
	// MaxTotalBytes.
	ErrTotalSizeLimit = errors.New("custom sections exceed the total size limit")

	// ErrSectionCountLimit is returned when the section count would exceed
	// MaxSections.
	ErrSectionCountLimit = errors.New("custom sections exceed the section count limit")

	// ErrDuplicateDecoder is returned when a decoder is registered twice for
	// the same section name.
	ErrDuplicateDecoder = errors.New("custom section decoder registered twice for the same name")

	// ErrDecoderNotFound is returned by Decode when no decoder is registered
	// for the targeted section name.
	ErrDecoderNotFound = errors.New("no custom section decoder registered for this section name")

	// ErrDecoderPanic is returned when a registered decoder panics.
	ErrDecoderPanic = errors.New("custom section decoder panicked")

	// ErrUnknownSection is returned when UnknownPolicyReject finds a section
	// without a registered decoder.
	ErrUnknownSection = errors.New("unregistered custom section rejected by policy")

	// ErrInvalidConfig is returned for an invalid index configuration.
	ErrInvalidConfig = errors.New("invalid custom section index configuration")

	// ErrInvalidArgument is returned for nonsensical query parameters.
	ErrInvalidArgument = errors.New("invalid custom section query argument")
)

// UnknownPolicy decides what the builder does with custom sections for which
// no decoder is registered. The WebAssembly "name" section is always indexed,
// regardless of this policy.
type UnknownPolicy uint8

const (
	// UnknownPolicyKeep (the default) indexes every custom section. Sections
	// without a decoder can still be read raw, but Decode fails.
	UnknownPolicyKeep UnknownPolicy = iota
	// UnknownPolicySkip does not index sections without a decoder. They remain
	// part of the module (ordinals keep counting them) but can never be read
	// through the index.
	UnknownPolicySkip
	// UnknownPolicyReject fails compilation when a section without a
	// registered decoder is encountered.
	UnknownPolicyReject
)

// Meta describes a section without exposing its payload. It is the only
// description handed to registered decoders besides the payload copy.
type Meta struct {
	Name    string
	Ordinal int
	Length  int
	Digest  []byte
}

// Decoder decodes the payload of one custom section on demand.
//
// Version identifies the decoder implementation. It travels with every
// Decode result so callers can tell which decoder revision produced a value
// and invalidate data decoded by older revisions.
//
// Implementations receive a private copy of the payload and may retain or
// mutate it without affecting other readers.
type Decoder interface {
	Version() uint32
	Decode(meta Meta, payload []byte) (any, error)
}

// Config configures a Builder. The zero value is not valid; use NewConfig or
// the root package's NewCustomSectionIndexConfig.
type Config struct {
	// MaxSectionBytes bounds a single section payload. Zero means default.
	MaxSectionBytes uint64
	// MaxTotalBytes bounds the sum of indexed payload bytes. Zero means
	// default.
	MaxTotalBytes uint64
	// MaxSections bounds the number of indexed sections. Zero means default.
	MaxSections int
	// NewHash builds the digest used to identify and select sections. Nil
	// means SHA-256.
	NewHash func() hash.Hash
	// Decoders maps custom section names to their decoders. It must not be
	// mutated after the Builder is created.
	Decoders map[string]Decoder
	// UnknownPolicy selects the behavior for sections without a decoder.
	UnknownPolicy UnknownPolicy
}

func (c Config) withDefaults() (Config, error) {
	if c.MaxSectionBytes == 0 {
		c.MaxSectionBytes = DefaultMaxSectionBytes
	}
	if c.MaxTotalBytes == 0 {
		c.MaxTotalBytes = DefaultMaxTotalBytes
	}
	if c.MaxSections == 0 {
		c.MaxSections = DefaultMaxSections
	}
	if c.MaxSectionBytes > maxIntBytes || c.MaxTotalBytes > maxIntBytes {
		return c, fmt.Errorf("%w: byte limits must not exceed %d", ErrInvalidConfig, maxIntBytes)
	}
	// The total limit is the stricter bound: a section can never exceed the
	// total budget, so clamp the effective per-section limit instead of
	// rejecting a configuration that only set a small total.
	if c.MaxSectionBytes > c.MaxTotalBytes {
		c.MaxSectionBytes = c.MaxTotalBytes
	}
	if c.MaxSections < 0 {
		return c, fmt.Errorf("%w: negative section count limit", ErrInvalidConfig)
	}
	if c.NewHash == nil {
		c.NewHash = sha256.New
	} else if c.NewHash() == nil {
		return c, fmt.Errorf("%w: digest factory returned nil", ErrInvalidConfig)
	}
	if c.UnknownPolicy > UnknownPolicyReject {
		return c, fmt.Errorf("%w: unknown unknown-section policy %d", ErrInvalidConfig, c.UnknownPolicy)
	}
	// Defensive copy: the builder must own the registry.
	if c.Decoders != nil {
		decoders := make(map[string]Decoder, len(c.Decoders))
		for name, d := range c.Decoders {
			if d == nil {
				return c, fmt.Errorf("%w: nil decoder for section name %q", ErrInvalidConfig, name)
			}
			decoders[name] = d
		}
		c.Decoders = decoders
	}
	return c, nil
}

// Entry is the immutable description of one indexed custom section.
type Entry struct {
	name    string
	ordinal int
	offset  int
	length  int
	digest  []byte
}

// Name implements IndexedCustomSection.Name.
func (e Entry) Name() string { return e.name }

// Ordinal implements IndexedCustomSection.Ordinal.
func (e Entry) Ordinal() int { return e.ordinal }

// Length implements IndexedCustomSection.Length.
func (e Entry) Length() int { return e.length }

// Digest returns a copy of the section digest so callers cannot mutate the
// index by retaining the returned slice.
func (e Entry) Digest() []byte {
	out := make([]byte, len(e.digest))
	copy(out, e.digest)
	return out
}

// Meta returns the Meta describing e.
func (e Entry) Meta() Meta {
	return Meta{Name: e.name, Ordinal: e.ordinal, Length: e.length, Digest: e.Digest()}
}

// Builder incrementally indexes the custom sections of one module binary. It
// is not safe for concurrent use; decoding a module is single-threaded.
type Builder struct {
	cfg           Config
	runtimeClosed *atomic.Uint64

	data      []byte // contiguous, append-only; frozen by Build
	entries   []Entry
	byOrdinal map[int]int
	total     uint64

	// ordinal counts every custom section in stream order, including the
	// "name" section and sections skipped by policy.
	ordinal int
}

// NewBuilder validates cfg and returns a fresh builder. runtimeClosed, when
// non-nil, is the owning runtime's closed marker: a non-zero value invalidates
// the resulting index just like CompiledModule.Close.
func NewBuilder(cfg Config, runtimeClosed *atomic.Uint64) (*Builder, error) {
	c, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	return &Builder{
		cfg:           c,
		runtimeClosed: runtimeClosed,
		byOrdinal:     map[int]int{},
	}, nil
}

// Ingest consumes exactly payloadSize bytes of one custom section payload from
// r and, depending on policy and decoder registration, indexes it.
//
// known must be true for the WebAssembly "name" section, which is always
// indexed and never subject to the unknown-section policy.
//
// indexed reports whether the payload was stored. It is false for
// policy-skipped sections. On success the returned slice is a private copy of
// the payload that remains valid only until the next Ingest call: the caller
// may use it for immediate in-place decoding (e.g. the name section) but must
// not retain it. It is nil for policy-skipped sections.
//
// All bounds checks happen before any allocation sized by payloadSize, so a
// malicious length field cannot trigger unbounded allocation.
func (b *Builder) Ingest(r *bytes.Reader, name string, payloadSize uint32, known bool) (payload []byte, ordinal int, indexed bool, err error) {
	ordinal = b.ordinal
	b.ordinal++

	size := uint64(payloadSize)
	if b.ordinal > b.cfg.MaxSections {
		return nil, ordinal, false, fmt.Errorf("%w: more than %d custom sections", ErrSectionCountLimit, b.cfg.MaxSections)
	}

	registered := false
	if b.cfg.Decoders != nil {
		_, registered = b.cfg.Decoders[name]
	}
	if !known && !registered {
		switch b.cfg.UnknownPolicy {
		case UnknownPolicyReject:
			return nil, ordinal, false, fmt.Errorf("%w: %q", ErrUnknownSection, name)
		case UnknownPolicySkip:
			// Validate against the real stream length without allocating, and
			// consume exactly the declared bytes so section length accounting
			// stays correct.
			if size > uint64(r.Len()) {
				return nil, ordinal, false, fmt.Errorf("%w: section %q declares %d payload bytes but %d remain",
					ErrMalformedLength, name, size, r.Len())
			}
			if _, err := io.CopyN(io.Discard, r, int64(size)); err != nil {
				return nil, ordinal, false, fmt.Errorf("failed to skip custom section %q: %w", name, err)
			}
			return nil, ordinal, false, nil
		}
	}

	// Validate the claimed length against the real remaining input BEFORE
	// allocating: this is what disarms a huge length in a tiny binary.
	if size > uint64(r.Len()) {
		return nil, ordinal, false, fmt.Errorf("%w: section %q declares %d payload bytes but %d remain",
			ErrMalformedLength, name, size, r.Len())
	}
	if size > b.cfg.MaxSectionBytes {
		return nil, ordinal, false, fmt.Errorf("%w: section %q is %d bytes (limit %d)",
			ErrSectionTooLarge, name, size, b.cfg.MaxSectionBytes)
	}
	// Overflow-safe total accounting.
	if size > b.cfg.MaxTotalBytes || b.total > b.cfg.MaxTotalBytes-size {
		return nil, ordinal, false, fmt.Errorf("%w: section %q would bring indexed bytes to %d (limit %d)",
			ErrTotalSizeLimit, name, b.total+size, b.cfg.MaxTotalBytes)
	}

	// Grow by exactly the validated amount: unlike append, this never
	// over-allocates according to a growth factor sized by untrusted input.
	offset := len(b.data)
	grown := make([]byte, offset+int(size))
	copy(grown, b.data)
	b.data = grown
	dst := b.data[offset:]
	if _, err := io.ReadFull(r, dst); err != nil {
		return nil, ordinal, false, fmt.Errorf("failed to read custom section %q: %w", name, err)
	}
	b.total += size

	h := b.cfg.NewHash()
	h.Write(dst)
	digest := h.Sum(nil)

	idx := len(b.entries)
	b.entries = append(b.entries, Entry{
		name:    name,
		ordinal: ordinal,
		offset:  offset,
		length:  len(dst),
		digest:  digest,
	})
	b.byOrdinal[ordinal] = idx
	// dst is a view into b.data valid only until the next Ingest; the decoder
	// uses it immediately (e.g. the "name" section) and never retains it.
	return dst, ordinal, true, nil
}

// OrdinalCount returns the number of custom sections seen so far, including
// skipped ones.
func (b *Builder) OrdinalCount() int { return b.ordinal }

// Build freezes the index. The builder must not be used afterwards.
func (b *Builder) Build() *Store {
	byName := make(map[string][]int, len(b.entries))
	byDigest := make(map[string][]int, len(b.entries))
	for i, e := range b.entries {
		byName[e.name] = append(byName[e.name], i)
		byDigest[string(e.digest)] = append(byDigest[string(e.digest)], i)
	}
	return &Store{
		data:          b.data,
		entries:       b.entries,
		byOrdinal:     b.byOrdinal,
		byName:        byName,
		byDigest:      byDigest,
		decoders:      b.cfg.Decoders,
		runtimeClosed: b.runtimeClosed,
	}
}

// Store is the immutable, concurrency-safe custom section index attached to a
// compiled module.
type Store struct {
	data          []byte
	entries       []Entry
	byOrdinal     map[int]int
	byName        map[string][]int
	byDigest      map[string][]int
	decoders      map[string]Decoder
	runtimeClosed *atomic.Uint64

	closed atomic.Bool
}

// failIfClosed returns ErrClosed when the index, its owning CompiledModule or
// its owning Runtime was closed.
func (s *Store) failIfClosed() error {
	if s.closed.Load() {
		return ErrClosed
	}
	if s.runtimeClosed != nil && s.runtimeClosed.Load() != 0 {
		return ErrClosed
	}
	return nil
}

// Close invalidates the index and every reader opened from it. It is safe to
// call concurrently and repeatedly.
func (s *Store) Close() error {
	s.closed.Store(true)
	return nil
}

// Len returns the number of indexed sections (excluding policy-skipped ones).
func (s *Store) Len() int { return len(s.entries) }

// All returns all indexed sections in original stream order.
func (s *Store) All() []Entry {
	out := make([]Entry, len(s.entries))
	copy(out, s.entries)
	return out
}

// EntryByOrdinal returns the section with the given stream ordinal.
func (s *Store) EntryByOrdinal(ordinal int) (Entry, error) {
	if err := s.failIfClosed(); err != nil {
		return Entry{}, err
	}
	if i, ok := s.byOrdinal[ordinal]; ok {
		return s.entries[i], nil
	}
	return Entry{}, fmt.Errorf("%w: ordinal %d", ErrNotFound, ordinal)
}

// ByName returns all sections with the given name in stream order. Duplicate
// names are preserved.
func (s *Store) ByName(name string) []Entry {
	if err := s.failIfClosed(); err != nil {
		return nil
	}
	return s.pick(s.byName[name])
}

// ByDigest returns all sections with the given digest in stream order.
func (s *Store) ByDigest(digest []byte) []Entry {
	if err := s.failIfClosed(); err != nil {
		return nil
	}
	if len(digest) == 0 {
		return nil
	}
	return s.pick(s.byDigest[string(digest)])
}

// ByLength returns sections whose payload length is within [minLength,
// maxLength]. A negative maxLength means no upper bound.
func (s *Store) ByLength(minLength, maxLength int) ([]Entry, error) {
	if minLength < 0 {
		return nil, fmt.Errorf("%w: negative minimum length", ErrInvalidArgument)
	}
	if maxLength >= 0 && maxLength < minLength {
		return nil, fmt.Errorf("%w: max length %d < min length %d", ErrInvalidArgument, maxLength, minLength)
	}
	if err := s.failIfClosed(); err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range s.entries {
		if e.length < minLength {
			continue
		}
		if maxLength >= 0 && e.length > maxLength {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *Store) pick(indexes []int) []Entry {
	if len(indexes) == 0 {
		return nil
	}
	out := make([]Entry, len(indexes))
	for i, idx := range indexes {
		out[i] = s.entries[idx]
	}
	return out
}

// CopyRange returns a fresh copy of bytes [off, off+n) of the section
// payload. Every call allocates an independent buffer.
func (s *Store) CopyRange(ordinal int, off, n int64) ([]byte, error) {
	if err := s.failIfClosed(); err != nil {
		return nil, err
	}
	if off < 0 || n < 0 || off > math.MaxInt32 || n > math.MaxInt32 {
		return nil, fmt.Errorf("%w: offset %d length %d", ErrRange, off, n)
	}
	idx, ok := s.byOrdinal[ordinal]
	if !ok {
		return nil, fmt.Errorf("%w: ordinal %d", ErrNotFound, ordinal)
	}
	e := s.entries[idx]
	if off > int64(e.length) || n > int64(e.length)-off {
		return nil, fmt.Errorf("%w: section %q (length %d): offset %d length %d",
			ErrRange, e.name, e.length, off, n)
	}
	start := e.offset + int(off)
	out := make([]byte, int(n))
	copy(out, s.data[start:start+int(n)])
	return out, nil
}

// CopyAll returns a private copy of the whole section payload.
func (s *Store) CopyAll(ordinal int) ([]byte, error) {
	e, err := s.EntryByOrdinal(ordinal)
	if err != nil {
		return nil, err
	}
	return s.CopyRange(ordinal, 0, int64(e.length))
}

// OpenReader opens an independent reader positioned at the start of the
// section.
func (s *Store) OpenReader(ordinal int) (*Reader, error) {
	if _, err := s.EntryByOrdinal(ordinal); err != nil {
		return nil, err
	}
	return &Reader{store: s, ordinal: ordinal}, nil
}

// DecodeResult is the outcome of Store.Decode.
type DecodeResult struct {
	Meta           Meta
	Value          any
	DecoderVersion uint32
}

// Decode decodes the section on demand using the decoder registered for its
// name. Each call builds a fresh payload copy and invokes the decoder anew:
// failures are never cached and cannot poison later reads.
func (s *Store) Decode(ordinal int) (*DecodeResult, error) {
	e, err := s.EntryByOrdinal(ordinal)
	if err != nil {
		return nil, err
	}
	decoder, ok := s.decoders[e.name]
	if !ok {
		return nil, fmt.Errorf("%w: section %q (ordinal %d)", ErrDecoderNotFound, e.name, ordinal)
	}
	payload, err := s.CopyRange(ordinal, 0, int64(e.length))
	if err != nil {
		return nil, err
	}

	meta := e.Meta()
	var (
		value  any
		decErr error
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				decErr = fmt.Errorf("%w: %v", ErrDecoderPanic, r)
			}
		}()
		value, decErr = decoder.Decode(meta, payload)
	}()
	if decErr != nil {
		return nil, &DecodeError{Name: e.name, Ordinal: ordinal, Err: decErr}
	}
	return &DecodeResult{Meta: meta, Value: value, DecoderVersion: decoder.Version()}, nil
}

// DecodeError wraps an error returned by a registered decoder, preserving it
// for errors.Is and errors.As.
type DecodeError struct {
	Name    string
	Ordinal int
	Err     error
}

func (e *DecodeError) Error() string {
	return fmt.Sprintf("custom section %q (ordinal %d) decode failed: %v", e.Name, e.Ordinal, e.Err)
}

func (e *DecodeError) Unwrap() error { return e.Err }

// Reader is an independent, single-goroutine reader over one indexed section.
// The reader never exposes the index's backing storage: Read only copies into
// the caller's buffer.
type Reader struct {
	store   *Store
	ordinal int
	pos     int64
	closed  bool
}

// Ordinal returns the ordinal of the read section.
func (r *Reader) Ordinal() int { return r.ordinal }

// Len returns the number of unread bytes.
func (r *Reader) Len() int {
	e, err := r.store.EntryByOrdinal(r.ordinal)
	if err != nil {
		return 0
	}
	return int(int64(e.length) - r.pos)
}

// Seek implements io.Seeker with the same semantics as bytes.Reader.Seek.
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	if r.closed {
		return 0, ErrReaderClosed
	}
	if err := r.store.failIfClosed(); err != nil {
		return 0, err
	}
	e, err := r.store.EntryByOrdinal(r.ordinal)
	if err != nil {
		return 0, err
	}
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.pos + offset
	case io.SeekEnd:
		abs = int64(e.length) + offset
	default:
		return 0, fmt.Errorf("%w: invalid whence %d", ErrInvalidArgument, whence)
	}
	if abs < 0 {
		return 0, fmt.Errorf("%w: negative position %d", ErrRange, abs)
	}
	if abs > int64(e.length) {
		return 0, fmt.Errorf("%w: position %d beyond length %d", ErrRange, abs, e.length)
	}
	r.pos = abs
	return abs, nil
}

// Read implements io.Reader. Repeated reads are supported via Seek.
func (r *Reader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, ErrReaderClosed
	}
	if err := r.store.failIfClosed(); err != nil {
		return 0, err
	}
	e, err := r.store.EntryByOrdinal(r.ordinal)
	if err != nil {
		return 0, err
	}
	if r.pos >= int64(e.length) {
		if len(p) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	idx := r.store.byOrdinal[r.ordinal]
	entry := r.store.entries[idx]
	start := entry.offset + int(r.pos)
	n := copy(p, r.store.data[start:entry.offset+entry.length])
	r.pos += int64(n)
	if r.pos >= int64(e.length) && len(p) > 0 {
		return n, io.EOF
	}
	return n, nil
}

// Close releases the reader. It is idempotent.
func (r *Reader) Close() error {
	r.closed = true
	return nil
}

// ReadAt implements io.ReaderAt without moving the reader position.
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	if r.closed {
		return 0, ErrReaderClosed
	}
	e, err := r.store.EntryByOrdinal(r.ordinal)
	if err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, fmt.Errorf("%w: negative offset %d", ErrRange, off)
	}
	if off >= int64(e.length) {
		if len(p) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	idx := r.store.byOrdinal[r.ordinal]
	entry := r.store.entries[idx]
	start := entry.offset + int(off)
	available := r.store.data[start : entry.offset+entry.length]
	n := copy(p, available)
	var readErr error
	if n < len(p) {
		readErr = io.EOF
	}
	return n, readErr
}
