package wazero

import (
	"fmt"
	"hash"
	"io"
	"math"
	"sync/atomic"

	"github.com/tetratelabs/wazero/internal/internalapi"
	"github.com/tetratelabs/wazero/internal/wasm/customsection"
)

// Custom section index sentinel errors. Use errors.Is to detect them.
var (
	// ErrCustomSectionNotFound is returned when no section matches the
	// requested ordinal, name or digest.
	ErrCustomSectionNotFound = customsection.ErrNotFound

	// ErrCustomSectionIndexClosed is returned after the owning CompiledModule
	// (or its Runtime) was closed.
	ErrCustomSectionIndexClosed = customsection.ErrClosed

	// ErrCustomSectionReaderClosed is returned when a reader is used after its
	// own Close.
	ErrCustomSectionReaderClosed = customsection.ErrReaderClosed

	// ErrCustomSectionRange is returned when a read range does not fit inside
	// the targeted section.
	ErrCustomSectionRange = customsection.ErrRange

	// ErrCustomSectionMalformedLength is returned when a section declares more
	// payload bytes than the module actually contains. It is detected before
	// any allocation sized by the declared length.
	ErrCustomSectionMalformedLength = customsection.ErrMalformedLength

	// ErrCustomSectionTooLarge is returned when a section exceeds the
	// configured per-section size limit.
	ErrCustomSectionTooLarge = customsection.ErrSectionTooLarge

	// ErrCustomSectionTotalLimit is returned when the indexed sections exceed
	// the configured total size limit.
	ErrCustomSectionTotalLimit = customsection.ErrTotalSizeLimit

	// ErrCustomSectionCountLimit is returned when the section count limit is
	// exceeded.
	ErrCustomSectionCountLimit = customsection.ErrSectionCountLimit

	// ErrCustomSectionDuplicateDecoder is returned when a decoder is
	// registered twice for the same section name.
	ErrCustomSectionDuplicateDecoder = customsection.ErrDuplicateDecoder

	// ErrCustomSectionDecoderNotFound is returned by Decode when no decoder is
	// registered for the targeted section name.
	ErrCustomSectionDecoderNotFound = customsection.ErrDecoderNotFound

	// ErrCustomSectionDecoderPanic is returned when a registered decoder
	// panics.
	ErrCustomSectionDecoderPanic = customsection.ErrDecoderPanic

	// ErrCustomSectionUnknown is returned by compilation under
	// RejectUnknownCustomSections when a section has no registered decoder.
	ErrCustomSectionUnknown = customsection.ErrUnknownSection

	// ErrCustomSectionInvalidArgument is returned for nonsensical query
	// parameters (e.g. an inverted length range).
	ErrCustomSectionInvalidArgument = customsection.ErrInvalidArgument
)

// UnknownCustomSectionPolicy decides what happens to custom sections for
// which no typed decoder is registered. The WebAssembly "name" section is
// always indexed, independently of this policy.
type UnknownCustomSectionPolicy uint8

const (
	// KeepUnknownCustomSections is the default policy: every custom section is
	// indexed. Sections without a decoder can be read raw, but
	// CustomSectionIndex.Decode returns ErrCustomSectionDecoderNotFound.
	KeepUnknownCustomSections UnknownCustomSectionPolicy = UnknownCustomSectionPolicy(customsection.UnknownPolicyKeep)

	// SkipUnknownCustomSections does not index sections without a decoder.
	// Ordinals keep counting them (so ordinals stay stable stream positions),
	// but they cannot be read through the index.
	SkipUnknownCustomSections UnknownCustomSectionPolicy = UnknownCustomSectionPolicy(customsection.UnknownPolicySkip)

	// RejectUnknownCustomSections makes compilation fail when a section
	// without a registered decoder is encountered.
	RejectUnknownCustomSections UnknownCustomSectionPolicy = UnknownCustomSectionPolicy(customsection.UnknownPolicyReject)
)

// CustomSectionMeta describes one section handed to a CustomSectionDecoder.
type CustomSectionMeta struct {
	// Name is the custom section name. The empty name is valid.
	Name string

	// Ordinal is the position of the section among all custom sections in
	// binary stream order, starting at zero, including duplicate sections and
	// (when SkipUnknownCustomSections is used) skipped sections.
	Ordinal int

	// Length is the payload length in bytes.
	Length int

	// Digest is the digest of the payload, computed with the configured digest
	// function (SHA-256 by default).
	Digest []byte
}

// CustomSectionDecoder decodes one custom section payload on demand.
//
// Version identifies the decoder implementation. It is attached to every
// Decode result so callers can tell which decoder revision produced a value
// and invalidate values produced by older revisions.
//
// DecodeCustomSection receives a private copy of the payload: it may retain
// or mutate the slice without affecting other readers or repeated decodes.
// A non-nil error or panic fails only that Decode call; the index stays
// usable and the next Decode invokes the decoder again with a fresh copy.
type CustomSectionDecoder interface {
	// Version returns the revision of this decoder.
	Version() uint32

	// DecodeCustomSection decodes one section payload.
	DecodeCustomSection(meta CustomSectionMeta, payload []byte) (any, error)
}

// CustomSectionIndexConfig configures the opt-in custom section index.
//
// The zero value is not usable; create one with NewCustomSectionIndexConfig
// and pass it to RuntimeConfig.WithCustomSectionIndex. The configuration is
// immutable: each With or Register call returns a new instance.
type CustomSectionIndexConfig struct {
	internalapi.WazeroOnlyType

	maxSectionBytes int64 // 0 = default
	maxTotalBytes   int64 // 0 = default
	maxSections     int   // 0 = default
	newHash         func() hash.Hash
	unknownPolicy   UnknownCustomSectionPolicy
	decoders        map[string]CustomSectionDecoder
}

// NewCustomSectionIndexConfig returns a configuration with safe default
// limits (128 MiB per section, 512 MiB total, 4096 sections), SHA-256
// digests and KeepUnknownCustomSections.
func NewCustomSectionIndexConfig() *CustomSectionIndexConfig {
	return &CustomSectionIndexConfig{maxSectionBytes: -1, maxTotalBytes: -1, maxSections: -1}
}

func (c *CustomSectionIndexConfig) clone() *CustomSectionIndexConfig {
	ret := *c
	if c.decoders != nil {
		ret.decoders = make(map[string]CustomSectionDecoder, len(c.decoders))
		for name, d := range c.decoders {
			ret.decoders[name] = d
		}
	}
	return &ret
}

// WithMaxSectionBytes limits the size of a single indexed section payload. A
// negative value restores the default. Compilation fails with
// ErrCustomSectionTooLarge when a larger section is encountered.
func (c *CustomSectionIndexConfig) WithMaxSectionBytes(max int64) *CustomSectionIndexConfig {
	if max < -1 || max > math.MaxInt32 {
		panic("custom section index: MaxSectionBytes out of range")
	}
	ret := c.clone()
	ret.maxSectionBytes = max
	return ret
}

// WithMaxTotalBytes limits the sum of indexed section payload bytes. A
// negative value restores the default. Compilation fails with
// ErrCustomSectionTotalLimit when the limit would be exceeded.
func (c *CustomSectionIndexConfig) WithMaxTotalBytes(max int64) *CustomSectionIndexConfig {
	if max < -1 || max > math.MaxInt32 {
		panic("custom section index: MaxTotalBytes out of range")
	}
	ret := c.clone()
	ret.maxTotalBytes = max
	return ret
}

// WithMaxSections limits the number of custom sections accepted while
// decoding. A negative value restores the default. Compilation fails with
// ErrCustomSectionCountLimit when exceeded.
func (c *CustomSectionIndexConfig) WithMaxSections(max int) *CustomSectionIndexConfig {
	ret := c.clone()
	ret.maxSections = max
	return ret
}

// WithUnknownCustomSections sets the policy for sections without a registered
// decoder. Defaults to KeepUnknownCustomSections.
func (c *CustomSectionIndexConfig) WithUnknownCustomSections(policy UnknownCustomSectionPolicy) *CustomSectionIndexConfig {
	ret := c.clone()
	ret.unknownPolicy = policy
	return ret
}

// WithDigest replaces the digest function used to identify sections. The
// factory must return a fresh hash on every call. The default is SHA-256.
func (c *CustomSectionIndexConfig) WithDigest(newHash func() hash.Hash) *CustomSectionIndexConfig {
	ret := c.clone()
	ret.newHash = newHash
	return ret
}

// RegisterDecoder registers a typed decoder for a custom section name and
// returns the resulting configuration. It returns
// ErrCustomSectionDuplicateDecoder when the name is already registered on
// this configuration and an error wrapping ErrInvalidConfig for a nil
// decoder.
func (c *CustomSectionIndexConfig) RegisterDecoder(name string, decoder CustomSectionDecoder) (*CustomSectionIndexConfig, error) {
	if decoder == nil {
		return nil, fmt.Errorf("%w: nil decoder for section name %q", customsection.ErrInvalidConfig, name)
	}
	if _, exists := c.decoders[name]; exists {
		return nil, customsection.ErrDuplicateDecoder
	}
	ret := c.clone()
	if ret.decoders == nil {
		ret.decoders = map[string]CustomSectionDecoder{}
	}
	ret.decoders[name] = decoder
	return ret, nil
}

// toBuilder converts the public configuration into an internal builder.
func (c *CustomSectionIndexConfig) toBuilder(runtimeClosed *atomic.Uint64) (*customsection.Builder, error) {
	cfg := customsection.Config{
		NewHash:       c.newHash,
		UnknownPolicy: customsection.UnknownPolicy(c.unknownPolicy),
	}
	if c.maxSectionBytes >= 0 {
		cfg.MaxSectionBytes = uint64(c.maxSectionBytes)
	}
	if c.maxTotalBytes >= 0 {
		cfg.MaxTotalBytes = uint64(c.maxTotalBytes)
	}
	if c.maxSections >= 0 {
		cfg.MaxSections = c.maxSections
	}
	if len(c.decoders) > 0 {
		cfg.Decoders = make(map[string]customsection.Decoder, len(c.decoders))
		for name, d := range c.decoders {
			cfg.Decoders[name] = sectionDecoderAdapter{d: d}
		}
	}
	return customsection.NewBuilder(cfg, runtimeClosed)
}

// sectionDecoderAdapter bridges the public decoder interface to the internal
// one.
type sectionDecoderAdapter struct {
	internalapi.WazeroOnlyType
	d CustomSectionDecoder
}

func (a sectionDecoderAdapter) Version() uint32 { return a.d.Version() }

func (a sectionDecoderAdapter) Decode(meta customsection.Meta, payload []byte) (any, error) {
	return a.d.DecodeCustomSection(CustomSectionMeta{
		Name:    meta.Name,
		Ordinal: meta.Ordinal,
		Length:  meta.Length,
		Digest:  meta.Digest,
	}, payload)
}

// IndexedCustomSection is the immutable description of one indexed custom
// section.
//
// # Notes
//
//   - This is an interface for decoupling, not third-party implementations.
//     All implementations are in wazero.
type IndexedCustomSection interface {
	// Name returns the custom section name (duplicates are allowed).
	Name() string

	// Ordinal returns the stream-order position of the section among all
	// custom sections, starting at zero.
	Ordinal() int

	// Length returns the payload length in bytes.
	Length() int

	// Digest returns a copy of the payload digest.
	Digest() []byte

	internalapi.WazeroOnly
}

// CustomSectionReader reads one section payload independently of every other
// reader: Read only fills the caller's buffer and never shares mutable
// storage. Repeated reads are supported via Seek or by opening another
// reader.
//
// A reader is intended for use by one goroutine at a time, like io.Reader.
// Multiple readers opened from the same index can be used concurrently.
//
// # Notes
//
//   - This is an interface for decoupling, not third-party implementations.
//     All implementations are in wazero.
type CustomSectionReader interface {
	io.Reader
	io.Seeker
	io.Closer

	// Ordinal returns the ordinal of the read section.
	Ordinal() int

	internalapi.WazeroOnly
}

// CustomSectionFilter selects sections for CustomSectionIndex.Find.
type CustomSectionFilter struct {
	// MatchName enables filtering by Name. Needed because the empty name is a
	// valid custom section name.
	MatchName bool
	Name      string

	// MatchOrdinal enables filtering by Ordinal.
	MatchOrdinal bool
	Ordinal      int

	// MinLength filters sections shorter than this value.
	MinLength int
	// MaxLength filters sections longer than this value. A zero or negative
	// value means no upper bound, so the zero-value filter is unrestricted.
	MaxLength int

	// Digest, when non-empty, filters sections by digest.
	Digest []byte
}

// DecodedCustomSection is the result of CustomSectionIndex.Decode.
type DecodedCustomSection struct {
	// CustomSectionMeta describes the decoded section.
	CustomSectionMeta

	// DecoderVersion is CustomSectionDecoder.Version() of the decoder that
	// produced Value.
	DecoderVersion uint32

	// Value is whatever the registered decoder returned.
	Value any
}

// CustomSectionIndex is the immutable, concurrency-safe index built while
// compiling a module. It is valid until the CompiledModule (or the Runtime
// that compiled it) is closed; afterwards every read returns
// ErrCustomSectionIndexClosed.
//
// # Notes
//
//   - This is an interface for decoupling, not third-party implementations.
//     All implementations are in wazero.
type CustomSectionIndex interface {
	// Len returns the number of indexed sections, in original stream order.
	// Policy-skipped sections are not counted here.
	Len() int

	// Sections returns all indexed sections in original stream order.
	Sections() []IndexedCustomSection

	// Section returns the section with the given stream ordinal. It returns
	// ErrCustomSectionNotFound when no indexed section has that ordinal.
	Section(ordinal int) (IndexedCustomSection, error)

	// SectionsByName returns all sections with the given name in stream
	// order, preserving duplicate sections.
	SectionsByName(name string) []IndexedCustomSection

	// SectionsByLength returns sections whose payload length is within
	// [minLength, maxLength]. A negative maxLength means no upper bound.
	SectionsByLength(minLength, maxLength int) ([]IndexedCustomSection, error)

	// SectionsByDigest returns all sections with the given digest in stream
	// order.
	SectionsByDigest(digest []byte) []IndexedCustomSection

	// Find returns sections matching all set filter fields.
	Find(filter CustomSectionFilter) []IndexedCustomSection

	// Open opens an independent reader over the section.
	Open(section IndexedCustomSection) (CustomSectionReader, error)

	// ReadAll returns a private copy of the full section payload.
	ReadAll(section IndexedCustomSection) ([]byte, error)

	// ReadRange returns a private copy of length bytes starting at offset in
	// the section payload. A negative length means "from offset to the end".
	ReadRange(section IndexedCustomSection, offset, length int64) ([]byte, error)

	// Decode decodes the section on demand using the decoder registered for
	// its name. Each call receives a fresh payload copy; failures are not
	// cached and do not affect later calls or raw reads.
	Decode(section IndexedCustomSection) (*DecodedCustomSection, error)

	internalapi.WazeroOnly
}

// customSectionIndex wraps the internal store.
type customSectionIndexAPI struct {
	internalapi.WazeroOnlyType
	store *customsection.Store
}

func (i *customSectionIndexAPI) Len() int { return i.store.Len() }

func (i *customSectionIndexAPI) Sections() []IndexedCustomSection {
	all := i.store.All()
	return i.wrapEntries(all)
}

func (i *customSectionIndexAPI) Section(ordinal int) (IndexedCustomSection, error) {
	e, err := i.store.EntryByOrdinal(ordinal)
	if err != nil {
		return nil, err
	}
	return indexedCustomSection{store: i.store, e: e}, nil
}

func (i *customSectionIndexAPI) SectionsByName(name string) []IndexedCustomSection {
	return i.wrapEntries(i.store.ByName(name))
}

func (i *customSectionIndexAPI) SectionsByLength(minLength, maxLength int) ([]IndexedCustomSection, error) {
	entries, err := i.store.ByLength(minLength, maxLength)
	if err != nil {
		return nil, err
	}
	return i.wrapEntries(entries), nil
}

func (i *customSectionIndexAPI) SectionsByDigest(digest []byte) []IndexedCustomSection {
	return i.wrapEntries(i.store.ByDigest(digest))
}

func (i *customSectionIndexAPI) Find(filter CustomSectionFilter) []IndexedCustomSection {
	all := i.store.All()
	out := make([]IndexedCustomSection, 0, len(all))
	for _, e := range all {
		if filter.MatchName && e.Name() != filter.Name {
			continue
		}
		if filter.MatchOrdinal && e.Ordinal() != filter.Ordinal {
			continue
		}
		if e.Length() < filter.MinLength {
			continue
		}
		// A non-positive MaxLength means "no upper bound", so the zero-value
		// filter does not accidentally restrict results to empty sections.
		if filter.MaxLength > 0 && e.Length() > filter.MaxLength {
			continue
		}
		if len(filter.Digest) > 0 && !equalBytes(e.Digest(), filter.Digest) {
			continue
		}
		out = append(out, indexedCustomSection{store: i.store, e: e})
	}
	return out
}

func (i *customSectionIndexAPI) checkRef(section IndexedCustomSection) (int, error) {
	if section == nil {
		return 0, customsection.ErrNotFound
	}
	ref, ok := section.(indexedCustomSection)
	if !ok || ref.store != i.store {
		return 0, customsection.ErrNotFound
	}
	return ref.e.Ordinal(), nil
}

func (i *customSectionIndexAPI) Open(section IndexedCustomSection) (CustomSectionReader, error) {
	ordinal, err := i.checkRef(section)
	if err != nil {
		return nil, err
	}
	r, err := i.store.OpenReader(ordinal)
	if err != nil {
		return nil, err
	}
	return &customSectionReader{r: r}, nil
}

func (i *customSectionIndexAPI) ReadAll(section IndexedCustomSection) ([]byte, error) {
	ordinal, err := i.checkRef(section)
	if err != nil {
		return nil, err
	}
	return i.store.CopyAll(ordinal)
}

func (i *customSectionIndexAPI) ReadRange(section IndexedCustomSection, offset, length int64) ([]byte, error) {
	ordinal, err := i.checkRef(section)
	if err != nil {
		return nil, err
	}
	if length < 0 {
		length = int64(section.Length()) - offset
	}
	return i.store.CopyRange(ordinal, offset, length)
}

func (i *customSectionIndexAPI) Decode(section IndexedCustomSection) (*DecodedCustomSection, error) {
	ordinal, err := i.checkRef(section)
	if err != nil {
		return nil, err
	}
	res, err := i.store.Decode(ordinal)
	if err != nil {
		return nil, err
	}
	return &DecodedCustomSection{
		CustomSectionMeta: CustomSectionMeta{
			Name:    res.Meta.Name,
			Ordinal: res.Meta.Ordinal,
			Length:  res.Meta.Length,
			Digest:  res.Meta.Digest,
		},
		DecoderVersion: res.DecoderVersion,
		Value:          res.Value,
	}, nil
}

// indexedCustomSection wraps an internal entry and carries its owning store so
// that sections from one index cannot be read through another.
type indexedCustomSection struct {
	internalapi.WazeroOnlyType
	store *customsection.Store
	e     customsection.Entry
}

func (s indexedCustomSection) Name() string   { return s.e.Name() }
func (s indexedCustomSection) Ordinal() int   { return s.e.Ordinal() }
func (s indexedCustomSection) Length() int    { return s.e.Length() }
func (s indexedCustomSection) Digest() []byte { return s.e.Digest() }

// customSectionReader wraps the internal reader.
type customSectionReader struct {
	internalapi.WazeroOnlyType
	r *customsection.Reader
}

func (r *customSectionReader) Read(p []byte) (int, error) { return r.r.Read(p) }
func (r *customSectionReader) Seek(offset int64, whence int) (int64, error) {
	return r.r.Seek(offset, whence)
}
func (r *customSectionReader) Close() error { return r.r.Close() }
func (r *customSectionReader) Ordinal() int { return r.r.Ordinal() }

func (i *customSectionIndexAPI) wrapEntries(entries []customsection.Entry) []IndexedCustomSection {
	if len(entries) == 0 {
		return nil
	}
	out := make([]IndexedCustomSection, len(entries))
	for idx, e := range entries {
		out[idx] = indexedCustomSection{store: i.store, e: e}
	}
	return out
}

func equalBytes(a, b []byte) bool {
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
