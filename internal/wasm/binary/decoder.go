package binary

import (
	"bytes"
	"debug/dwarf"
	"errors"
	"fmt"
	"io"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/leb128"
	"github.com/tetratelabs/wazero/internal/wasm"
	"github.com/tetratelabs/wazero/internal/wasm/customsection"
	"github.com/tetratelabs/wazero/internal/wasmdebug"
)

// DecodeModule implements wasm.DecodeModule for the WebAssembly 1.0 (20191205) Binary Format
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-format%E2%91%A0
//
// sectionIndex, when non-nil, enables the opt-in custom section index: custom
// section payloads are ingested by the builder instead of being unconditionally
// copied. This never changes the decoded Module otherwise.
func DecodeModule(
	binary []byte,
	enabledFeatures api.CoreFeatures,
	memoryLimitPages uint32,
	memoryCapacityFromMax,
	dwarfEnabled, storeCustomSections bool,
	sectionIndex *customsection.Builder,
) (*wasm.Module, error) {
	r := bytes.NewReader(binary)

	// Magic number.
	buf := make([]byte, 4)
	if _, err := io.ReadFull(r, buf); err != nil || !bytes.Equal(buf, Magic) {
		return nil, ErrInvalidMagicNumber
	}

	// Version.
	if _, err := io.ReadFull(r, buf); err != nil || !bytes.Equal(buf, version) {
		return nil, ErrInvalidVersion
	}

	memSizer := newMemorySizer(memoryLimitPages, memoryCapacityFromMax)

	m := &wasm.Module{}
	var lastSectionID wasm.SectionID
	var info, line, str, abbrev, ranges []byte // For DWARF Data.

	// Only used when sectionIndex != nil: exposedOrdinals lists, in stream
	// order, the non-name custom sections that m.CustomSections would contain
	// (policy-skipped ones are absent from the store). dwarfOrdinals remembers
	// the latest ordinal of each DWARF section name.
	var exposedOrdinals []int
	dwarfOrdinals := map[string]int{}
	for {
		// TODO: except custom sections, all others are required to be in order, but we aren't checking yet.
		// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#modules%E2%91%A0%E2%93%AA
		sectionID, err := r.ReadByte()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("read section id: %w", err)
		}

		sectionSize, _, err := leb128.DecodeUint32(r)
		if err != nil {
			return nil, fmt.Errorf("get size of section %s: %v", wasm.SectionIDName(sectionID), err)
		}

		var ok bool
		lastSectionID, ok = checkSectionOrder(sectionID, lastSectionID)
		if !ok {
			return nil, errors.New("invalid section order")
		}

		sectionContentStart := r.Len()
		switch sectionID {
		case wasm.SectionIDCustom:
			// Reject a section that claims more bytes than the module still
			// contains BEFORE decoding its name or payload: otherwise a
			// hostile length could drive a multi-gigabyte allocation for the
			// name buffer alone.
			if uint64(sectionSize) > uint64(r.Len()) {
				return nil, fmt.Errorf("section custom: declares %d bytes but %d remain: %w",
					sectionSize, r.Len(), customsection.ErrMalformedLength)
			}
			// First, validate the section and determine if the section for this name has already been set
			name, nameSize, decodeErr := decodeUTF8(r, "custom section name")
			if decodeErr != nil {
				err = decodeErr
				break
			} else if sectionSize < nameSize {
				err = fmt.Errorf("malformed custom section %s", name)
				break
			} else if name == "name" && m.NameSection != nil {
				err = fmt.Errorf("redundant custom section %s", name)
				break
			}

			// Now, either decode the NameSection or CustomSection
			limit := sectionSize - nameSize

			if name != "name" {
				if sectionIndex != nil {
					// The builder performs all length/overflow/limit checks
					// before allocating and consumes exactly `limit` bytes.
					_, ordinal, indexed, ingestErr := sectionIndex.Ingest(r, name, limit, false)
					if ingestErr != nil {
						return nil, fmt.Errorf("failed to read custom section name[%s]: %w", name, ingestErr)
					}
					if indexed && (storeCustomSections || dwarfEnabled) {
						exposedOrdinals = append(exposedOrdinals, ordinal)
						if dwarfEnabled {
							switch name {
							case ".debug_info", ".debug_line", ".debug_str", ".debug_abbrev", ".debug_ranges":
								dwarfOrdinals[name] = ordinal
							}
						}
					}
				} else if storeCustomSections || dwarfEnabled {
					var c *wasm.CustomSection
					c, err = decodeCustomSection(r, name, uint64(limit))
					if err != nil {
						return nil, fmt.Errorf("failed to read custom section name[%s]: %w", name, err)
					}
					m.CustomSections = append(m.CustomSections, c)
					if dwarfEnabled {
						switch name {
						case ".debug_info":
							info = c.Data
						case ".debug_line":
							line = c.Data
						case ".debug_str":
							str = c.Data
						case ".debug_abbrev":
							abbrev = c.Data
						case ".debug_ranges":
							ranges = c.Data
						}
					}
				} else {
					if _, err = io.CopyN(io.Discard, r, int64(limit)); err != nil {
						return nil, fmt.Errorf("failed to skip name[%s]: %w", name, err)
					}
				}
			} else if sectionIndex != nil {
				// The "name" section is always indexed and decoded from the
				// same payload bytes, so the decoded NameSection is identical
				// to the non-indexed path.
				payload, _, _, ingestErr := sectionIndex.Ingest(r, name, limit, true)
				if ingestErr != nil {
					return nil, fmt.Errorf("failed to read custom section name[%s]: %w", name, ingestErr)
				}
				m.NameSection, err = decodeNameSection(bytes.NewReader(payload), uint64(limit))
			} else {
				m.NameSection, err = decodeNameSection(r, uint64(limit))
			}
		case wasm.SectionIDType:
			m.TypeSection, err = decodeTypeSection(enabledFeatures, r)
		case wasm.SectionIDImport:
			m.ImportSection, m.ImportPerModule, m.ImportFunctionCount, m.ImportGlobalCount, m.ImportMemoryCount, m.ImportTableCount, m.ImportTagCount, err = decodeImportSection(r, memSizer, memoryLimitPages, enabledFeatures)
			if err != nil {
				return nil, err // avoid re-wrapping the error.
			}
		case wasm.SectionIDFunction:
			m.FunctionSection, err = decodeFunctionSection(r)
		case wasm.SectionIDTable:
			m.TableSection, err = decodeTableSection(r, enabledFeatures)
		case wasm.SectionIDMemory:
			m.MemorySection, err = decodeMemorySection(r, enabledFeatures, memSizer, memoryLimitPages)
		case wasm.SectionIDTag:
			if err := enabledFeatures.RequireEnabled(experimental.CoreFeaturesExceptionHandling); err != nil {
				return nil, fmt.Errorf("tag section not supported as %v", err)
			}
			m.TagSection, err = decodeTagSection(r)
		case wasm.SectionIDGlobal:
			if m.GlobalSection, err = decodeGlobalSection(r, enabledFeatures); err != nil {
				return nil, err // avoid re-wrapping the error.
			}
		case wasm.SectionIDExport:
			m.ExportSection, m.Exports, err = decodeExportSection(r)
		case wasm.SectionIDStart:
			m.StartSection, err = decodeStartSection(r)
		case wasm.SectionIDElement:
			m.ElementSection, err = decodeElementSection(r, enabledFeatures)
		case wasm.SectionIDCode:
			m.CodeSection, err = decodeCodeSection(r)
		case wasm.SectionIDData:
			m.DataSection, err = decodeDataSection(r, enabledFeatures)
		case wasm.SectionIDDataCount:
			if err := enabledFeatures.RequireEnabled(api.CoreFeatureBulkMemoryOperations); err != nil {
				return nil, fmt.Errorf("data count section not supported as %v", err)
			}
			m.DataCountSection, err = decodeDataCountSection(r)
		default:
			err = ErrInvalidSectionID
		}

		readBytes := sectionContentStart - r.Len()
		if err == nil && int(sectionSize) != readBytes {
			err = fmt.Errorf("invalid section length: expected to be %d but got %d", sectionSize, readBytes)
		}

		if err != nil {
			return nil, fmt.Errorf("section %s: %v", wasm.SectionIDName(sectionID), err)
		}
	}

	if sectionIndex != nil {
		// Freeze the index, then reconstruct m.CustomSections (and the DWARF
		// payloads) from fresh copies of the immutable storage so that the
		// decoded Module is byte-identical to the non-indexed code path.
		store := sectionIndex.Build()
		m.SetCustomSectionIndex(store)
		if storeCustomSections || dwarfEnabled {
			for _, ordinal := range exposedOrdinals {
				e, findErr := store.EntryByOrdinal(ordinal)
				if findErr != nil {
					return nil, fmt.Errorf("failed to read custom section ordinal %d: %w", ordinal, findErr)
				}
				data, copyErr := store.CopyAll(ordinal)
				if copyErr != nil {
					return nil, fmt.Errorf("failed to read custom section name[%s]: %w", e.Name(), copyErr)
				}
				m.CustomSections = append(m.CustomSections, &wasm.CustomSection{Name: e.Name(), Data: data})
			}
			if dwarfEnabled {
				copyDWARF := func(name string) []byte {
					if ordinal, ok := dwarfOrdinals[name]; ok {
						if data, copyErr := store.CopyAll(ordinal); copyErr == nil {
							return data
						}
					}
					return nil
				}
				info = copyDWARF(".debug_info")
				line = copyDWARF(".debug_line")
				str = copyDWARF(".debug_str")
				abbrev = copyDWARF(".debug_abbrev")
				ranges = copyDWARF(".debug_ranges")
			}
		}
	}

	if dwarfEnabled {
		d, _ := dwarf.New(abbrev, nil, nil, info, line, nil, ranges, str)
		m.DWARFLines = wasmdebug.NewDWARFLines(d)
	}

	functionCount, codeCount := m.SectionElementCount(wasm.SectionIDFunction), m.SectionElementCount(wasm.SectionIDCode)
	if functionCount != codeCount {
		return nil, fmt.Errorf("function and code section have inconsistent lengths: %d != %d", functionCount, codeCount)
	}
	return m, nil
}

func checkSectionOrder(current, previous wasm.SectionID) (byte, bool) {
	// https://webassembly.github.io/spec/core/binary/modules.html#binary-module

	// Custom sections can show up anywhere.
	if current == wasm.SectionIDCustom {
		return previous, true
	}

	// Tag section (ID 13) must come after Memory (5) and before Global (6).
	if current == wasm.SectionIDTag {
		return current, previous <= wasm.SectionIDMemory
	}
	if previous == wasm.SectionIDTag {
		return current, current >= wasm.SectionIDGlobal
	}

	// DataCount was introduced in Wasm 2.0.
	// It must come after Element and before Code.
	if current > wasm.SectionIDDataCount {
		return current, false
	}
	if current == wasm.SectionIDDataCount {
		return current, previous <= wasm.SectionIDElement
	}
	if previous == wasm.SectionIDDataCount {
		return current, current >= wasm.SectionIDCode
	}

	// Otherwise, strictly increasing order.
	return current, current > previous
}

// memorySizer derives min, capacity and max pages from decoded wasm.
type memorySizer func(minPages uint32, maxPages *uint32) (min uint32, capacity uint32, max uint32)

// newMemorySizer sets capacity to minPages unless max is defined and
// memoryCapacityFromMax is true.
func newMemorySizer(memoryLimitPages uint32, memoryCapacityFromMax bool) memorySizer {
	return func(minPages uint32, maxPages *uint32) (min, capacity, max uint32) {
		if maxPages != nil {
			// This is an invalid value: let it propagate, we will fail later.
			if *maxPages > wasm.MemoryLimitPages {
				return minPages, minPages, *maxPages
			}
			// This is a valid value, but it goes over the run-time limit: return the limit.
			if *maxPages > memoryLimitPages {
				if memoryCapacityFromMax {
					return minPages, memoryLimitPages, memoryLimitPages
				}
				return minPages, minPages, memoryLimitPages
			}
			if memoryCapacityFromMax {
				return minPages, *maxPages, *maxPages
			}
			return minPages, minPages, *maxPages
		}
		if memoryCapacityFromMax {
			return minPages, memoryLimitPages, memoryLimitPages
		}
		return minPages, minPages, memoryLimitPages
	}
}
