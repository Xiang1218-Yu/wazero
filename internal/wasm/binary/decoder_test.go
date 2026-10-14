package binary

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/internal/testing/binaryencoding"
	"github.com/tetratelabs/wazero/internal/testing/dwarftestdata"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
	"github.com/tetratelabs/wazero/internal/wasm/customsection"
)

// TestDecodeModule relies on unit tests for Module.Encode, specifically that the encoding is both known and correct.
// This avoids having to copy/paste or share variables to assert against byte arrays.
func TestDecodeModule(t *testing.T) {
	i32, f32 := wasm.ValueTypeI32, wasm.ValueTypeF32
	zero := uint32(0)

	tests := []struct {
		name  string
		input *wasm.Module // round trip test!
	}{
		{
			name:  "empty",
			input: &wasm.Module{},
		},
		{
			name:  "only name section",
			input: &wasm.Module{NameSection: &wasm.NameSection{ModuleName: "simple"}},
		},
		{
			name: "type section",
			input: &wasm.Module{
				TypeSection: []wasm.FunctionType{
					{},
					{Params: []wasm.ValueType{i32, i32}, Results: []wasm.ValueType{i32}},
					{Params: []wasm.ValueType{i32, i32, i32, i32}, Results: []wasm.ValueType{i32}},
				},
			},
		},
		{
			name: "type and import section",
			input: &wasm.Module{
				ImportFunctionCount: 2,
				ImportTableCount:    1,
				ImportMemoryCount:   1,
				ImportGlobalCount:   3,
				TypeSection: []wasm.FunctionType{
					{Params: []wasm.ValueType{i32, i32}, Results: []wasm.ValueType{i32}},
					{Params: []wasm.ValueType{f32, f32}, Results: []wasm.ValueType{f32}},
				},
				ImportSection: []wasm.Import{
					{
						Module: "Math", Name: "Mul",
						Type:         wasm.ExternTypeFunc,
						DescFunc:     1,
						IndexPerType: 0,
					},
					{
						Module: "foo", Name: "bar",
						Type:         wasm.ExternTypeTable,
						DescTable:    wasm.Table{Type: wasm.ValueTypeFuncref},
						IndexPerType: 0,
					},
					{
						Module: "Math", Name: "Add",
						Type:         wasm.ExternTypeFunc,
						DescFunc:     0,
						IndexPerType: 1,
					},
					{
						Module: "bar", Name: "mem",
						Type:         wasm.ExternTypeMemory,
						DescMem:      &wasm.Memory{IsMaxEncoded: true},
						IndexPerType: 0,
					},
					{
						Module: "foo", Name: "bar2",
						Type:         wasm.ExternTypeGlobal,
						DescGlobal:   wasm.GlobalType{ValType: wasm.ValueTypeI32},
						IndexPerType: 0,
					},
					{
						Module: "foo", Name: "bar3",
						Type:         wasm.ExternTypeGlobal,
						DescGlobal:   wasm.GlobalType{ValType: wasm.ValueTypeI32},
						IndexPerType: 1,
					},
					{
						Module: "foo", Name: "bar4",
						Type:         wasm.ExternTypeGlobal,
						DescGlobal:   wasm.GlobalType{ValType: wasm.ValueTypeI32},
						IndexPerType: 2,
					},
				},
			},
		},
		{
			name: "table and memory section",
			input: &wasm.Module{
				TableSection:  []wasm.Table{{Min: 3, Type: wasm.RefTypeFuncref}},
				MemorySection: &wasm.Memory{Min: 1, Cap: 1, Max: 1, IsMaxEncoded: true},
			},
		},
		{
			name: "type function and start section",
			input: &wasm.Module{
				ImportFunctionCount: 1,
				TypeSection:         []wasm.FunctionType{{}},
				ImportSection: []wasm.Import{{
					Module: "", Name: "hello",
					Type:     wasm.ExternTypeFunc,
					DescFunc: 0,
				}},
				StartSection: &zero,
			},
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			m, e := DecodeModule(binaryencoding.EncodeModule(tc.input), api.CoreFeaturesV1, wasm.MemoryLimitPages, false, false, false, nil)
			require.NoError(t, e)
			// Set the FunctionType keys on the input.
			for i := range tc.input.TypeSection {
				tp := &(tc.input.TypeSection)[i]
				_ = tp.String()
			}
			if len(tc.input.ImportSection) > 0 {
				expImportPerModule := make(map[string][]*wasm.Import)
				for i := range m.ImportSection {
					imp := &m.ImportSection[i]
					expImportPerModule[imp.Module] = append(expImportPerModule[imp.Module], imp)
				}
				tc.input.ImportPerModule = expImportPerModule
			}
			require.Equal(t, tc.input, m)
		})
	}

	t.Run("skips custom section", func(t *testing.T) {
		input := append(append(Magic, version...),
			wasm.SectionIDCustom, 0xf, // 15 bytes in this section
			0x04, 'm', 'e', 'm', 'e',
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0)
		m, e := DecodeModule(input, api.CoreFeaturesV1, wasm.MemoryLimitPages, false, false, false, nil)
		require.NoError(t, e)
		require.Equal(t, &wasm.Module{}, m)
	})

	t.Run("reads custom sections", func(t *testing.T) {
		input := append(append(Magic, version...),
			wasm.SectionIDCustom, 0xf, // 15 bytes in this section
			0x04, 'm', 'e', 'm', 'e',
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0)
		m, e := DecodeModule(input, api.CoreFeaturesV2, wasm.MemoryLimitPages, false, false, true, nil)
		require.NoError(t, e)
		require.Equal(t, &wasm.Module{
			CustomSections: []*wasm.CustomSection{
				{
					Name: "meme",
					Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
				},
			},
		}, m)
	})

	t.Run("skips custom section, but not name", func(t *testing.T) {
		input := append(append(Magic, version...),
			wasm.SectionIDCustom, 0xf, // 15 bytes in this section
			0x04, 'm', 'e', 'm', 'e',
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
			wasm.SectionIDCustom, 0x0e, // 14 bytes in this section
			0x04, 'n', 'a', 'm', 'e',
			subsectionIDModuleName, 0x07, // 7 bytes in this subsection
			0x06, // the Module name simple is 6 bytes long
			's', 'i', 'm', 'p', 'l', 'e')
		m, e := DecodeModule(input, api.CoreFeaturesV1, wasm.MemoryLimitPages, false, false, false, nil)
		require.NoError(t, e)
		require.Equal(t, &wasm.Module{NameSection: &wasm.NameSection{ModuleName: "simple"}}, m)
	})

	t.Run("read custom sections and name separately", func(t *testing.T) {
		input := append(append(Magic, version...),
			wasm.SectionIDCustom, 0xf, // 15 bytes in this section
			0x04, 'm', 'e', 'm', 'e',
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
			wasm.SectionIDCustom, 0x0e, // 14 bytes in this section
			0x04, 'n', 'a', 'm', 'e',
			subsectionIDModuleName, 0x07, // 7 bytes in this subsection
			0x06, // the Module name simple is 6 bytes long
			's', 'i', 'm', 'p', 'l', 'e')
		m, e := DecodeModule(input, api.CoreFeaturesV2, wasm.MemoryLimitPages, false, false, true, nil)
		require.NoError(t, e)
		require.Equal(t, &wasm.Module{
			NameSection: &wasm.NameSection{ModuleName: "simple"},
			CustomSections: []*wasm.CustomSection{
				{
					Name: "meme",
					Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
				},
			},
		}, m)
	})

	t.Run("DWARF enabled", func(t *testing.T) {
		m, err := DecodeModule(dwarftestdata.ZigWasm, api.CoreFeaturesV2, wasm.MemoryLimitPages, false, true, true, nil)
		require.NoError(t, err)
		require.NotNil(t, m.DWARFLines)
	})

	t.Run("DWARF disabled", func(t *testing.T) {
		m, err := DecodeModule(dwarftestdata.ZigWasm, api.CoreFeaturesV2, wasm.MemoryLimitPages, false, false, true, nil)
		require.NoError(t, err)
		require.Nil(t, m.DWARFLines)
	})

	t.Run("data count section disabled", func(t *testing.T) {
		input := append(append(Magic, version...),
			wasm.SectionIDDataCount, 1, 0)
		_, e := DecodeModule(input, api.CoreFeaturesV1, wasm.MemoryLimitPages, false, false, false, nil)
		require.EqualError(t, e, `data count section not supported as feature "bulk-memory-operations" is disabled`)
	})
}

func TestDecodeModule_Errors(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectedErr string
	}{
		{
			name:        "wrong magic",
			input:       []byte("wasm\x01\x00\x00\x00"),
			expectedErr: "invalid magic number",
		},
		{
			name:        "wrong version",
			input:       []byte("\x00asm\x01\x00\x00\x01"),
			expectedErr: "invalid version header",
		},
		{
			name: "invalid section order",
			input: append(append(Magic, version...),
				wasm.SectionIDType, 4, 1, 0x60, 0, 0,
				wasm.SectionIDFunction, 2, 1, 0,
				wasm.SectionIDCode, 4, 1,
				2, 0, wasm.OpcodeEnd,
				wasm.SectionIDStart, 1, 0,
				wasm.SectionIDStart, 1, 0,
			),
			expectedErr: `invalid section order`,
		},
		{
			name: "redundant name section",
			input: append(append(Magic, version...),
				wasm.SectionIDCustom, 0x09, // 9 bytes in this section
				0x04, 'n', 'a', 'm', 'e',
				subsectionIDModuleName, 0x02, 0x01, 'x',
				wasm.SectionIDCustom, 0x09, // 9 bytes in this section
				0x04, 'n', 'a', 'm', 'e',
				subsectionIDModuleName, 0x02, 0x01, 'x'),
			expectedErr: "section custom: redundant custom section name",
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			_, e := DecodeModule(tc.input, api.CoreFeaturesV1, wasm.MemoryLimitPages, false, false, false, nil)
			require.EqualError(t, e, tc.expectedErr)
		})
	}
}

// TestDecodeModule_CustomSectionIndexParity ensures enabling the index
// produces the same decoded sections and DWARF data as the legacy path.
func TestDecodeModule_CustomSectionIndexParity(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		dwarf, storeSections bool
	}{
		{name: "dwarf and stored", dwarf: true, storeSections: true},
		{name: "dwarf only", dwarf: true, storeSections: false},
		{name: "stored only", dwarf: false, storeSections: true},
		{name: "neither", dwarf: false, storeSections: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain, err := DecodeModule(dwarftestdata.ZigWasm, api.CoreFeaturesV2, wasm.MemoryLimitPages,
				false, tc.dwarf, tc.storeSections, nil)
			require.NoError(t, err)

			b, err := customsection.NewBuilder(customsection.Config{}, nil)
			require.NoError(t, err)
			indexed, err := DecodeModule(dwarftestdata.ZigWasm, api.CoreFeaturesV2, wasm.MemoryLimitPages,
				false, tc.dwarf, tc.storeSections, b)
			require.NoError(t, err)

			// Legacy CustomSections are byte-identical.
			require.Equal(t, len(plain.CustomSections), len(indexed.CustomSections))
			for i, want := range plain.CustomSections {
				got := indexed.CustomSections[i]
				require.Equal(t, want.Name, got.Name)
				require.Equal(t, want.Data, got.Data)
			}
			require.Equal(t, plain.NameSection, indexed.NameSection)
			if tc.dwarf {
				require.NotNil(t, indexed.DWARFLines)
			} else {
				require.Nil(t, indexed.DWARFLines)
			}

			store := indexed.CustomSectionIndex()
			require.NotNil(t, store)
			// Every indexed payload hashes to its recorded digest and every
			// stored legacy section matches an indexed section by content.
			for _, e := range store.All() {
				data, copyErr := store.CopyAll(e.Ordinal())
				require.NoError(t, copyErr)
				sum := sha256.Sum256(data)
				require.Equal(t, sum[:], e.Digest())
				require.Equal(t, len(data), e.Length())
			}
			stored := map[string][][]byte{}
			for _, cs := range indexed.CustomSections {
				stored[cs.Name] = append(stored[cs.Name], cs.Data)
			}
			for _, e := range store.All() {
				if e.Name() == "name" {
					continue
				}
				data, copyErr := store.CopyAll(e.Ordinal())
				require.NoError(t, copyErr)
				var matched bool
				for _, candidate := range stored[e.Name()] {
					if bytes.Equal(candidate, data) {
						matched = true
					}
				}
				if len(stored[e.Name()]) > 0 && !matched {
					t.Fatalf("indexed section %q not reflected in CustomSections", e.Name())
				}
			}
		})
	}
}

// TestDecodeModule_NoIndexByDefault ensures the index stays nil unless built.
func TestDecodeModule_NoIndexByDefault(t *testing.T) {
	m, err := DecodeModule(dwarftestdata.ZigWasm, api.CoreFeaturesV2, wasm.MemoryLimitPages,
		false, false, false, nil)
	require.NoError(t, err)
	require.Nil(t, m.CustomSectionIndex())
}

// TestDecodeModule_MaliciousCustomSectionLength makes sure a hostile length
// field fails before large allocation, whether or not the index is enabled.
func TestDecodeModule_MaliciousCustomSectionLength(t *testing.T) {
	input := append(Magic, version...)
	input = append(input, 0x00)
	input = append(input, 0xff, 0xff, 0xff, 0xff, 0x0f) // section size = MaxUint32
	input = append(input, 0xff, 0xff, 0xff, 0xff, 0x0f) // name size = MaxUint32

	for _, builder := range []*customsection.Builder{nil, mustNewBuilder(t)} {
		_, err := DecodeModule(input, api.CoreFeaturesV2, wasm.MemoryLimitPages,
			false, false, false, builder)
		require.ErrorIs(t, err, customsection.ErrMalformedLength)
	}
}

func mustNewBuilder(t *testing.T) *customsection.Builder {
	t.Helper()
	b, err := customsection.NewBuilder(customsection.Config{}, nil)
	require.NoError(t, err)
	return b
}
