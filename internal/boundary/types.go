package boundary

// Sig is a canonical import or export function signature recorded in the
// manifest.
type Sig struct {
	// Import is true for imported functions, false for exported ones.
	Import bool
	// Module is the import module name (empty for exports).
	Module string
	// Name is the import/export name.
	Name string
	// Params and Results are the api.ValueType encoded signatures.
	Params  []byte
	Results []byte
}

// Manifest is the module identity record validated before replay starts.
type Manifest struct {
	// ModuleSHA is the SHA-256 of the exact wasm binary compiled.
	ModuleSHA [32]byte
	// Sigs are the canonical imported/exported function signatures.
	Sigs []Sig
}

// RuntimeFP is the runtime configuration fingerprint validated before
// replay starts.
type RuntimeFP struct {
	// Engine is the concrete engine type (compiler or interpreter).
	Engine string
	// CoreFeatures is the enabled api.CoreFeatures bitmask.
	CoreFeatures uint64
	// MemoryLimitPages is the configured memory page limit.
	MemoryLimitPages uint32
	// MemoryCapacityFromMax mirrors RuntimeConfig.
	MemoryCapacityFromMax bool
	// EnsureTermination mirrors RuntimeConfig (close on context done).
	EnsureTermination bool
}

// ConfigFP is the module configuration fingerprint validated before replay
// starts.
type ConfigFP struct {
	Name    string
	NameSet bool
	// StartFunctions are the functions invoked on instantiation.
	StartFunctions []string
	Args           [][]byte
	// Environ is pair-indexed key/value entries like os.Environ.
	Environ [][]byte
	// GuestPaths are the configured preopen guest paths.
	GuestPaths []string
	// Clock resolutions in nanoseconds.
	WalltimeResolution uint64
	NanotimeResolution uint64
	// Presence of custom (host-provided) resources. Nil defaults are fake,
	// deterministic wazero defaults and therefore part of the fingerprint.
	HasCustomWalltime  bool
	HasCustomNanotime  bool
	HasCustomNanosleep bool
	HasRandSource      bool
	HasStdin           bool
	HasStdout          bool
	HasStderr          bool
	HasTCPListeners    bool
}
