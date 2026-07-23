# r2warp

A native radare2 plugin for the [WARP](https://github.com/Vector35/warp) signature format.

## Features

- Load WARP signature files (`.warp`)
- Create WARP signatures from analyzed binaries
- Match functions by GUID
- Apply matched function metadata (names, comments, types)
- Support for constraint-based disambiguation

## Installation

### Prerequisites

1. Rust toolchain (1.70+): https://rustup.rs/
2. radare2 (6.0+): https://github.com/radareorg/radare2

### From r2pm (recommended)

```bash
r2pm -Uci r2warp
```

### From source

```bash
make install
```

## Usage

### Commands

```bash
Usage: zw  # Manage WARP signatures
zw                list loaded WARP containers
zw?               show this help
zw load <file>    load WARP signature file (.warp)
zw save <file>    save current signatures to WARP file
zw match [addr]   match function at address
zw match -a       match all functions in binary
zw create [addr]  create WARP signature for function
zw create -a      create signatures for all functions
zw server [url]   show or set the WARP server for this session
zw auth [token]   show/set API key; use 'zw auth clear' to forget it
zw sources        list WARP server sources
zw source create <name>  create a writable WARP server source
zw pull [source-uuid] [--current]  fetch matching server signatures
zw push <source-uuid> [commit-name]  upload current signatures
zw test <binary>  test GUID generation against snapshot
zw info           show container/target info
zw clear          clear loaded containers
```

**Note:** WARP uses exact GUID matching which requires function boundaries to be known. When you run `zw match` or `zw create`, the plugin will automatically run minimal analysis (`aa`) if no functions are found in the binary. If you want deeper analysis beforehand, run `aa` or `aaa` manually.

### Examples

```bash
# Load a WARP signature file
zw load /path/to/signatures.warp

# Match all functions in the binary
zw match -a

# Match function at current address
zw match

# Create signatures for all functions
zw create -a

# Save to a WARP file
zw save output.warp
```

### WARP server

r2warp connects to `https://warp.binary.ninja` by default. Configure a different server or an API key for the current radare2 session with `zw server` and `zw auth`; both settings can also be supplied before starting radare2:

```bash
export R2WARP_SERVER_URL=https://warp.binary.ninja
export R2WARP_API_TOKEN='your-api-key'
```

`zw pull` analyzes the current binary as needed, queries the server with its function GUIDs, and loads any matching WARP signatures into the normal matcher. Unrestricted pulls only use sources tagged `official` or `trusted`; provide a source UUID to select a particular source, or `--current` to query only the function at the seek address. `zw push` uploads every signature currently in the container to the specified source; creating a source and pushing require an API key.

```bash
# Check the configured server and list visible sources
zw server
zw sources

# Pull matches for this binary, or only the current function from a source
zw pull
zw pull 01234567-89ab-cdef-0123-456789abcdef --current

# Create a source, then upload the signatures created or loaded in this session
zw source create my-signatures
zw push 01234567-89ab-cdef-0123-456789abcdef initial-import
```

## WARP Format

WARP uses UUIDv5-based function identification:

1. **Basic Block GUID**: UUIDv5 of instruction bytes (with relocatable addresses masked)
2. **Function GUID**: UUIDv5 of concatenated basic block GUIDs (sorted by address)

### Namespace UUIDs

- Basic Block: `0192a178-7a5f-7936-8653-3cbaa7d6afe7`
- Function: `0192a179-61ac-7cef-88ed-012296e9492f`
- Constraint: `019701f3-e89c-7afa-9181-371a5e98a576`

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                   radare2 (libr_core.so)                       │
└─────────────────────────────┬──────────────────────────────────┘
                              │ FFI
┌─────────────────────────────▼──────────────────────────────────┐
│              r2warp.so (Rust native plugin)                    │
├────────────────────────────────────────────────────────────────┤
│            RCorePlugin → zw command handler                    │
├────────────────────────────────────────────────────────────────┤
│  GUID Generator  │  WARP Container  │  r2 Integration          │
│  (UUIDv5)        │  (File I/O)      │  (FFI bindings)          │
└────────────────────────────────────────────────────────────────┘
```

## Roadmap

- [x] Plugin registration
- [x] Command handler (`zw` namespace)
- [x] GUID generation (UUIDv5)
- [x] WARP file loading (FlatBuffers)
- [x] WARP file saving
- [x] FlatBuffers I/O
- [x] Function matching
- [x] Metadata application (names, comments)
- [x] Progress display (interactive mode)
- [x] Constraint collection (adjacency + call sites)
- [x] Constraint matching (disambiguation)
- [x] Performance optimization (caching, batch fetch)
- [x] Network server support (status, source management, pull, push)
- [ ] GUID snapshot testing

## References

- [WARP](https://github.com/vector35/warp)
- [radare2](https://github.com/radareorg/radare2)
- [Binary Ninja WARP Plugin](https://github.com/Vector35/binaryninja-api/tree/dev/plugins/warp)
