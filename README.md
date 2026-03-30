# WARP radare2 Plugin

A native radare2 plugin for the WARP (https://github.com/Vector35/warp) signature format.

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

### Build

```bash
cd warp-r2
cargo build --release
```

### Install

```bash
# Linux/macOS
mkdir -p ~/.local/share/radare2/plugins
cp target/release/libcore_warp.so ~/.local/share/radare2/plugins/
# or on macOS:
# cp target/release/libcore_warp.dylib ~/.local/share/radare2/plugins/
```

## Usage

### Commands

```
zw               # List loaded WARP containers
zw load <file>   # Load WARP signature file
zw save <file>   # Save signatures to WARP file
zw match [addr]  # Match function at address (or all with -a)
zw create [addr] # Create WARP signature for function(s)
zw test <bin> <snap> # Test GUID generation
zw info          # Show container/target info
zw clear         # Clear loaded containers
zw help          # Show help
```

### Examples

```r2
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
│                   radare2 (libr_core.so)                        │
└─────────────────────────────┬──────────────────────────────────┘
                              │ FFI
┌─────────────────────────────▼──────────────────────────────────┐
│            core_warp.so (Rust native plugin)                    │
├────────────────────────────────────────────────────────────────┤
│  RCorePlugin → zw command handler                               │
├────────────────────────────────────────────────────────────────┤
│  GUID Generator  │  WARP Container  │  r2 Integration          │
│  (UUIDv5)        │  (File I/O)       │  (FFI bindings)          │
└────────────────────────────────────────────────────────────────┘
```

## Testing

```bash
# Run unit tests
cargo test

# Test with a binary
r2 -e core_warp=true /path/to/binary
[0x00000000]> zw load /path/to/msvcrt.warp
[0x00000000]> zw match -a
```

## Development Status

| Feature | Status |
|---------|--------|
| Plugin registration | ✅ Complete |
| Command handler | ✅ Complete |
| GUID generation | ✅ Complete |
| WARP file loading | 🟡 Basic (JSON fallback) |
| WARP file saving | ❌ TODO |
| FlatBuffers I/O | ❌ TODO |
| Constraint matching | ❌ TODO (Phase 5) |

## License

LGPL-3.0

## References

- [WARP Specification](https://github.com/vector35/warp)
- [radare2](https://github.com/radareorg/radare2)
- [Binary Ninja WARP Plugin](https://github.com/Vector35/binaryninja-api/tree/dev/plugins/warp)
