# surf-tls-client

Go CFFI wrapper for the [enetx/surf](https://github.com/enetx/surf) HTTP client library, enabling Python integration via shared libraries.

## Overview

This repository provides a C Foreign Function Interface (CFFI) wrapper around the `surf` Go library, allowing Python applications to leverage surf's advanced HTTP capabilities including:

- TLS fingerprinting (JA3/JA4)
- HTTP/3 and QUIC support
- Browser impersonation
- Advanced proxy support

## Architecture

```
┌─────────────────────────────────┐
│  Python (surf-tls-client-python)│
│  - Uses ctypes to load .so/.dylib│
└──────────────┬──────────────────┘
               │ JSON over CFFI
┌──────────────▼──────────────────┐
│  cffi_dist/main.go               │
│  - C exports (request, freeMemory)│
│  - JSON marshaling/unmarshaling  │
└──────────────┬──────────────────┘
               │
┌──────────────▼──────────────────┐
│  cffi_src/                       │
│  - factory.go (client management)│
│  - types.go (data structures)    │
└──────────────┬──────────────────┘
               │
┌──────────────▼──────────────────┐
│  github.com/enetx/surf           │
│  - HTTP client implementation    │
└──────────────────────────────────┘
```

## Structure

- **`cffi_src/`** - Core Go logic for creating clients and building requests
- **`cffi_dist/`** - CFFI entry point that exports C functions for Python
- **`.github/workflows/`** - CI/CD for building cross-platform binaries

## Building

### Prerequisites

- Go 1.24+
- Local copy of `github.com/enetx/surf` (or it will be downloaded via go.mod)

### Local Build

```bash
cd cffi_dist
go build -buildmode=c-shared -o surf-tls-client.so
```

This will create:
- `surf-tls-client.so` (or `.dylib` on macOS, `.dll` on Windows)
- `surf-tls-client.h` (C header file)

### Cross-Platform Builds

The repository uses GitHub Actions to automatically build binaries for:
- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64)

Binaries are published as GitHub releases with version tags.

## Usage

This library is primarily used by the Python package `surf-tls-client-python`. The Python package downloads the appropriate binary for your platform automatically.

### For Python Developers

Install the Python package:
```bash
pip install surf-tls
```

The Python package will automatically download the correct binary from GitHub releases.

### For Go Developers

If you want to use this CFFI wrapper directly:

1. Build the shared library (see Building above)
2. Use the C header file (`surf-tls-client.h`) to call the exported functions
3. Functions available:
   - `request(requestParams *C.char) *C.char` - Execute HTTP request
   - `freeMemory(responseId *C.char)` - Free allocated memory
   - `destroySession(sessionId *C.char)` - Clean up session

## Development

### Module Structure

- `cffi_src/go.mod` - Module for core logic
- `cffi_dist/go.mod` - Module for CFFI exports (depends on cffi_src)
- `go.mod` - Root module (minimal, mainly for CI)

### Testing

```bash
# Test cffi_src
cd cffi_src
go test ./...

# Test cffi_dist (requires building first)
cd cffi_dist
go build -buildmode=c-shared -o test.so
```

## Releases

Releases are created automatically via GitHub Actions when tags are pushed:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow will:
1. Build binaries for all supported platforms
2. Create a GitHub release
3. Upload binaries as release assets

## Dependencies

- `github.com/enetx/surf` - HTTP client library
- `github.com/enetx/g` - Utility library
- `github.com/google/uuid` - UUID generation

## License

MIT License - see LICENSE file for details.

## Related Projects

- **Python Package**: [surf-tls-client-python](https://github.com/ClaritySolutionsLLC/surf-tls-client-python)
- **Upstream Library**: [enetx/surf](https://github.com/enetx/surf)
