# CLAUDE.md - Firo Development Guide

## Project Overview

Firo is a privacy-focused cryptocurrency forked from Bitcoin Core, featuring zero-knowledge proof protocols (Spark, Lelantus), masternode infrastructure (LLMQ), and FiroPOW mining. Current version: **0.14.15.2**. Licensed under MIT.

## Build System

**CMake 3.22+** with **C++20** standard. No autotools.

### Quick Build (Linux)

```bash
# 1. Build dependencies
make -C depends -j$(nproc)

# 2. Configure and build
export HOST_TRIPLET=$(depends/config.guess)
cmake -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=$(pwd)/depends/$HOST_TRIPLET/toolchain.cmake \
  -DBUILD_TESTS=ON -DBUILD_GUI=ON -DENABLE_CRASH_HOOKS=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -S. -Bbuild
cd build && ninja
```

### Key CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_DAEMON` | ON | Build `firod` |
| `BUILD_GUI` | ON | Build `firo-qt` (requires Qt 6.7.3+) |
| `BUILD_CLI` | ON | Build `firo-cli` |
| `BUILD_TX` | ON | Build `firo-tx` |
| `BUILD_TESTS` | OFF | Build unit test suite |
| `ENABLE_WALLET` | ON | Wallet functionality |
| `WITH_ZMQ` | ON | ZeroMQ notifications |
| `ENABLE_CRASH_HOOKS` | ON | Stack trace generation |
| `CLIENT_VERSION_IS_RELEASE` | false | Release build flag |

### Build Outputs

Binaries go to `build/bin/`: `firod`, `firo-cli`, `firo-qt`, `firo-tx`

### Cross-Compilation

Use the `depends/` system with host triplets:
- Linux: `x86_64-pc-linux-gnu` (default), `aarch64-linux-gnu`
- Windows: `make -C depends HOST=x86_64-w64-mingw32`
- macOS: requires SDK in `depends/SDKs/`

### Docker Build

```bash
docker build . -t firo-local
docker run -d --name firod -v "${HOME}/.firo:/home/firod/.firo" firo-local
```

## Testing

### Unit Tests (Boost.Test)

```bash
cmake -Bbuild -DBUILD_TESTS=ON ...
cd build && ctest --output-on-failure
```

Test source: `src/test/` (~60 test files). Framework setup in `src/test/test_bitcoin.h`.

### Integration Tests (Python)

```bash
# Copy binaries where the test harness expects them
cp -rf build/bin/* build/src/
qa/pull-tester/rpc-tests.py -extended
```

Test scripts: `qa/rpc-tests/` (50+ Python scripts covering wallet, privacy protocols, masternodes, consensus).

### Test Networks

- `-testnet` for multi-node testing over the network
- `-regtest` for local single-node testing with on-demand block creation

## Repository Structure

```
src/                        # Main source code
├── libspark/               # Spark protocol (current privacy protocol) - ZK proofs, crypto primitives
├── spark/                  # Spark wallet integration and state management
├── liblelantus/            # Lelantus protocol (legacy privacy protocol)
├── wallet/                 # Full wallet implementation
├── rpc/                    # JSON-RPC API endpoints
├── qt/                     # Qt GUI wallet
├── evo/                    # Deterministic masternode lists, special transactions
├── llmq/                   # Long Living Masternode Quorums (chainlocks, instant send)
├── bls/                    # BLS signatures for quorum signing
├── bip47/                  # BIP47 payment codes
├── hdmint/                 # Hierarchical deterministic minting
├── crypto/                 # Cryptographic functions (SHA, HMAC, ChaCha20, Lyra2Z, ProgPoW)
├── consensus/              # Consensus rules and validation parameters
├── primitives/             # Block and transaction primitives
├── script/                 # Bitcoin script interpreter
├── policy/                 # Transaction policy (fees)
├── secp256k1/              # ECDSA library (subtree)
├── leveldb/                # Key-value storage (subtree)
├── univalue/               # JSON parsing (subtree)
├── test/                   # Unit tests
├── fuzz/                   # Fuzz testing
├── bench/                  # Benchmarks
├── config/                 # Build configuration headers
├── validation.cpp/h        # Core block/transaction validation (~6100 lines)
├── net.cpp/h               # Network layer
├── net_processing.cpp/h    # Peer protocol handling
├── init.cpp/h              # Application initialization
├── miner.cpp/h             # Block mining (FiroPOW)
├── pow.cpp/h               # Proof-of-Work consensus
├── chainparams.cpp/h       # Network parameters (mainnet/testnet/regtest)
└── firo_params.h           # Protocol parameters
depends/                    # Deterministic dependency build system
cmake/                      # CMake modules
contrib/                    # Auxiliary tools (gitian, guix, packaging, devtools)
qa/                         # Integration test suite
doc/                        # Documentation (build guides, developer notes, API docs)
share/                      # UI resources, scripts
```

## Coding Conventions

### Style Rules (from `src/.clang-format` and `doc/developer-notes.md`)

- **Indentation**: 4 spaces, no tabs
- **Braces**: Linux style - new line for namespaces, classes, functions; same line for control flow
- **No column limit** (ColumnLimit: 0)
- **Pointer alignment**: Left (`int* p`)
- **Prefer `++i`** over `i++`
- **Single-statement `if`** may omit braces on same line; otherwise braces required

```cpp
namespace foo
{
class Class
{
    bool Function(const std::string& s, int n)
    {
        for (int i = 0; i < n; ++i) {
            if (!Something()) return false;
            if (SomethingElse()) {
                DoMore();
            } else {
                DoLess();
            }
        }
        return true;
    }
}
}
```

### Naming Conventions

- **Classes**: `C` prefix (e.g., `CBlock`, `CTransaction`, `CKey`, `CWallet`)
- **Member variables**: `m_` prefix or no prefix with context
- **Boolean flags**: `f` prefix (e.g., `fCompressed`, `fValid`)
- **Constants**: `UPPER_CASE`
- **Functions**: `CamelCase` or `camelCase`
- **Header guards**: `#ifndef BITCOIN_<PATH>_<FILE>_H` (legacy Bitcoin naming preserved)

### Documentation

Use Doxygen-compatible comments:
```cpp
/**
 * Description of function.
 * @param[in] arg1    Description
 * @param[in] arg2    Description
 * @return Description
 * @pre Precondition
 */
bool Function(int arg1, const char* arg2)

int var; //!< Inline member description
```

### C++ Guidelines

- Use `std::string` over C string functions
- Use `.find()` on maps for reading, never `[]` (it inserts defaults)
- Use RAII (`unique_ptr`) for resource management
- Use `ParseInt32`, `ParseInt64`, `ParseDouble` from `utilstrencodings.h`
- Use explicitly signed/unsigned `char`, prefer `uint8_t`/`int8_t`
- Assertions must not have side effects
- Watch for out-of-bounds vector access; use `.data()` instead of `&v[0]`
- `-Wshadow` is enabled; avoid variable name shadowing
- New features should be exposed via RPC first, then GUI

### Threading

The codebase is multi-threaded using `LOCK`/`TRY_LOCK` macros. Compile with `-DDEBUG_LOCKORDER` to detect lock ordering issues. Key threads: `ThreadScriptCheck`, `ThreadImport`, `ThreadSocketHandler`, `ThreadMessageHandler`, `ThreadRPCServer`.

## CI/CD

GitHub Actions (`.github/workflows/ci-master.yml`):
- Triggers on all pushes and PRs to master (ignores `doc/**` and `README.md`)
- **Linux** (ubuntu-22.04): Release + Debug builds, unit tests, RPC integration tests
- **Windows** (cross-compile via MinGW): Release + Debug builds
- **macOS** (macos-latest): Release + Debug builds
- **Guix** reproducible builds for all platforms
- Uses ccache for build acceleration
- Dependencies cached via `actions/cache`

## Network Ports

| Network | P2P | RPC |
|---------|-----|-----|
| Mainnet | 8168 | 8888 |
| Testnet | 18168 | 18888 |
| Regtest | 18444 | 28888 |

## Key Privacy Protocols

- **Spark** (`libspark/`, `spark/`): Current privacy protocol using Bulletproofs++, Grootle proofs, Chaum proofs, AEAD encryption, Bech32 addresses
- **Lelantus** (`liblelantus/`): Legacy privacy protocol with joinsplit, range proofs, Schnorr proofs
- **BIP47** (`bip47/`): Reusable payment codes to prevent address reuse
- **Dandelion++**: Transaction propagation privacy (IP obscuring)

## Consensus

- **FiroPOW**: ProgPoW variant - GPU-friendly, ASIC-resistant proof of work
- **LLMQ Chainlocks**: Deterministic masternode quorums for chain finality
- **Instant Send**: Quorum-based instant transaction confirmation

## PR and Commit Conventions

- PR titles prefixed by area: `Consensus:`, `Net:`, `Qt:`, `Wallet:`, `RPC/REST/ZMQ:`, `Mining:`, `Tests:`, `Trivial:`, `Docs:`
- Commits should be atomic; don't mix formatting with logic changes
- Commit messages: short subject (50 chars max), blank line, detailed body
- Reference issues with `refs #1234` or `fixes #4321`
