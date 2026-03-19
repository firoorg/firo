# AGENTS.md — Firo

## Project Overview

Firo (formerly Zcoin) is a privacy-focused cryptocurrency built on a fork of Bitcoin Core. It implements the **Lelantus Spark** privacy protocol, which provides high anonymity sets without trusted setup. Firo uses a hybrid Proof-of-Work and LLMQ Chainlocks consensus mechanism, with **FiroPOW** (a ProgPOW variant) as its mining algorithm targeting GPUs.

- **Language**: C++20 (with C11 for some components)
- **Build system**: CMake (minimum version 3.22)
- **License**: MIT
- **Current version**: 0.14.15.x
- **Network protocol version**: 90031

## Repository Structure

```
firo/
├── cmake/                  # CMake modules and scripts
├── contrib/                # Auxiliary tools (Guix, Gitian, deployment helpers)
│   └── guix/               # Reproducible (Guix) build system
├── depends/                # Cross-compilation dependency build system
├── doc/                    # Documentation (build guides, developer notes, release notes)
├── qa/                     # Functional / RPC test suite (Python)
│   ├── pull-tester/        # Test runner and test framework
│   │   └── test_framework/ # Python test framework (BitcoinTestFramework)
│   └── rpc-tests/          # Individual RPC / functional test scripts (~110 tests)
├── share/                  # Shared data files (man pages, examples)
├── src/                    # All C++ source code
│   ├── bip47/              # BIP47 reusable payment codes
│   ├── bls/                # BLS signature utilities
│   ├── bench/              # Benchmarks (Boost-based)
│   ├── consensus/          # Consensus rules (merkle, validation, params)
│   ├── crypto/             # Cryptographic primitives
│   │   ├── ctaes/          # Constant-time AES (subtree)
│   │   ├── Lyra2Z/         # Lyra2Z hash (legacy)
│   │   ├── MerkleTreeProof/# MTP algorithm
│   │   └── progpow/        # FiroPOW (ProgPOW variant)
│   ├── evo/                # Evolution layer — deterministic masternodes, provider txs, sporks
│   ├── fuzz/               # Fuzz testing harness
│   ├── hdmint/             # Hierarchical deterministic minting
│   ├── liblelantus/        # Lelantus cryptographic library
│   ├── libspark/           # Spark cryptographic library (proofs, keys, coins, transcripts)
│   ├── llmq/               # Long-Living Masternode Quorums (DKG, signing, chainlocks, InstantSend)
│   ├── policy/             # Transaction policy (fees, RBF)
│   ├── primitives/         # Core data structures (CBlock, CTransaction, mint/spend)
│   ├── qt/                 # Qt6 GUI wallet (firo-qt)
│   ├── rpc/                # RPC server and method implementations
│   ├── script/             # Script interpreter and signing
│   ├── secp256k1/          # libsecp256k1 (subtree)
│   ├── spark/              # Spark wallet and state management
│   ├── test/               # Unit tests (Boost.Test, ~75 test suites)
│   ├── wallet/             # Wallet implementation (BerkeleyDB, encryption, coin selection)
│   └── zmq/                # ZeroMQ notification interface
└── .github/
    └── workflows/          # GitHub Actions CI (ci-master.yml)
```

### Key Source Files

| File | Description |
|------|-------------|
| `src/validation.cpp` | Block and transaction validation (consensus-critical) |
| `src/net_processing.cpp` | P2P message handling and processing |
| `src/net.cpp` | Network connection management |
| `src/init.cpp` | Node initialization and shutdown |
| `src/miner.cpp` | Block template creation and mining |
| `src/chainparams.cpp` | Chain parameters for mainnet, testnet, devnet, regtest |
| `src/firo_params.h` | Firo-specific protocol constants |
| `src/lelantus.cpp` | Lelantus protocol integration |
| `src/sparkname.cpp` | Spark Names feature |
| `src/txmempool.cpp` | Transaction memory pool |
| `src/pow.cpp` | Proof-of-work validation (FiroPOW) |

### Output Binaries

| Binary | Description |
|--------|-------------|
| `firod` | Full node daemon |
| `firo-cli` | RPC command-line client |
| `firo-qt` | Qt6 GUI wallet |
| `firo-tx` | Transaction utility tool |

## Building

Firo uses a two-stage build process: first build dependencies via the `depends/` system, then configure and build the project with CMake.

### Prerequisites (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install python3 git curl build-essential cmake pkg-config
# For GUI wallet:
sudo apt-get install qttools5-dev qttools5-dev-tools libxcb-xkb-dev bison
```

### Full Build (Headless + Tests)

```bash
# 1. Build dependencies
cd depends
make -j$(nproc)
cd ..

# 2. Configure with CMake
cmake -B build \
  -DCMAKE_TOOLCHAIN_FILE=$(pwd)/depends/$(depends/config.guess)/toolchain.cmake \
  -DBUILD_GUI=OFF -DBUILD_CLI=ON -DBUILD_TESTS=ON

# 3. Build
cd build && make -j$(nproc)
```

### Full Build (With GUI)

```bash
cmake -B build \
  -DCMAKE_TOOLCHAIN_FILE=$(pwd)/depends/$(depends/config.guess)/toolchain.cmake \
  -DBUILD_GUI=ON -DBUILD_CLI=ON -DBUILD_TESTS=ON

cd build && make -j$(nproc)
```

### CMake Options

| Flag | Default | Description |
|------|---------|-------------|
| `BUILD_DAEMON` | `ON` | Build `firod` |
| `BUILD_GUI` | `ON` | Build `firo-qt` |
| `BUILD_CLI` | `ON` | Build `firo-cli` and `firo-tx` |
| `BUILD_TESTS` | `OFF` | Build unit test suite (`test_firo`) |
| `ENABLE_WALLET` | `ON` | Enable wallet functionality |
| `ENABLE_CRASH_HOOKS` | varies | Enable crash reporting / stack traces |
| `WITH_ZMQ` | `ON` | Enable ZeroMQ notifications |
| `CMAKE_BUILD_TYPE` | — | `Release`, `Debug`, `RelWithDebInfo` |

### Cross-Compilation

Build for other platforms by specifying `HOST` when building dependencies:

```bash
# Example: Windows 64-bit
cd depends
make HOST=x86_64-w64-mingw32 -j$(nproc)
cd ..
cmake -B build -DCMAKE_TOOLCHAIN_FILE=$(pwd)/depends/x86_64-w64-mingw32/toolchain.cmake ...
```

Supported targets: `x86_64-pc-linux-gnu`, `x86_64-w64-mingw32`, `aarch64-apple-darwin`, `arm-linux-gnueabihf`, `aarch64-linux-gnu`.

### Docker Build

```bash
docker build . -t firo-local
docker run -d --name firod -v "${HOME}/.firo:/home/firod/.firo" firo-local
```

## Testing

### Unit Tests

Unit tests use the **Boost.Test** framework. The test executable is `test_firo`, built when `BUILD_TESTS=ON`. Source files are in `src/test/`, with additional library-specific tests in `src/liblelantus/test/`, `src/libspark/test/`, `src/hdmint/test/`, and `src/wallet/test/`.

**Running all unit tests:**

```bash
cd build
ctest --output-on-failure
```

**Running a specific test suite:**

```bash
./bin/test_firo --run_test=<suite_name> --catch_system_error=no --log_level=test_suite -- DEBUG_LOG_OUT
```

For example: `./bin/test_firo --run_test=lelantus_tests`

**Adding a new unit test:**

1. Create a `.cpp` file in `src/test/` using `BOOST_AUTO_TEST_SUITE` or `BOOST_FIXTURE_TEST_SUITE`.
2. Add it to the `test_firo` target's source list in `src/test/CMakeLists.txt`.
3. CMake will auto-register it as a CTest test case by parsing the suite name.

### RPC / Functional Tests

Functional tests are Python scripts in `qa/rpc-tests/`. They use a custom test framework in `qa/pull-tester/test_framework/` built around `BitcoinTestFramework`. These tests launch actual `firod` instances in regtest mode and interact with them via RPC.

**Running all RPC tests:**

```bash
# Binaries must be in build/src/ for the test runner:
cp -rf build/bin/* build/src/
qa/pull-tester/rpc-tests.py -extended
```

**Running a specific RPC test:**

```bash
qa/rpc-tests/<test_name>.py
```

**Key environment variables:**

- `FIROD` — path to firod binary (defaults to `build/src/firod`)
- `FIROCLI` — path to firo-cli binary (defaults to `build/src/firo-cli`)

**RPC test categories include:** Spark mint/spend, Lelantus mint/spend, wallet operations, mempool behavior, P2P networking, LLMQ chainlocks, LLMQ InstantSend, DKG errors, masternode management, and more.

### Benchmarks

```bash
# Build with benchmarks
cmake -B build ... -DBUILD_BENCH=ON
cd build && make -j$(nproc)
./bin/bench_firo
```

### Fuzz Testing

Fuzz tests are in `src/fuzz/`. See `doc/fuzzing.md` for AFL setup instructions.

## Code Style and Conventions

The project has a `.clang-format` configuration at `src/.clang-format`. Full coding standards are in `doc/developer-notes.md`.

### Formatting Rules

- **Indentation**: 4 spaces, no tabs.
- **Braces**: Linux style — new line for namespaces, classes, and function definitions; same line for everything else (`if`, `for`, `while`, `else`).
- **No extra spaces** inside parentheses.
- **No space** after function names; one space after `if`, `for`, `while`.
- Prefer `++i` over `i++`.
- Single-statement `if` clauses may appear on the same line without braces. In all other cases, braces are required.

### C++ Guidelines

- **Standard**: C++20 (`CMAKE_CXX_STANDARD 20`).
- **No `using namespace`**: Always use fully qualified types (e.g., `std::string`, `std::vector`).
- **RAII**: Use `unique_ptr` for allocations. Avoid manual memory management.
- **Maps**: Never use `std::map[]` for reads — use `.find()` instead (avoids unintended insertions).
- **Strings**: Use `std::string`, avoid C string functions.
- **Number parsing**: Use `ParseInt32`, `ParseInt64`, `ParseUInt32`, `ParseUInt64`, `ParseDouble` from `utilstrencodings.h`.
- **Logging**: Use `LogPrint` (with category) or `LogPrintf` (without category). Do not confuse the two — tinyformat is type-safe but format mismatches cause runtime exceptions.
- **Chars**: Use `uint8_t` or `int8_t` instead of bare `char`.
- **Assertions**: Must not have side effects.
- **Shadowing**: The `-Wshadow` warning is enabled. Do not shadow variable names. In constructors, prefix arguments with `_` (e.g., `AddressBookPage(Mode _mode) : mode(_mode)`).

### Doxygen Comments

Use doxygen-compatible comment blocks:

```cpp
/**
 * Description of the function.
 * @param[in] arg1  Description of arg1
 * @param[in] arg2  Description of arg2
 * @pre Precondition
 */
bool Function(int arg1, const char* arg2)
```

For members: `int var; //!< Description` or `//! Description` above the member.

### Threading

- The codebase is multi-threaded. Use `LOCK` / `TRY_LOCK` macros for synchronization.
- Compile with `-DDEBUG_LOCKORDER` to detect potential deadlocks (enabled automatically in debug builds).
- Wrap `LOCK`/`TRY_LOCK` and the code that needs the lock in braces to scope the lock correctly.

## Network Configuration

| Network | P2P Port | RPC Port |
|---------|----------|----------|
| Mainnet | 8168 | 8888 |
| Testnet | 18168 | 18888 |
| Devnet | 38168 | 38888 |
| Regtest | 18444 | 28888 |

Use `-regtest` for local testing (blocks can be created on demand). Use `-testnet` for multi-machine testing over the internet.

## CI/CD

### GitHub Actions

The primary CI workflow is `.github/workflows/ci-master.yml`. It runs on all pushes and pull requests to `master`.

**Build matrix:**

| Platform | Build Types | Tests |
|----------|-------------|-------|
| Linux (Ubuntu 22.04) | Release, Debug | Unit tests + RPC tests |
| Windows (cross-compiled on Ubuntu) | Release, Debug | None (cross-compiled) |
| macOS | Release, Debug | None |

**Guix reproducible builds** also run in CI for: `x86_64-linux-gnu`, `aarch64-linux-gnu`, `x86_64-w64-mingw32`, `arm64-apple-darwin`, `x86_64-apple-darwin`.

### Jenkins

A `Jenkinsfile` is also available for CI via Docker (`firoorg/firo-builder-depends`).

## Pull Request Conventions

### PR Title Prefixes

PRs should be prefixed by the area they affect (from `CONTRIBUTING.md`):

- **Consensus** — consensus-critical code changes
- **Net** or **P2P** — peer-to-peer network code
- **RPC/REST/ZMQ** — RPC, REST, or ZMQ API changes
- **Wallet** — wallet code
- **Qt** — GUI changes
- **Mining** — mining code
- **Tests** — unit tests or QA tests
- **Docs** — documentation
- **Utils and libraries** — utilities and libraries
- **Scripts and tools** — scripts and tools
- **Trivial** — comments, whitespace, variable names, logging (no behavior change)

### PR Template

The PR template (`.github/pull_request_template.md`) expects:

1. **PR intention** — what the PR does, what change it introduces, what issue it solves.
2. **Code changes brief** — architectural, UX, or other changes that are hard to deduce from code.

### Commit Guidelines

- Atomic commits with readable diffs.
- Do not mix formatting changes with functional changes.
- Subject line ≤50 chars, followed by a blank line and detailed explanatory text.
- Reference issues with `refs #1234` or `fixes #4321`.

## Subtrees

Several directories are subtrees of upstream projects:

| Directory | Upstream | Notes |
|-----------|----------|-------|
| `src/leveldb` | google/leveldb | Maintained by Google |
| `src/secp256k1` | bitcoin-core/secp256k1 | Actively maintained by Bitcoin Core |
| `src/crypto/ctaes` | bitcoin-core/ctaes | Actively maintained by Bitcoin Core |
| `src/univalue` | jgarzik/univalue | JSON parsing library |

Changes to subtrees should ideally be sent upstream first. Use `contrib/devtools/git-subtree-check.sh` to verify subtree consistency.

## Key Architectural Concepts

### Privacy Protocols

- **Lelantus** (`src/liblelantus/`, `src/lelantus.cpp`): The earlier privacy protocol using one-out-of-many proofs for anonymous transactions. Still supported for backward compatibility.
- **Lelantus Spark** (`src/libspark/`, `src/spark/`): The current privacy protocol providing full sender/receiver privacy with no trusted setup. Includes Spark addresses, Spark names, and view keys.

### Masternodes and Quorums

- **Deterministic Masternodes** (`src/evo/`): Registration, updates, and management of masternodes on-chain.
- **LLMQ** (`src/llmq/`): Long-Living Masternode Quorums handling Distributed Key Generation (DKG), threshold signing, ChainLocks (instant block finality), and InstantSend (instant transaction confirmation).

### Mining

- **FiroPOW** (`src/crypto/progpow/`, `src/pow.cpp`): A ProgPOW variant designed to be GPU-friendly and ASIC/FPGA-resistant.

### Wallet

- **Wallet** (`src/wallet/`): Full wallet with BerkeleyDB storage, BIP39 mnemonic support, HD key derivation, Lelantus/Spark minting and spending, coin control, and encryption.
- **BIP47** (`src/bip47/`): Reusable payment codes for enhanced privacy.
