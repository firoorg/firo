# AGENTS.md - Firo repository guide

This file is a concise guide for coding agents working in the Firo repository. It is intentionally practical: use it to orient yourself quickly, choose the right build and test commands, and avoid risky changes in consensus- or wallet-sensitive code.

## Project snapshot

- Privacy-focused cryptocurrency forked from Bitcoin Core
- Current version in `CMakeLists.txt`: `0.14.15.3`
- Languages: C++20 and C11
- Build system: CMake 3.22+ with out-of-tree builds only
- Main executables:
  - `firod`
  - `firo-cli`
  - `firo-tx`
  - `firo-qt`

Core features include Spark and Lelantus privacy protocols, deterministic masternodes, LLMQ-based ChainLocks and InstantSend, BIP47 payment codes, and FiroPOW mining.

## Repository map

Top-level directories you will touch most often:

- `src/` - production C++ code
- `src/test/` - Boost unit tests
- `src/wallet/test/`, `src/libspark/test/`, `src/liblelantus/test/`, `src/hdmint/test/` - domain-specific unit tests
- `qa/rpc-tests/` - Python functional tests
- `qa/pull-tester/` - functional test runner and framework
- `depends/` - deterministic dependency build system and cross-compilation support
- `cmake/` - CMake modules and helper logic
- `doc/` - developer notes and build documentation
- `.github/workflows/ci-master.yml` - main CI pipeline

Important source areas:

- `src/validation.cpp` - block and transaction validation, consensus-critical
- `src/net_processing.cpp` / `src/net.cpp` - peer-to-peer networking
- `src/init.cpp` - startup and shutdown wiring
- `src/miner.cpp` / `src/pow.cpp` - mining and proof-of-work logic
- `src/chainparams.cpp` - network configuration
- `src/txmempool.cpp` - mempool behavior
- `src/wallet/` - wallet storage, RPC, coin selection, privacy spends
- `src/libspark/`, `src/spark/` - current privacy protocol
- `src/liblelantus/` - legacy privacy protocol
- `src/evo/`, `src/llmq/` - masternodes, quorums, ChainLocks, InstantSend

## Build quickstart

Firo uses a two-stage build:

1. Build dependencies with `depends/`
2. Configure and build with CMake

Preferred Linux build matching CI:

```bash
make -C depends -j$(nproc)

export HOST_TRIPLET=$(depends/config.guess)
env PKG_CONFIG_PATH="$(realpath depends/$HOST_TRIPLET/lib/pkgconfig):$PKG_CONFIG_PATH" \
cmake -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$(realpath depends/$HOST_TRIPLET/toolchain.cmake)" \
  -DBUILD_CLI=ON \
  -DBUILD_DAEMON=ON \
  -DBUILD_GUI=ON \
  -DBUILD_TESTS=ON \
  -DENABLE_CRASH_HOOKS=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -S "$(pwd)" \
  -B "$(pwd)/build"

cmake --build build
```

Headless build:

```bash
cmake -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$(realpath depends/$HOST_TRIPLET/toolchain.cmake)" \
  -DBUILD_GUI=OFF \
  -DBUILD_CLI=ON \
  -DBUILD_DAEMON=ON \
  -DBUILD_TESTS=ON \
  -S "$(pwd)" \
  -B "$(pwd)/build"
cmake --build build
```

Useful CMake options:

| Option | Default | Notes |
|--------|---------|-------|
| `BUILD_DAEMON` | `ON` | Builds `firod` |
| `BUILD_GUI` | `ON` | Builds `firo-qt`; requires Qt `6.7.3` |
| `BUILD_CLI` | `ON` | Builds `firo-cli` |
| `BUILD_TX` | `${BUILD_CLI}` | Builds `firo-tx` |
| `BUILD_TESTS` | `OFF` | Builds `test_firo` and test targets |
| `BUILD_BENCH` | `OFF` | Builds `bench_firo` |
| `ENABLE_WALLET` | `ON` | Wallet support |
| `WITH_BDB` | `OFF` | Legacy Berkeley DB wallet support |
| `WITH_ZMQ` | `ON` | ZMQ notification support |
| `ENABLE_CRASH_HOOKS` | config-dependent | Enabled by default for release-like single-config builds |
| `CLIENT_VERSION_IS_RELEASE` | `false` | Set in CI per build type |

Build outputs are placed under `build/bin/` and libraries under `build/lib/`.

### Cross-compilation

`depends/` supports multiple host triplets. Typical examples:

- Native Linux: `$(depends/config.guess)`
- Windows: `x86_64-w64-mingw32`
- Linux ARM64: `aarch64-linux-gnu`
- macOS cross-builds require an SDK in `depends/SDKs/`

Example Windows dependency build:

```bash
make -C depends HOST=x86_64-w64-mingw32 -j$(nproc)
```

## Testing

Always run the most targeted tests that cover your change. For high-risk areas such as consensus, wallet accounting, Spark/Lelantus logic, or networking, broaden coverage before finishing.

### Unit tests

Build with `-DBUILD_TESTS=ON`, then run:

```bash
cd build
ctest --output-on-failure
```

Run a specific Boost test suite:

```bash
./bin/test_firo --run_test=<suite_name> --catch_system_error=no --log_level=test_suite -- DEBUG_LOG_OUT
```

Examples:

- `./bin/test_firo --run_test=lelantus_tests`
- `./bin/test_firo --run_test=spark_wallet_tests`

Test registration is driven from `src/test/CMakeLists.txt`.

### Functional / RPC tests

Functional tests live under `qa/rpc-tests/` and launch real `firod` nodes in regtest mode.

Before running the harness, copy binaries where the test framework expects them:

```bash
cp -rf build/bin/* build/src/
qa/pull-tester/rpc-tests.py -extended
```

Run a single script directly:

```bash
qa/rpc-tests/<test_name>.py
```

Useful environment variables:

- `FIROD` - defaults to `build/src/firod`
- `FIROCLI` - defaults to `build/src/firo-cli`

### Benchmarks and fuzzing

Benchmarks:

```bash
cmake -B build -DBUILD_BENCH=ON ...
cmake --build build
./build/bin/bench_firo
```

Fuzz targets live in `src/fuzz/`. See `doc/fuzzing.md` for setup details.

## CI reference

The main workflow is `.github/workflows/ci-master.yml`.

Current CI behavior:

- Runs on pushes to all branches and PRs targeting `master`
- Ignores `doc/**` and `**/README.md`
- Linux matrix: Release and Debug, with unit tests and RPC tests
- Windows matrix: Release and Debug cross-builds on Ubuntu
- macOS matrix: Release and Debug builds
- Uses `ccache`
- Caches `depends/` artifacts

If you want to reproduce CI most closely, use Ninja, the `depends/` toolchain, and the same build flags shown above.

## Coding conventions

Source of truth:

- `src/.clang-format`
- `doc/developer-notes.md`

Important rules:

- 4-space indentation, no tabs
- Linux brace style: new line for namespaces, classes, and function definitions
- No column limit in formatting rules
- Prefer `++i` over `i++`
- Avoid `using namespace`
- Use RAII and smart pointers instead of manual ownership
- Use `std::string` instead of C string APIs where practical
- Use `.find()` on maps for reads; avoid `operator[]` when it would insert
- Use `ParseInt32`, `ParseInt64`, `ParseUInt32`, `ParseUInt64`, and `ParseDouble` from `utilstrencodings.h`
- Avoid variable shadowing; `-Wshadow` is enabled
- Use `uint8_t` or `int8_t` instead of plain `char` when signedness matters
- Assertions must not have side effects

Threading and locking:

- Use `LOCK` / `TRY_LOCK` macros
- Scope lock regions carefully with braces
- Debug builds can help surface lock-order issues

Documentation style:

- Prefer Doxygen-compatible comments for non-obvious public interfaces
- Use succinct comments for tricky logic, not commentary on obvious assignments

## Risk areas and change guidance

Be especially careful in these parts of the tree:

- Consensus and validation: `src/validation.cpp`, `src/consensus/`, `src/pow.cpp`
- Chain parameters and network selection: `src/chainparams.cpp`
- Mempool and relay behavior: `src/txmempool.cpp`, `src/net_processing.cpp`
- Wallet correctness and privacy spends: `src/wallet/`, `src/spark/`, `src/liblelantus/`, `src/libspark/`
- LLMQ / masternodes: `src/llmq/`, `src/evo/`

Guidelines for agents:

- Keep changes minimal and localized
- Do not mix pure formatting changes with behavior changes
- Add or update tests when behavior changes
- Treat privacy, consensus, wallet balance accounting, serialization, and networking as high-regression areas
- Prefer exposing new behavior through RPC before adding GUI surfaces
- When touching a subtree directory such as `src/secp256k1`, `src/leveldb`, `src/univalue`, or `src/crypto/ctaes`, verify whether the change belongs upstream

## Network ports

| Network | P2P | RPC |
|---------|-----|-----|
| Mainnet | 8168 | 8888 |
| Testnet | 18168 | 18888 |
| Devnet | 38168 | 38888 |
| Regtest | 18444 | 28888 |

Use `-regtest` for local multi-node functional testing and `-testnet` for public test network behavior.

## PR and commit conventions

Preferred PR title prefixes:

- `Consensus:`
- `Net:` or `P2P:`
- `RPC/REST/ZMQ:`
- `Wallet:`
- `Qt:`
- `Mining:`
- `Tests:`
- `Docs:`
- `Utils and libraries:`
- `Scripts and tools:`
- `Trivial:`

PR template: `.github/pull_request_template.md`

It expects:

1. `## PR intention`
2. `## Code changes brief`

Commit guidance:

- Keep commits atomic
- Do not mix formatting-only changes into logic commits
- Use a short subject line, ideally 50 characters or less
- Add a blank line before the body when a body is needed
- Reference issues with `refs #1234`, `fixes #1234`, or similar when applicable

## Related docs worth reading

- `CLAUDE.md`
- `doc/developer-notes.md`
- `.github/workflows/ci-master.yml`
- `src/.clang-format`
- `doc/fuzzing.md`
