# Firo security scan

Firo is a privacy-focused cryptocurrency. Its nodes and wallets process untrusted
peer messages, blocks, transactions and cryptographic proofs while protecting
user funds, private keys, transaction privacy and consensus integrity. Firo has
substantial independent functionality beyond its Bitcoin ancestry, including
Spark and Lelantus privacy protocols, FiroPOW, deterministic masternodes and LLMQs.

## Scope and trust boundaries

Scan the current `master` branch of `firoorg/firo`. Prioritize:

- P2P message parsing, serialization, peer state and resource exhaustion in
  `src/net*`, `src/streams.h` and related code.
- Transaction, block, mempool and consensus validation in `src/validation.cpp`,
  `src/consensus/` and related code, including inflation and double spending.
- Proof verification and privacy in `src/libspark/`, `src/spark/`,
  `src/liblelantus/` and their wallet integration.
- Wallet key handling, persistence and accounting in `src/wallet/`, and
  RPC/REST input handling in `src/rpc/` and `src/wallet/rpc*`.
- Deterministic masternodes, quorum messages, ChainLocks and InstantSend in
  `src/evo/` and `src/llmq/`.

Distinguish unauthenticated remote inputs from authenticated RPC access and local
filesystem access. State precisely which privileges, peer connections, network
conditions or economic resources an exploit requires. Use local regtest nodes
and synthetic wallets; do not connect reproductions to production networks or
use real funds. Third-party dependencies are relevant when a defect is reachable
through Firo's own code paths.

Firo's public vulnerability policy is at
https://firo.org/guide/bounty-program.html. It documents bounty scope and rewards;
report the demonstrated technical impact separately from bounty eligibility.
Check public fixes and prior reports when assessing whether a finding is new.

## Reports

Include the exact scanned commit, affected file paths and line numbers, a working
reproducer, observed versus expected behavior, prerequisites, and demonstrated
impact. Prioritize fund loss, inflation, consensus failures, private-key exposure,
privacy failures and remotely triggered node compromise or denial of service.
Explain uncertainty and distinguish a hypothesis from a reproduced defect.
Group reports sharing the same root cause. Include a minimal proposed fix and a
regression test where possible.

## Offline build and tests

The checkout, dependency sources, build tools and compiled binaries remain in
`/src`. The image builds the daemon, CLI, wallet and unit tests with debug
information and frame pointers. GUI execution is not configured.

From `/src`:

```sh
ctest --test-dir build --output-on-failure
python3 qa/pull-tester/rpc-tests.py -parallel=1 httpbasics
python3 qa/pull-tester/rpc-tests.py -parallel=2 -extended
```

The last command runs the broader functional suite and may take substantially
longer. `FIROD` and `FIROCLI` point to `/src/build/bin/`, so the functional harness
can launch the compiled binaries offline. Targeted unit suites can be run with
`build/bin/test_firo --run_test=<suite_name>`. To rebuild after a patch, run
`cmake --build /src/build -j2`.
