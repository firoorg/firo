# Spark Security Audit Notes

## Purpose

This document captures a focused security review of the Spark library and its
wallet / node integration in Firo. It is intended for developers who want to
understand the current risk areas and prioritize fixes.

This review focused on issues that could plausibly lead to:

- fund loss
- supply inflation or acceptance of invalid value
- spendability failures
- theft-enabling key exposure

It did **not** attempt a full historical review of all Spark-related pull
requests, and it did **not** focus on deprecated Lelantus beyond shared code
paths that still affect Spark behavior.

---

## Scope

Reviewed components included:

- `src/libspark/`
- `src/spark/`
- `src/wallet/wallet.cpp`
- `src/wallet/walletdb.cpp`
- `src/wallet/rpcwallet.cpp`
- `src/wallet/rpcdump.cpp`
- `src/validation.cpp`
- `src/batchproof_container.cpp`
- `src/sparkname.cpp`

Supporting Spark tests were also reviewed and executed.

---

## Executive Summary

After reassessing the review under the intended threat model, the strongest
developer-actionable items are **not** direct vulnerabilities in Spark proof
arithmetic. Instead, they are mostly:

- **hardening concerns**
- **operational / recovery footguns**
- **developer-facing invariants that need to remain true as the code evolves**

Under the clarified model:

- `dumpwallet` exporting Spark-sensitive material is **expected behavior**, not
  a vulnerability
- persisting `FullViewKey` is **intentional design**, not a vulnerability, if
  physical access and wallet-file theft are out of scope

The most important remaining items are:

1. `dumpsparkviewkey` still exports a stronger secret than its name implies,
   and its UX / gating should be treated as a **hardening concern**
2. `dumpwallet` / `importwallet` is **not** a complete Spark backup / restore
   pair, which is a real operational recovery footgun
3. deferred Spark batch verification remains an architectural hardening area,
   especially around correctness equivalence, liveness, and maintenance risk

I did **not** confirm a direct Spark inflation bug in the reviewed code, and I
did **not** confirm a default mempool invalid-spend acceptance bug in the
current stateful validation path.

---

## Reassessed Findings Under the Current Threat Model

This section reflects the clarified assumptions:

- `dumpwallet` is an explicit full-secret export and requires wallet unlock
- one-time authorization for dump RPCs is primarily an anti-scam UX measure
- the wallet must persist Spark full-view material in order to track balances
  while locked
- physical wallet-file access is out of scope

## 1. Hardening Concern: `dumpsparkviewkey` exports a stronger secret than its
name suggests

### What happens

The RPC named `dumpsparkviewkey` exports a serialized `spark::FullViewKey`.

Relevant code:

- `src/wallet/rpcdump.cpp` — `dumpsparkviewkey`
- `src/wallet/wallet.cpp` — `GetSparkViewKeyStr`
- `src/libspark/keys.h`
- `src/libspark/keys.cpp`
- `src/libspark/coin.cpp` — `Coin::recover`

`FullViewKey` contains:

- `s1`
- `s2`
- `D`
- `P2`

That key is not just enough to detect incoming outputs. It is also sufficient
for `coin.recover(...)` to derive owned-coin serial / tag material.

### Why this still matters

The name **“view key”** strongly suggests a watch-only or incoming-view-only
capability. In reality, this export is materially stronger:

- it deanonymizes owned Spark activity much more deeply than an incoming-only
  viewing key would
- it can recover serial / tag related metadata for owned coins
- it is not gated like the more obviously dangerous export RPCs

Unlike `dumpwallet`, this RPC is presented as a narrower “view key” export, but
it actually returns `FullViewKey`-class material. Even if this is acceptable in
the product threat model, the naming still understates sensitivity.

It also does not require `EnsureWalletIsUnlocked`, unlike more obviously
dangerous export flows.

### Impact classification

- **hardening / UX concern**
- not treated as a standalone vulnerability under the clarified model

### What was **not** confirmed

This review did **not** confirm that `FullViewKey` alone is sufficient to spend
Spark coins. Spend construction still requires scalar `r`, which is not present
in `FullViewKey`.

### Recommended remediation

- Rename the RPC and UI language so it does not imply watch-only semantics.
- Consider aligning export gating with other sensitive export RPCs, or at
  minimum documenting the difference clearly.
- Consider exporting a true incoming-view-only key instead of `FullViewKey`
  where possible.
- Audit any GUI flows that present this value to users.

---

## 2. Non-issue as a vulnerability: `dumpwallet` exports Spark spend-derivation
material by design

### What happens

`dumpwallet` appends a line of the form:

```text
# Spark key secret <WIF>
```

Relevant code:

- `src/wallet/rpcdump.cpp` — `dumpwallet`
- `src/spark/sparkwallet.cpp` — `generateSpendKey`

The dumped secret comes from:

- `GetKeyFromKeypath(BIP44_SPARK_INDEX, nCount, key)`

And Spark spend authority is deterministically derived from that secret plus
`sparkncount`.

### Reassessment

This remains theft-capable material, but that is not surprising or
developer-actionable under the clarified model. `dumpwallet` already requires:

- wallet unlock
- explicit export intent
- the anti-scam one-time authorization flow

So this should not be treated as a vulnerability on its own. It is better
understood as an expected consequence of exporting full wallet secrets.

### Existing mitigation / context

The exported dump is routed through `dumpwallet_firo`, which adds a one-time
authorization flow. That helps against casual misuse, but it does not change
the severity of the material once exported.

### Developer note

The important remaining concern is not that `dumpwallet` exports secrets, but
that developers should continue treating the exported Spark key as equivalent in
sensitivity to other wallet-secret exports.

---

## 3. Accepted design under this threat model: persisted Spark `FullViewKey`

### What happens

Spark `FullViewKey` is stored via normal wallet DB writes:

- `src/wallet/walletdb.cpp` — `writeFullViewKey`
- `src/wallet/db.h` — generic `CDB::Write`

The wallet encryption machinery protects:

- encrypted private keys
- mnemonic container / related secret material

But there is no Spark-specific path encrypting the persisted `fullViewKey`.

### Reassessment

Under the clarified assumptions, this is not a vulnerability:

- balance tracking while locked requires persistent Spark viewing state
- physical-access / wallet-file compromise is out of scope

So this should be treated as an **accepted design choice**, not a security bug.

### Developer note

If the threat model ever expands to include wallet-file theft or “encrypted
wallet means all Spark privacy state is protected at rest,” this area should be
revisited. For now, it should not be framed as a confirmed issue.

---

## 4. Low/Medium: `dumpwallet` is not a complete Spark restore artifact

### What happens

The Spark key secret is emitted as a comment line:

```text
# Spark key secret <WIF>
```

But `importwallet` skips comment lines entirely.

Relevant code:

- `src/wallet/rpcdump.cpp` — `dumpwallet`
- `src/wallet/rpcdump.cpp` — `importwallet`

### Why this still matters

A developer or operator may assume that:

- `dumpwallet` + `importwallet`

is a complete backup/restore pair for Spark. It is not.

If a user relies on this flow alone for Spark restoration, Spark-specific key
material may not be restored even though the generic wallet dump/import
workflow appears to succeed.

### Impact

- recovery footgun
- plausible operational fund-loss scenario

This may be partially mitigated if the user still has the mnemonic / HD seed,
but that does not remove the recovery mismatch.

### Recommended remediation

- Document clearly that wallet dump/import is not currently a complete Spark
  restore path.
- Either make Spark restoration explicit and supported,
- or remove the misleading implication that the dump is sufficient.

---

## Hardening Concerns

These issues are important, but this review does **not** elevate them to
confirmed exploits.

## A. Deferred / batched Spark verification remains the most important
hardening concern

Relevant code:

- `src/spark/state.cpp`
- `src/batchproof_container.cpp`
- `src/validation.cpp`
- `src/libspark/spend_transaction.cpp`

Spark proof checks can be deferred into `BatchProofContainer::batch_spark()`
for older blocks. This is not a confirmed inflation bug in the current review,
but it remains the strongest architectural hardening topic.

Important behaviors:

- `CheckSparkSpendTransaction()` can skip direct proof verification and queue
  the transaction when `useBatching` is true.
- `ConnectBlockSpark()` applies Spark state transitions based on `sparkTxInfo`
  built during block connection.
- `ActivateBestChain()` later decides whether to actually run batched proof
  verification based on wall-clock age vs tip block time.

More concretely:

- `ConnectBlock()` enables proof collection for blocks older than one day and
  initializes the batch container before iterating transactions.
- `CheckSparkSpendTransaction()` sets `passVerify = true` and only queues the
  spend into `BatchProofContainer` when batching is active.
- `ConnectBlockSpark()` can then consume `sparkTxInfo` and update state for the
  block.
- `ActivateBestChain()` only runs `batchProofContainer->verify()` once the new
  tip is recent enough that `fCollectProofs` becomes false.

This means Spark proof verification can be intentionally deferred across many
historical blocks during IBD or reindex.

### Why developers should care

The risk here is not “known invalid spends are accepted on mainline mempool
paths.” The review did **not** confirm that. The risk is that batching creates a
second validation mode whose behavior must stay equivalent to per-transaction
verification.

That creates ongoing maintenance hazards:

- correctness equivalence between batch and single-tx verification
- failure-mode handling and user recovery semantics
- resource spikes when deferred Spark batches are finally verified
- assumptions about canonical / monotonic cover sets

Questions worth answering in follow-up work:

- Are batch verification assumptions identical to per-transaction verification?
- Can any failure mode leave chain or wallet state temporarily advanced in a
  way that is operationally surprising?
- Are cover-set assumptions sufficiently canonical for batch verification?
- Are there useful tests that explicitly compare batched and non-batched Spark
  verification outcomes on the same historical data?

### Additional technical note

`BatchProofContainer::batch_spark()` rebuilds cover sets from the current Spark
state using `CSparkState::GetCoinSet()`, whereas the per-transaction path builds
cover sets from the block-hash-pinned ancestry walk in
`CheckSparkSpendTransaction()`. The current review did not prove this creates a
consensus failure, but it is precisely the sort of equivalence assumption that
should be locked down with tests and explicit developer documentation.

### Deeper batching flow analysis

The key sequencing is:

1. `ConnectBlock()` sets `batchProofContainer->fCollectProofs` based on block
   age and calls `batchProofContainer->init()`.
2. While iterating transactions, `CheckSparkSpendTransaction()` may skip
   immediate proof verification and instead enqueue Spark spends if
   `useBatching` is true.
3. `ConnectBlockSpark()` then applies block-local Spark state derived from
   `sparkTxInfo`, including linking tags and mint/index updates.
4. `ConnectBlock()` finishes, calls `batchProofContainer->finalize()`, and
   returns success.
5. Only later, in `ActivateBestChain()`, the node decides whether to call
   `batchProofContainer->verify()`, and that depends on the **new tip's**
   recency relative to wall clock time.

This means that:

- per-block Spark proof soundness is not enforced at the same moment as
  `ConnectBlockSpark()` state transitions for old blocks
- proof collection can span many connected historical blocks before actual
  Spark batch verification happens
- the trigger for running verification is driven by wall-clock freshness of the
  active tip, not by an explicit "all collected Spark proofs for this block have
  now been checked" barrier

### Why this is subtle

The current design appears to be optimizing IBD / reindex performance rather
than weakening the final validation goal. However, it introduces a second
validation mode with a different set of assumptions:

- **single-transaction path:** proof verified against a cover set assembled from
  the spend's referenced block hash and ancestry walk
- **batched path:** proof verified later against a cover set rebuilt from the
  current Spark state using `GetCoinSet()`

The review did not confirm that these two paths disagree today, but the code
clearly relies on that equivalence.

### Specific developer risks

1. **Behavior drift risk**
   - A future change to cover-set selection, set-hash semantics, or grouping
     rules could preserve one path while accidentally changing the other.

2. **Late-failure / liveness risk**
   - Batch verification failures are raised late and currently instruct the user
     to rerun with `-reindex -batching=0`.
   - That is acceptable as a recovery mechanism, but it means failures can
     surface long after individual historical blocks were connected.

3. **Resource concentration risk**
   - Spark proofs can accumulate across many old blocks and then be checked in a
     large batch once the tip becomes recent enough.
   - This creates a concentrated CPU / memory / latency event rather than a
     per-block cost.

4. **Testing gap**
   - The existing tests exercise normal Spark mint/spend behavior, but this
     review did not find explicit coverage that:
     - compares batched and non-batched verification on the same history
     - forces delayed batch failure handling
     - asserts equivalence of block-hash-pinned and state-rebuilt cover sets

### Suggested concrete follow-up for developers

- Add a targeted test harness that replays the same Spark-heavy historical
  chain twice:
  - once with batching disabled
  - once with batching enabled
  - and asserts identical accept/reject outcomes
- Add tests that explicitly validate the relationship between:
  - `CheckSparkSpendTransaction()` cover-set assembly
  - `CSparkState::GetCoinSet()` / `GetCoinSetForSpend()`
- Add regression coverage for a late batch-verification failure path so that
  operational recovery behavior is intentional and documented

## B. Wallet-state inconsistencies around Spark mint removal on reorg

Relevant code:

- `src/spark/sparkwallet.cpp`
- `src/validation.cpp`
- `src/wallet/wallet.cpp`

Spark mint metadata removal on disconnect appears capable of causing temporary
accounting inconsistencies. I did not confirm permanent fund loss from this,
but it remains a wallet safety area worth closer review.

This should be treated as a wallet robustness concern, especially if future UI
or RPC behavior assumes Spark metadata and wallet transaction ownership are
always perfectly aligned during reorgs.

## C. Sensitive Spark memo/address data is written to logs

Relevant code:

- `src/wallet/rpcwallet.cpp`

This is a real privacy issue, but it was not a primary confirmed
fund-loss/inflation finding in this scoped review.

---

## Areas Reviewed With No Confirmed Critical Issue

The following areas were reviewed and did **not** yield a confirmed direct
critical bug in this audit:

- Spark value-balance proof wiring in the reviewed mint/spend paths
- default stateful mempool validation for Spark spends
- duplicate linking-tag enforcement in the reviewed path
- direct “FullViewKey alone can spend” hypothesis

That does **not** mean those areas are mathematically proven correct. It means
this review did not find a concrete, developer-actionable exploit in them.

---

## Tests Reviewed and Executed

The following existing tests were run successfully during the audit:

### Unit tests

```bash
./build/bin/test_firo --run_test=spark_wallet_tests --catch_system_error=no --log_level=test_suite
./build/bin/test_firo --run_test=spark_state_tests --catch_system_error=no --log_level=test_suite
./build/bin/test_firo --run_test=spark_mintspend --catch_system_error=no --log_level=test_suite
./build/bin/test_firo --run_test=spark_tests --catch_system_error=no --log_level=test_suite
./build/bin/test_firo --run_test=sparknames --catch_system_error=no --log_level=test_suite
```

### Functional test

```bash
FIROD=/workspace/build/src/firod FIROCLI=/workspace/build/src/firo-cli python3 qa/rpc-tests/spark_mintspend.py
```

### Interpretation

These passing tests are evidence that the normal Spark mint/spend flows still
work in the reviewed tree.

They do **not** adequately cover the most important findings above, which are
mainly about:

- key sensitivity mismatches
- export / persistence semantics
- backup / recovery expectations

---

## Recommended Developer Action Plan

## Priority 0 — deepen batching / deferred-verification review

- Re-check correctness equivalence between:
  - per-transaction Spark verification
  - deferred batched Spark verification
- Add explicit regression tests for batched verification behavior.
- Review operator failure handling when batch verification fails late.

## Priority 1 — fix misleading “view key” semantics

- Rename `dumpsparkviewkey` or change what it exports.
- If possible, expose a true incoming-only view key for benign viewing use
  cases.
- Consider whether full-view export should require unlock or stronger
  confirmation, even if not treated as a vulnerability.

## Priority 2 — fix Spark backup / restore semantics

- Either make `dumpwallet` / `importwallet` Spark-complete,
- or explicitly document that they are not.
- Add tests for the expected Spark restore behavior.

## Priority 3 — document accepted Spark secret-handling assumptions

- Document that:
  - persisted `FullViewKey` is an intentional design requirement for locked
    balance tracking
  - `dumpwallet` exports Spark-sensitive material by design
  - physical-access / wallet-file compromise is outside the current threat
    model

---

## Suggested Follow-up Tests

The existing test suite should be extended with explicit regression coverage
for:

1. Spark export semantics
   - verify exactly which key class is exported
   - verify protection requirements and operator-facing wording around export
     RPCs

2. Spark backup / restore behavior
   - prove whether `dumpwallet` + `importwallet` restores Spark capability
   - ensure user-visible semantics match actual restore behavior

3. Batch verification safety
   - explicit tests for batched Spark verification failure handling
   - compare batched vs non-batched verification outcomes
   - exercise historical-sync style deferred verification paths

---

## Closing Notes

This document should be treated as a developer-facing audit summary, not a
formal external disclosure advisory.

Under the clarified threat model, the most actionable items are now:

- batch-verification hardening
- recovery / backup semantics
- and making Spark export semantics harder to misunderstand

This review still did **not** find a demonstrated failure in core Spark proof
arithmetic.
