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

The most important confirmed issues are **not** in the core arithmetic of Spark
proof construction. Instead, they are concentrated around **secret handling** and
**wallet export / persistence semantics**.

The highest-priority issues are:

1. `dumpsparkviewkey` exports a secret that is much more powerful than its name
   suggests.
2. `dumpwallet` exports Spark spend-derivation material that can be used to
   reconstruct Spark spend authority.
3. persisted Spark full-view material appears to live outside the wallet
   encryption path.
4. `dumpwallet` and `importwallet` are not a complete Spark backup / restore
   pair, which creates a realistic operational recovery hazard.

I did **not** confirm a direct Spark inflation bug in the current reviewed code,
and I did **not** confirm a default mempool invalid-spend acceptance bug in the
current stateful validation path.

---

## Confirmed Findings

## 1. High: `dumpsparkviewkey` exports a materially over-privileged secret

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

### Why this is dangerous

The name **“view key”** strongly suggests a watch-only or incoming-view-only
capability. In reality, this export is materially stronger:

- it deanonymizes owned Spark activity much more deeply than an incoming-only
  viewing key would
- it can recover serial / tag related metadata for owned coins
- it is not gated like the more obviously dangerous export RPCs

`dumpsparkviewkey` currently lacks the stronger protections used elsewhere,
such as the one-time authorization pattern applied to `dumpwallet_firo` and
`dumpprivkey_firo`.

### Impact

- catastrophic Spark privacy loss for the wallet whose key is exported
- high operator risk because the interface naming understates sensitivity

### What was **not** confirmed

This review did **not** confirm that `FullViewKey` alone is sufficient to spend
Spark coins. Spend construction still requires scalar `r`, which is not present
in `FullViewKey`.

### Recommended remediation

- Rename the RPC and UI language so it does not imply watch-only semantics.
- Restrict export behind stronger confirmation / authorization controls.
- Consider exporting a true incoming-view-only key instead of `FullViewKey`
  where possible.
- Audit any GUI flows that present this value to users.

---

## 2. High: `dumpwallet` exports Spark spend-derivation secret material

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

### Why this is dangerous

Anyone who obtains that dumped key material and the matching derivation setting
can reconstruct the same Spark spend key path and therefore recover Spark spend
authority.

Unlike the previous finding, this is not just a privacy risk. This is a
**theft-capable export surface**.

### Impact

- direct loss of Spark funds if the dump file is exposed

### Existing mitigation

The exported dump is routed through `dumpwallet_firo`, which adds a one-time
authorization flow. That helps against casual misuse, but it does not change
the severity of the material once exported.

### Recommended remediation

- Explicitly document that the Spark key in wallet dumps is theft-capable.
- Consider separating Spark-secret export from generic wallet dumps or adding
  stronger dedicated warnings.
- Re-evaluate whether generic wallet dump output should include this Spark
  secret by default.

---

## 3. Medium: persisted Spark full-view material appears to bypass wallet encryption

### What happens

Spark `FullViewKey` is stored via normal wallet DB writes:

- `src/wallet/walletdb.cpp` — `writeFullViewKey`
- `src/wallet/db.h` — generic `CDB::Write`

The wallet encryption machinery protects:

- encrypted private keys
- mnemonic container / related secret material

But there is no Spark-specific path encrypting the persisted `fullViewKey`.

### Why this is dangerous

Users may reasonably assume that “encrypted wallet” semantics protect all
high-sensitivity Spark wallet secrets. In the current design, that assumption
does not appear to hold for `FullViewKey`.

Because `FullViewKey` is stronger than a basic incoming-only view key, this is
not a trivial metadata leak.

### Impact

- at-rest compromise of Spark wallet privacy material
- meaningful gap between user expectations and actual protection

### Recommended remediation

- Either encrypt persisted Spark full-view material at rest,
- or reduce what needs to be stored persistently,
- or split storage into lower-sensitivity incoming-view-only material and
  separately protected full-view material.

Also update developer comments and user-facing assumptions accordingly.

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

### Why this is dangerous

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

## A. Batched Spark proof verification occurs after best-chain advancement logic

Relevant code:

- `src/spark/state.cpp`
- `src/batchproof_container.cpp`
- `src/validation.cpp`
- `src/libspark/spend_transaction.cpp`

Spark proof checks can be deferred into `BatchProofContainer::batch_spark()`
for older blocks. This verification happens after the best-chain step has
already advanced the tip in the activation loop.

I did not confirm a concrete inflation or invalid-acceptance exploit from this
path under current default stateful validation behavior. However, it is an
architectural risk area and deserves explicit review by developers, especially
if batching behavior changes in the future.

Questions worth answering in follow-up work:

- Are batch verification assumptions identical to per-transaction verification?
- Can any failure mode leave state temporarily advanced in a way that is
  operationally dangerous?
- Are cover-set assumptions sufficiently canonical for batch verification?

## B. Wallet-state inconsistencies around Spark mint removal on reorg

Relevant code:

- `src/spark/sparkwallet.cpp`
- `src/validation.cpp`
- `src/wallet/wallet.cpp`

Spark mint metadata removal on disconnect appears capable of causing temporary
accounting inconsistencies. I did not confirm permanent fund loss from this,
but it remains a wallet safety area worth closer review.

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

## Priority 0 — prevent theft-capable exports from being misunderstood

- Reclassify Spark export surfaces by actual sensitivity.
- Treat `dumpwallet` Spark-secret output as theft-capable.
- Add stronger user-facing warnings where secrets can be exported.

## Priority 1 — fix misleading “view key” semantics

- Rename `dumpsparkviewkey` or change what it exports.
- If possible, expose a true incoming-only view key for benign viewing use
  cases.
- Restrict full-view export behind stronger safeguards.

## Priority 2 — protect persisted Spark full-view material

- Decide whether `FullViewKey` truly must be persisted.
- If yes, store it under an encryption model consistent with wallet user
  expectations.
- If no, minimize persisted Spark-sensitive state.

## Priority 3 — fix Spark backup / restore semantics

- Either make `dumpwallet` / `importwallet` Spark-complete,
- or explicitly document that they are not.
- Add tests for the expected Spark restore behavior.

## Priority 4 — review batch verification architecture

- Re-check the correctness and failure semantics of deferred Spark proof
  verification.
- Ensure the ordering of chain advancement and deferred verification is fully
  intentional and safe.

---

## Suggested Follow-up Tests

The existing test suite should be extended with explicit regression coverage
for:

1. Spark export semantics
   - verify exactly which key class is exported
   - verify protection requirements around export RPCs

2. Spark backup / restore behavior
   - prove whether `dumpwallet` + `importwallet` restores Spark capability
   - ensure user-visible semantics match actual restore behavior

3. At-rest protection expectations
   - if full-view material becomes encrypted, add tests for persistence and
     unlock behavior

4. Batch verification safety
   - explicit tests for batched Spark verification failure handling

---

## Closing Notes

This document should be treated as a developer-facing audit summary, not a
formal external disclosure advisory.

The most actionable issues are currently around **secret handling and wallet
export semantics**, not a demonstrated failure in the Spark arithmetic itself.
