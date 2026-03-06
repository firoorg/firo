# Firo Masternode Security Audit Report

**Date:** 2026-03-06
**Scope:** Masternode subsystem including DKG sessions, quorum signing, BLS cryptography, masternode authentication, P2P message handling, and evo transaction processing.

**Total Findings:** 47 (10 HIGH, 21 MEDIUM, 11 LOW, 5 Informational)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Area 1: DKG Session Code](#area-1-dkg-session-code)
3. [Area 2: Quorum Signing & Consensus (ChainLocks, InstantSend)](#area-2-quorum-signing--consensus)
4. [Area 3: BLS Cryptography Implementation](#area-3-bls-cryptography-implementation)
5. [Area 4: Masternode Authentication & P2P Messages](#area-4-masternode-authentication--p2p-messages)
6. [Area 5: Masternode Networking & Evo Transactions](#area-5-masternode-networking--evo-transactions)
7. [Summary Table](#summary-table)
8. [Recommended Remediation Priority](#recommended-remediation-priority)

---

## Executive Summary

This audit examined the Firo masternode subsystem across five areas: DKG session management, quorum signing/consensus protocols, BLS cryptographic primitives, masternode P2P authentication, and evo transaction validation. The audit identified 47 findings spanning memory safety, cryptographic design, denial-of-service vectors, race conditions, logic bugs, and input validation gaps.

**Critical themes:**
- **Memory safety:** Use-after-free in async BLS worker (H-1 in BLS), memory leaks via raw pointers (multiple locations)
- **Cryptographic design:** IES encryption scheme lacks ciphertext authentication and uses no KDF for key derivation
- **Denial of service:** Multiple unbounded data structures and missing rate limits enable remote resource exhaustion
- **Race conditions:** Several data races on shared state accessed from multiple threads without synchronization
- **Logic bugs:** Dead code in signature conflict detection, inverted min/max in thread pool sizing, off-by-one in batch verification blame logic

---

## Area 1: DKG Session Code

**Files:** `src/llmq/quorums_dkgsession.{h,cpp}`, `quorums_dkgsessionhandler.{h,cpp}`, `quorums_dkgsessionmgr.{h,cpp}`, `quorums_blockprocessor.{h,cpp}`, `quorums_commitment.{h,cpp}`, `quorums_utils.{h,cpp}`

### DKG-1: BatchVerifyMessageSigs Logic Bug Causes False Banning (HIGH)

**File:** `src/llmq/quorums_dkgsessionhandler.cpp`, lines 327-345

```cpp
NodeId firstNodeId = 0;
first = true;
bool nodeIdsAllSame = true;
for (auto it = messages.begin(); it != messages.end(); ++it) {
    if (first) {
        firstNodeId = it->first;
    } else {
        first = false;      // BUG: set to false in else branch, not if branch
        if (it->first != firstNodeId) {
```

The variable `first` is never set to `false` in the `if (first)` branch. On the second iteration, `first` is still `true`, so `firstNodeId` is overwritten with the second node's ID. The `first = false` assignment only executes on the third iteration. For batches with exactly 2 messages from different nodes, `nodeIdsAllSame` incorrectly remains `true`, causing the wrong node to be blamed and banned (Misbehaving score 100).

### DKG-2: Verification Vector Written to DB Before SK Contribution Verified (HIGH)

**File:** `src/llmq/quorums_dkgsession.cpp`, line 318

```cpp
dkgManager.WriteVerifiedVvecContribution(params.type, pindexQuorum, qc.proTxHash, qc.vvec);
```

Called in `ReceiveMessage` before `VerifyPendingContributions()` validates the secret key share. The vvec is stored as "verified" when only structural validity and signature have been confirmed, not cryptographic consistency with the secret key share. Creates a window where `GetVerifiedContributions()` returns potentially invalid data.

### DKG-3: Simulated DKG Error Rate in Production Code (MEDIUM-HIGH)

**File:** `src/llmq/quorums_dkgsession.cpp`, lines 37-60

The RPC command `quorum dkgsimerror` allows setting error rates for contribution-omit, contribution-lie, complain-lie, justify-lie, justify-omit, commit-omit, and commit-lie. If RPC credentials are compromised, this can sabotage DKG participation. Should not exist in production builds.

### DKG-4: QWATCH Allows Unauthenticated DKG Surveillance (MEDIUM-HIGH)

**File:** `src/llmq/quorums_dkgsessionmgr.cpp`, lines 79-81

```cpp
if (strCommand == NetMsgType::QWATCH) {
    pfrom->qwatch = true;
    return;
}
```

Any peer can send QWATCH with no authentication, rate limiting, or validation. The node then relays ALL DKG messages (contributions, complaints, justifications, commitments) to that peer. Enables passive surveillance of DKG sessions and bandwidth amplification attacks.

### DKG-5: Unbounded `seenMessages` Set Growth (MEDIUM)

**File:** `src/llmq/quorums_dkgsessionhandler.h`, line 46

The `seenMessages` set has no size limit. Per-node limits exist but total across all NodeIds is unbounded. Sybil connections can insert unlimited hashes consuming significant memory.

### DKG-6: No Misbehaving Penalty for Message Flooding (MEDIUM)

**File:** `src/llmq/quorums_dkgsessionhandler.cpp`, lines 33-36

```cpp
if (messagesPerNode[from] >= maxMessagesPerNode) {
    // TODO ban?
    LogPrintf("CDKGPendingMessages::%s -- too many messages, peer=%d\n", __func__, from);
    return;
}
```

Exceeding the message limit only drops messages with a log entry. No `Misbehaving()` penalty applied.

### DKG-7: Premature Commitment Stored Without Full Validation (MEDIUM)

**File:** `src/llmq/quorums_dkgsession.cpp`, lines 1078-1098

When quorum vvec cannot be built, premature commitments are stored in `prematureCommitments` without validation. While only `validCommitments` items are used in `FinalizeCommitments()`, unbounded storage is a concern.

### DKG-8: No Phase-Gating of Incoming DKG Messages (MEDIUM)

**File:** `src/llmq/quorums_dkgsessionhandler.cpp`, lines 128-140

Messages for all phases are accepted and queued regardless of current phase. An attacker can pre-fill pending queues with messages for future phases, consuming memory.

### DKG-9: Justification + QWATCH Reveals Secret Key Shares (MEDIUM)

**File:** `src/llmq/quorums_dkgsession.cpp`, lines 643-664

During justification, secret key shares are broadcast in plaintext. Combined with QWATCH (DKG-4), any network observer can collect revealed shares. An attacker could strategically complain to force specific members to reveal shares.

### DKG-10: AddMinableCommitment Stale Map Entry / Memory Leak (LOW-MEDIUM)

**File:** `src/llmq/quorums_blockprocessor.cpp`, lines 469-492

```cpp
ins.first->second = commitmentHash;              // Update to new hash
minableCommitments.erase(ins.first->second);     // BUG: erases NEW hash, not old
minableCommitments.emplace(commitmentHash, fqc); // Re-inserts
```

The old commitment entry is never removed, causing a memory leak.

### DKG-11: No Cross-Validation of llmqType in Message vs Session (LOW-MEDIUM)

**File:** `src/llmq/quorums_dkgsession.cpp`

The `llmqType` field inside deserialized messages is never verified to match `params.type` of the session. Routing is by raw byte, but internal fields are unchecked.

---

## Area 2: Quorum Signing & Consensus

**Files:** `src/llmq/quorums.{h,cpp}`, `quorums_signing.{h,cpp}`, `quorums_signing_shares.{h,cpp}`, `quorums_chainlocks.{h,cpp}`, `quorums_instantsend.{h,cpp}`, `quorums_init.{h,cpp}`

### QS-1: Conflict Detection Compares Incoming Signature Against Itself (HIGH)

**File:** `src/llmq/quorums_signing.cpp`, line 673

```cpp
auto otherSignHash = CLLMQUtils::BuildSignHash(recoveredSig);  // BUG: should be otherRecoveredSig
```

The conflict-warning branch is dead code. `signHash != otherSignHash` is always false because both are built from the same `recoveredSig`. If an attacker produces two different valid recovered signatures for the same signing ID (indicating quorum compromise), the attack goes completely undetected.

### QS-2: VerifyRecoveredSig Ignores Its llmqType Parameter (HIGH)

**File:** `src/llmq/quorums_signing.cpp`, lines 902-913

```cpp
bool CSigningManager::VerifyRecoveredSig(Consensus::LLMQType llmqType, ...) {
    auto& llmqParams = Params().GetConsensus().llmqs.at(Params().GetConsensus().llmqChainLocks);
    // llmqType parameter is completely ignored
```

Unconditionally uses `llmqChainLocks` regardless of the `llmqType` parameter. Currently accidentally correct since the only caller passes ChainLock type, but any future caller (e.g., InstantSend verification) would verify against the wrong quorum type.

### QS-3: Out-of-Bounds Array Access on Transaction Outputs (HIGH)

**File:** `src/llmq/quorums_instantsend.cpp`, line 574

```cpp
*retValue = tx->vout[outpoint.n].nValue;
```

`outpoint.n` from deserialized network data is used without bounds checking against `tx->vout.size()`. A crafted InstantSend lock can crash any masternode processing it.

### QS-4: Unbounded Sessions Per Node in Signature Shares Manager (HIGH)

**File:** `src/llmq/quorums_signing_shares.h`, line 311

```cpp
// TODO limit number of sessions per node
std::unordered_map<uint256, Session, StaticSaltedHasher> sessions;
```

No limit on session creation. An attacker can send unlimited `QSIGSESANN` messages creating unbounded per-node session state, causing OOM crashes.

### QS-5: Recovered Signature Only Verified 1 in 100 Times (MEDIUM)

**File:** `src/llmq/quorums_signing_shares.cpp`, lines 770-779

```cpp
if (((recoveredSigsCounter++) % 100) == 0) {
    // verify...
}
```

After Lagrange interpolation, the recovered signature is only verified against the quorum public key 1% of the time. The other 99% are accepted and propagated unverified. For consensus-critical protocols (ChainLocks, InstantSend), an invalid recovered signature can cause chain splits.

### QS-6: Unbounded pendingInstantSendLocks Map (MEDIUM)

**File:** `src/llmq/quorums_instantsend.cpp`, line 739

No size limit. `PreVerifyInstantSendLock` only performs lightweight checks without BLS verification. Attackers can flood with unique ISLOCK messages consuming unbounded memory.

### QS-7: Unbounded pendingRecoveredSigs Queue (MEDIUM)

**File:** `src/llmq/quorums_signing.cpp`, line 480

After passing `PreVerifyRecoveredSig` (no BLS check), recovered sigs are queued without per-node or global size limit.

### QS-8: seenChainLocks Grows Before Signature Verification (MEDIUM)

**File:** `src/llmq/quorums_chainlocks.cpp`, line 104

Every unique CLSIG hash inserted into `seenChainLocks` before BLS verification. Entries persist 24 hours. Sustained flooding accumulates memory.

### QS-9: ChainLock Height Not Validated for Negative Values (MEDIUM)

**File:** `src/llmq/quorums_chainlocks.h`, line 26

`nHeight` is a signed `int32_t` deserialized without validation. Negative heights could trigger undefined behavior in ancestor-lookup logic.

### QS-10: Batch Verification Poisoning Causes Innocent Peer Banning (LOW)

**File:** `src/llmq/quorums_signing.cpp`, line 599

Batch verifier constructed with `perMessageFallback=false`. If batch fails, all messages from the same source node are treated as bad (Misbehaving 100 = immediate ban).

### QS-11: Race Condition in CQuorum Destructor (LOW)

**File:** `src/llmq/quorums.cpp`, lines 43-52

When destructor is called from the cache populator thread itself, the thread may still access `members` and `qc.validMembers` on the object being destroyed.

### QS-12: Cleanup Uses Manipulable Adjusted Time (LOW)

**File:** `src/llmq/quorums_signing.cpp`, lines 720-728

`-recsigsmaxage` parameter used without validation. Setting to 0 disables signature database. Uses `GetAdjustedTime()` which can be peer-skewed.

---

## Area 3: BLS Cryptography Implementation

**Files:** `src/bls/bls.{h,cpp}`, `bls_batchverifier.h`, `bls_ies.{h,cpp}`, `bls_worker.{h,cpp}`

### BLS-1: Use-After-Free in AsyncVerifyContributionShare (HIGH)

**File:** `src/bls/bls_worker.cpp`, lines 764-773

```cpp
auto f = [&forId, &vvec, &skContribution](int threadId) {
    // Uses dangling references after caller returns
};
return workerPool.push(f);
```

Lambda captures `forId`, `vvec`, and `skContribution` by reference, then dispatches to thread pool. When caller returns before worker executes, the lambda dereferences dangling pointers. Compare with `AsyncSign` at line 835 which correctly captures by value.

### BLS-2: IES Encryption Has No Ciphertext Authentication (HIGH)

**File:** `src/bls/bls_ies.cpp`, lines 12-20

AES-256-CBC with no HMAC. Vulnerable to CBC bit-flipping attacks on encrypted DKG secret key shares. An attacker can flip bits in ciphertext to produce controlled changes in decrypted plaintext.

### BLS-3: IES Symmetric Key Derived From Raw EC Point Without KDF (HIGH)

**File:** `src/bls/bls_ies.cpp`, lines 52-53

```cpp
std::vector<unsigned char> symKey = pk.ToByteVector();
symKey.resize(32);
```

Symmetric key is raw truncated point serialization including flag bits. ECIES standards mandate a proper KDF (e.g., HKDF-SHA256). Non-uniform key distribution weakens encryption.

### BLS-4: Secret Key Material Not Zeroed on Stack (MEDIUM)

**File:** `src/bls/bls.cpp`, lines 59-72

32-byte stack buffer `buf` containing raw secret key entropy is never zeroed before function return. Recoverable via core dumps or memory forensics.

### BLS-5: IES Symmetric Keys Not Zeroed After Use (MEDIUM)

**File:** `src/bls/bls_ies.cpp`, lines 52-53, 66-67, 120-121, 137-138

AES key material stored in plain `std::vector` lingers in freed heap memory across all four IES encrypt/decrypt paths.

### BLS-6: CBLSLazyWrapper::operator== Has Data Race (MEDIUM)

**File:** `src/bls/bls.h`, lines 401-415

`operator==` reads `bufValid`, `vecBytes`, `objInitialized`, `obj` without acquiring mutex. Every other method on `CBLSLazyWrapper` acquires the mutex. Concurrent calls produce undefined behavior.

### BLS-7: Worker Pool Thread Count Logic Bug (MEDIUM)

**File:** `src/bls/bls_worker.cpp`, lines 63-64

```cpp
workerCount = std::max(std::min(1, workerCount), 4);
// Always returns 4. min/max arguments are inverted.
// Intended: std::max(1, std::min(workerCount, 4))
```

### BLS-8: VerifySecureAggregated Missing IsValid() Checks (MEDIUM)

**File:** `src/bls/bls.cpp`, lines 302-315

Unlike other verify methods, does not check `IsValid()` on signature or public keys. Invalid objects passed directly to underlying library.

### BLS-9: Batch Verifier Insecure Mode Vulnerable to Rogue Key Attack (MEDIUM)

**File:** `src/bls/bls_batchverifier.h`, lines 135-184

`secureVerification=false` aggregates keys via simple addition, enabling rogue public key attacks.

### BLS-10: Ephemeral Secret Key Persists After Encryption (MEDIUM)

**File:** `src/bls/bls_ies.h`, lines 90-91

The ephemeral secret key (can decrypt every recipient's blob) persists for the lifetime of `CBLSIESMultiRecipientBlobs`. Should be cleared after `Encrypt()`.

### BLS-11: GetOrBuild Exception Safety Issues (MEDIUM)

**File:** `src/bls/bls_worker.h`, lines 184-202

If `builder()` throws: (1) promise destroyed without `set_value()`, all waiting threads get `future_error`, poisoned cache entry persists permanently. (2) Manual `lock()`/`unlock()` not exception-safe, deadlocks all future cache operations.

### BLS-12: Aggregation Functions Use assert() Compiled Out in Release (MEDIUM)

**File:** `src/bls/bls.cpp`, lines 34, 134, 203, 257

All `AggregateInsecure` and `SubInsecure` methods use `assert()` as sole validity check. In release builds, assertions are removed. Invalid BLS objects produce incorrect aggregations.

### BLS-13: IES IV Derivation is O(n^2) for Multi-Recipient (LOW)

**File:** `src/bls/bls_ies.cpp`, lines 32-39

Computing IV for recipient index `idx` requires `idx` sequential hashes. For large quorums, the last decryption is expensive.

### BLS-14: AES-CBC Fails Silently for Non-Block-Aligned Data (LOW)

**File:** `src/bls/bls_ies.cpp`, line 17

Padding disabled. Non-16-byte-aligned plaintext silently fails. Currently safe (32-byte BLS keys), but fragile API.

---

## Area 4: Masternode Authentication & P2P Messages

**Files:** `src/evo/mnauth.{h,cpp}`, `src/masternode-payments.{h,cpp}`, `src/masternode-utils.{h,cpp}`, `src/evo/simplifiedmns.{h,cpp}`, `src/net_processing.cpp`, `src/spork.{h,cpp}`

### AUTH-1: MNAUTH Connection Hijacking with Data Race (HIGH)

**File:** `src/evo/mnauth.cpp`, lines 110-122

```cpp
connman.ForEachNode([&](CNode* pnode2) {
    if (pnode2->verifiedProRegTxHash == mnauth.proRegTxHash) {  // No lock!
        pnode2->fDisconnect = true;
    }
});
```

Two issues: (1) Reads `verifiedProRegTxHash` without holding `cs_mnauth` -- data race. (2) When a new valid MNAUTH arrives for an already-verified proRegTxHash, the OLD legitimate connection is disconnected and the NEW one takes over. Enables forced connection eviction.

### AUTH-2: GETMNLISTDIFF No Rate Limiting, CPU/Disk/Lock Amplification (HIGH)

**File:** `src/net_processing.cpp`, lines 3089-3102

Zero rate limiting. Each request holds `cs_main`, acquires `deterministicMNManager->cs`, performs `ReadBlockFromDisk` (disk I/O under two locks), and builds a Merkle tree. Request payload is only 64 bytes. An attacker sends `baseBlockHash=genesis, blockHash=tip` to maximize work. Successful requests incur zero Misbehaving penalty.

### AUTH-3: Memory Leak in Deferred MNAUTH Processing (MEDIUM)

**File:** `src/evo/mnauth.cpp`, line 59

```cpp
pnode->pendingMNVerification = new CMNAuth(mnauth);
```

Raw pointer overwritten without `delete` on previous allocation. Repeated MNAUTH messages during sync leak memory.

### AUTH-4: Missing Null Check on sentMNAuthChallenge (MEDIUM)

**File:** `src/evo/mnauth.cpp`, lines 95-100

If `sentMNAuthChallenge` is all-zeros (default), the signHash becomes deterministic and predictable.

### AUTH-5: assert(false) Reachable from Network Data in Payment Validation (MEDIUM)

**File:** `src/masternode-payments.cpp`, lines 140-141 and 286-288

```cpp
if (!ExtractDestination(payee->pdmnState->scriptPayout, dest))
    assert(false);
```

If a masternode's `scriptPayout` is non-standard, these assertions crash the node during block validation. Network-wide DoS if many nodes affected.

### AUTH-6: ProcessMasternodeConnections Entirely Commented Out (MEDIUM)

**File:** `src/masternode-utils.cpp`, lines 68-93

Function body entirely commented out but still called every 60 seconds. Non-quorum masternode connections are never pruned.

### AUTH-7: Potential Deadlock from Nested ForEachNode (MEDIUM)

**File:** `src/masternode-sync.cpp`, lines 276-293

`ForEachNode` (acquires `cs_vNodes`) -> lambda calls `ProcessMNAUTH` -> which calls `ForEachNode` again (re-acquires `cs_vNodes`). Recursive lock acquisition. Works only if `cs_vNodes` is a recursive mutex.

### AUTH-8: Disk I/O Under cs_main in BuildSimplifiedMNListDiff (MEDIUM)

**File:** `src/evo/simplifiedmns.cpp`, lines 234-238

`ReadBlockFromDisk` under both `cs_main` and `deterministicMNManager->cs`. Blocks all concurrent operations requiring either lock.

### AUTH-9: Unbounded feature String in Spork Deserialization (LOW)

**File:** `src/evo/spork.h`, lines 59-75

`feature` string limited only by global MAX_SIZE (32 MB). Requires spork key compromise to exploit.

### AUTH-10: Lite Mode Bypasses All Payment Validation (LOW)

**File:** `src/masternode-payments.cpp`, lines 90-96

In lite mode, all masternode payment validation skipped. Any coinbase distribution accepted.

---

## Area 5: Masternode Networking & Evo Transactions

**Files:** `src/masternode-sync.{h,cpp}`, `src/evo/deterministicmns.{h,cpp}`, `src/evo/evodb.{h,cpp}`, `src/evo/specialtx.{h,cpp}`, `src/evo/providertx.{h,cpp}`, `src/evo/cbtx.{h,cpp}`

### EVO-1: Provider TX Validation Bypass When pindexPrev Is NULL (HIGH)

**File:** `src/evo/providertx.cpp`, ~lines 234, 299, 371

```cpp
if (pindexPrev) {
    // ALL validation: MN existence, duplicate checks, inputsHash, BLS signature
}
return true;  // No validation when pindexPrev is NULL
```

`CheckProUpServTx`, `CheckProUpRegTx`, `CheckProUpRevTx` all skip entire validation when `pindexPrev` is NULL (mempool acceptance). Completely unauthenticated masternode update/revocation transactions enter mempool and propagate network-wide.

### EVO-2: No Synchronization on CMasternodeSync Members (MEDIUM)

**File:** `src/masternode-sync.h`, lines 33-42

No mutex, critical section, or atomics on `nCurrentAsset`, `nTriedPeerCount`, `nTimeAssetSyncStarted`, etc. Read and written from multiple threads (scheduler, P2P handlers, validation interface). Undefined behavior under C++ memory model.

### EVO-3: Static fReachedBestHeader Data Race (MEDIUM)

**File:** `src/masternode-sync.cpp`, lines 248-260

Static local variable read and written without synchronization in `UpdatedBlockTip`, called from multiple threads.

### EVO-4: VerifyInsecure BLS Verification Pattern (MEDIUM)

**File:** `src/evo/providertx.cpp` line 69, `src/evo/mnauth.cpp` line 102

Uses "insecure" (non-augmented) BLS verification. No proof-of-possession for operator keys. Vulnerable to rogue key attacks if aggregation is ever introduced.

### EVO-5: Unbounded Deserialization Allocations (MEDIUM)

**File:** `src/evo/deterministicmns.h`, lines 250, 327, 575, 582

`ReadCompactSize` followed by allocation loops without sanity bounds. A crafted message with inflated count causes OOM crash.

### EVO-6: GetCurTransaction() Bypasses Lock Protection (LOW)

**File:** `src/evo/evodb.h`, lines 40-43

Returns mutable reference to `curDBTransaction` without acquiring `cs` lock. All other methods acquire the lock first.

### EVO-7: Weak DoS Scoring on MNAUTH Failures (LOW)

**File:** `src/evo/mnauth.cpp`, lines 86-92, 102-107

Failed MNAUTH (invalid signature) only adds 10 to DoS score. Allows 9 invalid BLS pairing operations per connection before ban.

### EVO-8: Static nTick/nTimeLastProcess Data Race (LOW)

**File:** `src/masternode-sync.cpp`, lines 110-114

Static locals without synchronization.

### EVO-9: Negative Sync Progress Value (LOW)

**File:** `src/masternode-sync.cpp`, line 144

When `nCurrentAsset` is FAILED (-1) or INITIAL (0), progress computation yields negative values.

### EVO-10: Missing Default Case in SwitchToNextAsset (LOW)

**File:** `src/masternode-sync.cpp`, lines 56-78

No `default` case in switch. Unhandled states silently reset counters.

---

## Summary Table

| ID | Finding | Severity | Category |
|----|---------|----------|----------|
| DKG-1 | BatchVerifyMessageSigs false banning logic bug | HIGH | Logic Bug |
| DKG-2 | VVec written to DB before SK verified | HIGH | Logic Bug |
| DKG-3 | Simulated DKG errors in production | MEDIUM-HIGH | Configuration |
| DKG-4 | QWATCH unauthenticated DKG surveillance | MEDIUM-HIGH | Auth Bypass |
| DKG-5 | Unbounded seenMessages growth | MEDIUM | DoS |
| DKG-6 | No penalty for message flooding | MEDIUM | DoS |
| DKG-7 | Premature commitments stored unvalidated | MEDIUM | Logic Bug |
| DKG-8 | No phase-gating of DKG messages | MEDIUM | DoS |
| DKG-9 | Justification + QWATCH reveals SK shares | MEDIUM | Information Leak |
| DKG-10 | AddMinableCommitment memory leak | LOW-MEDIUM | Memory Leak |
| DKG-11 | No llmqType cross-validation | LOW-MEDIUM | Input Validation |
| QS-1 | Conflict detection dead code | HIGH | Logic Bug |
| QS-2 | VerifyRecoveredSig ignores llmqType | HIGH | Logic Bug |
| QS-3 | Out-of-bounds tx output access | HIGH | Memory Safety |
| QS-4 | Unbounded sig share sessions | HIGH | DoS |
| QS-5 | Recovered sig verified 1% of time | MEDIUM | Verification Gap |
| QS-6 | Unbounded pendingInstantSendLocks | MEDIUM | DoS |
| QS-7 | Unbounded pendingRecoveredSigs | MEDIUM | DoS |
| QS-8 | seenChainLocks grows before verification | MEDIUM | DoS |
| QS-9 | Negative ChainLock height unvalidated | MEDIUM | Input Validation |
| QS-10 | Batch verification innocent peer banning | LOW | DoS |
| QS-11 | CQuorum destructor race condition | LOW | Race Condition |
| QS-12 | Cleanup uses manipulable time | LOW | Input Validation |
| BLS-1 | Use-after-free in async worker | HIGH | Memory Safety |
| BLS-2 | IES no ciphertext authentication | HIGH | Cryptography |
| BLS-3 | IES no KDF for key derivation | HIGH | Cryptography |
| BLS-4 | Secret key not zeroed on stack | MEDIUM | Key Hygiene |
| BLS-5 | IES symmetric keys not zeroed | MEDIUM | Key Hygiene |
| BLS-6 | CBLSLazyWrapper operator== data race | MEDIUM | Race Condition |
| BLS-7 | Worker pool thread count bug | MEDIUM | Logic Bug |
| BLS-8 | VerifySecureAggregated missing checks | MEDIUM | Input Validation |
| BLS-9 | Insecure batch mode rogue key attack | MEDIUM | Cryptography |
| BLS-10 | Ephemeral key persists after encrypt | MEDIUM | Key Hygiene |
| BLS-11 | GetOrBuild exception safety | MEDIUM | Exception Safety |
| BLS-12 | assert() compiled out in release | MEDIUM | Input Validation |
| BLS-13 | O(n^2) IV derivation | LOW | Performance |
| BLS-14 | Silent AES failure for unaligned data | LOW | Input Validation |
| AUTH-1 | MNAUTH connection hijacking + race | HIGH | Race/Spoofing |
| AUTH-2 | GETMNLISTDIFF DoS amplification | HIGH | DoS |
| AUTH-3 | Deferred MNAUTH memory leak | MEDIUM | Memory Leak |
| AUTH-4 | Missing sentMNAuthChallenge null check | MEDIUM | Input Validation |
| AUTH-5 | assert(false) from network data | MEDIUM | DoS |
| AUTH-6 | MN connection pruning disabled | MEDIUM | Missing Control |
| AUTH-7 | Nested ForEachNode deadlock risk | MEDIUM | Deadlock |
| AUTH-8 | Disk I/O under cs_main | MEDIUM | Performance/DoS |
| AUTH-9 | Unbounded spork feature string | LOW | Input Validation |
| AUTH-10 | Lite mode skips payment validation | LOW | Logic Bug |
| EVO-1 | Provider TX validation bypass | HIGH | Auth Bypass |
| EVO-2 | CMasternodeSync no synchronization | MEDIUM | Race Condition |
| EVO-3 | fReachedBestHeader data race | MEDIUM | Race Condition |
| EVO-4 | VerifyInsecure BLS pattern | MEDIUM | Cryptography |
| EVO-5 | Unbounded deserialization allocations | MEDIUM | DoS |
| EVO-6 | GetCurTransaction bypasses lock | LOW | Race Condition |
| EVO-7 | Weak MNAUTH DoS scoring | LOW | DoS |
| EVO-8 | Static nTick data race | LOW | Race Condition |
| EVO-9 | Negative sync progress | LOW | Logic Bug |
| EVO-10 | Missing switch default case | LOW | Logic Bug |

---

## Recommended Remediation Priority

### Immediate (P0) -- Exploitable crashes or consensus issues

1. **BLS-1**: Fix lambda captures to by-value in `AsyncVerifyContributionShare`
2. **QS-3**: Add bounds check on `outpoint.n` before indexing `tx->vout`
3. **QS-1**: Fix conflict detection to compare against `otherRecoveredSig`
4. **EVO-1**: Add basic validation even when `pindexPrev` is NULL
5. **AUTH-2**: Add per-peer rate limiting for GETMNLISTDIFF

### Short-term (P1) -- Remote DoS and authentication issues

6. **QS-4**: Add session count limit per node
7. **BLS-2 + BLS-3**: Redesign IES with HKDF and Encrypt-then-MAC
8. **DKG-1**: Fix `first = false` placement in batch verification
9. **AUTH-1**: Fix data race and connection displacement logic
10. **QS-6, QS-7**: Add size limits on pending maps
11. **AUTH-3**: Fix memory leak with `unique_ptr` or explicit delete
12. **AUTH-5**: Replace `assert(false)` with graceful error handling

### Medium-term (P2) -- Defense in depth

13. **DKG-4**: Add authentication/rate-limiting to QWATCH
14. **QS-5**: Increase recovered signature verification rate
15. **EVO-2, EVO-3**: Add mutex to CMasternodeSync
16. **BLS-6**: Add locking to `operator==`
17. **BLS-7**: Fix min/max inversion in thread pool sizing
18. **BLS-12**: Replace `assert()` with runtime checks
19. **DKG-3**: Remove simulated error functionality from production
20. **BLS-4, BLS-5, BLS-10**: Implement key hygiene (memory_cleanse)

### Long-term (P3) -- Code quality and hardening

21. Remaining MEDIUM and LOW findings
22. Add size bounds to all deserialization paths
23. Audit and document lock ordering across subsystems
24. Consider formal verification of BLS primitives
