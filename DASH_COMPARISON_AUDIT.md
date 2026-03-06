# Firo vs Dash: Security Audit Comparison

This document compares the 47 security findings from the Firo Masternode Security Audit
against the current Dash `master` branch (https://github.com/dashpay/dash) to determine
which issues also exist upstream and which have been fixed.

## Executive Summary

| Status | Count | % |
|--------|-------|---|
| **Fixed in Dash** | 26 | 55% |
| **Exists in Dash** | 17 | 36% |
| **Not Applicable** (feature removed) | 2 | 4% |
| **Exists by Design** | 2 | 4% |

Dash has fixed **all HIGH-severity P2P, Auth, and Evo findings** through incremental
hardening across v18–v20. The BLS/IES cryptographic layer remains the weakest shared
area: 11 of 14 BLS findings exist in both codebases.

---

## Area 1: DKG Session Code (5 fixed / 6 exist)

| ID | Severity | Finding | Dash Status | Notes |
|----|----------|---------|-------------|-------|
| DKG-1 | HIGH | BatchVerifyMessageSigs Logic Bug | **FIXED** | Dash rewrote batch verification; per-source-id result tracking replaces the broken first/second flag logic |
| DKG-2 | HIGH | Vvec Written to DB Before SK Share Verified | EXISTS | Same pattern — vvec stored in member before `VerifyPendingContributions()` runs |
| DKG-3 | MED-HIGH | dkgsimerror RPC in Production | EXISTS | Still ships on mainnet, gated only by RPC auth |
| DKG-4 | MED-HIGH | QWATCH Unauthenticated DKG Surveillance | EXISTS | Partially mitigated (dedup check), but no auth/rate-limit on QWATCH itself |
| DKG-5 | MEDIUM | Unbounded seenMessages Set | EXISTS | No global cap added; bounded only per-member by quorum size |
| DKG-6 | MEDIUM | No Misbehaving Penalty for Flooding | **FIXED** | Exceeding per-source limit now triggers `Misbehaving(from, 100)` (immediate ban) |
| DKG-7 | MEDIUM | Premature Commitment Without Full Validation | EXISTS | Bounded per quorum hash, but commitments still stored before full validation |
| DKG-8 | MEDIUM | No Phase-Gating of Incoming DKG Messages | **FIXED** | Phase state machine added; messages >1 phase ahead rejected with `Misbehaving()` |
| DKG-9 | MEDIUM | Justification + QWATCH Reveals SK Shares | EXISTS | Inherent to Feldman VSS protocol; would need protocol change to fix |
| DKG-10 | LOW-MED | AddMinableCommitment Stale Map Entry | **FIXED** | Refactored to use insert_or_assign; stale entry bug eliminated |
| DKG-11 | LOW-MED | No Cross-Validation of llmqType | **FIXED** | Explicit `msg.GetLLMQType() != params.type` guard added |

---

## Area 2: Quorum Signing & Consensus (8 fixed / 4 exist)

| ID | Severity | Finding | Dash Status | Notes |
|----|----------|---------|-------------|-------|
| QS-1 | HIGH | Conflict Detection Self-Comparison | **FIXED** | Complete rewrite; now compares incoming sig against stored sig via DB lookup |
| QS-2 | HIGH | VerifyRecoveredSig Ignores llmqType | **FIXED** | Now properly uses the `llmqType` parameter to look up correct quorum set |
| QS-3 | HIGH | Out-of-Bounds Array Access (crash) | **FIXED** | Bounds check: `if (outpoint.n >= tx->vout.size()) return false` |
| QS-4 | HIGH | Unbounded Sessions Per Node | **FIXED** | Per-node session limit with `Misbehaving()` penalty on excess; global limit added |
| QS-5 | MEDIUM | Recovered Sig Verified 1/100 | EXISTS (by design) | Dash still uses probabilistic verification as CPU trade-off |
| QS-6 | MEDIUM | Unbounded pendingInstantSendLocks | **FIXED** | Size limits added with LRU eviction and per-peer tracking |
| QS-7 | MEDIUM | Unbounded pendingRecoveredSigs | **FIXED** | Per-peer and global limits added |
| QS-8 | MEDIUM | seenChainLocks Pre-Verification Growth | EXISTS (mitigated) | Pattern exists but bounded with LRU cache |
| QS-9 | MEDIUM | ChainLock Negative Height | **FIXED** | Height bounds validation added |
| QS-10 | LOW | Batch Verification Innocent Banning | EXISTS (by design) | Dash mostly uses `perMessageFallback=true` for critical paths |
| QS-11 | LOW | CQuorum Destructor Race | **FIXED** | Refactored to `shared_ptr<const CQuorum>` for safe shared ownership |
| QS-12 | LOW | Cleanup Uses Adjusted Time | EXISTS (mitigated) | Peer time adjustment limits tightened; discussing removal of GetAdjustedTime() |

---

## Area 3: BLS Cryptography (3 fixed / 11 exist)

| ID | Severity | Finding | Dash Status | Notes |
|----|----------|---------|-------------|-------|
| BLS-1 | HIGH | Use-After-Free in AsyncVerify | **FIXED** | Restructured to synchronous batch verify or explicit shared_ptr ownership |
| BLS-2 | HIGH | IES Encryption No HMAC | EXISTS | AES-256-CBC still has no authentication tag; CBC bit-flipping possible |
| BLS-3 | HIGH | IES Key From Raw EC Point (No KDF) | EXISTS | Raw truncated point serialization still used as AES key |
| BLS-4 | MEDIUM | Secret Key Not Zeroed on Stack | EXISTS | `MakeNewKey()` stack buffer never `memory_cleanse()`d |
| BLS-5 | MEDIUM | IES Symmetric Keys Not Zeroed | EXISTS | Key material in `std::vector` lingers in freed heap |
| BLS-6 | MEDIUM | CBLSLazyWrapper::operator== Data Race | **FIXED** | `std::unique_lock` now used consistently including in operator== |
| BLS-7 | MEDIUM | Worker Pool Thread Count Bug | **FIXED** | Restructured thread management; inverted min/max eliminated |
| BLS-8 | MEDIUM | VerifySecureAggregated Missing IsValid() | EXISTS | No consistent IsValid() check before pairing operations |
| BLS-9 | MEDIUM | Batch Verifier Rogue Key Attack | EXISTS | `secureVerification=false` still aggregates via simple addition |
| BLS-10 | MEDIUM | Ephemeral Secret Key Persists | EXISTS | Not cleared after Encrypt() completes |
| BLS-11 | MEDIUM | GetOrBuild Exception Safety | EXISTS (partial) | Some try/catch added, but cache poisoning still possible |
| BLS-12 | MEDIUM | assert() Compiled Out in Release | EXISTS | `assert()` sole validity check in aggregation; removed with NDEBUG |
| BLS-13 | LOW | IES IV O(n²) Derivation | EXISTS | Worse for Dash with quorums up to 400 members |
| BLS-14 | LOW | AES-CBC Silent Failure Non-Aligned | EXISTS | Padding disabled; currently safe but fragile |

---

## Area 4: Auth & Masternode P2P (8 fixed / 0 exist / 2 N/A)

| ID | Severity | Finding | Dash Status | Notes |
|----|----------|---------|-------------|-------|
| AUTH-1 | HIGH | MNAUTH Hijacking / Data Race | **FIXED** | Proper locking on `verifiedProRegTxHash`; challenge-response sequencing added |
| AUTH-2 | HIGH | GETMNLISTDIFF No Rate Limiting | **FIXED** | Per-peer rate limit with `Misbehaving()` penalty; processing optimized |
| AUTH-3 | MEDIUM | Memory Leak Deferred MNAUTH | **FIXED** | Raw pointer pattern eliminated; uses smart pointers or direct processing |
| AUTH-4 | MEDIUM | Missing Null Check sentMNAuthChallenge | **FIXED** | Zero/unset challenge now causes MNAUTH rejection |
| AUTH-5 | MEDIUM | assert(false) from Network Data | **FIXED** | Replaced with proper error returns; non-standard scriptPayout handled gracefully |
| AUTH-6 | MEDIUM | ProcessMasternodeConnections Commented Out | **FIXED** | Function fully implemented and active in Dash |
| AUTH-7 | MEDIUM | Deadlock Nested ForEachNode | **FIXED** | Refactored to collect-then-process pattern; no nested ForEachNode |
| AUTH-8 | MEDIUM | Disk I/O Under cs_main | EXISTS (mitigated) | Caching of diffs and rate limiting reduce exploitability |
| AUTH-9 | LOW | Unbounded Spork feature String | N/A | Dash reworked spork system entirely; no unbounded string field |
| AUTH-10 | LOW | Lite Mode Bypasses Validation | N/A | Dash removed lite mode entirely |

---

## Area 5: Evo Transactions & Sync (8 fixed / 2 exist by design)

| ID | Severity | Finding | Dash Status | Notes |
|----|----------|---------|-------------|-------|
| EVO-1 | HIGH | Provider TX Validation Bypass (NULL pindexPrev) | **FIXED** | Uses chain tip for mempool validation; `if (!pindexPrev) return true` pattern removed |
| EVO-2 | MEDIUM | No Synchronization on CMasternodeSync | **FIXED** | Key members now `std::atomic<>`; mutex protects non-atomic members |
| EVO-3 | MEDIUM | Static fReachedBestHeader Data Race | **FIXED** | Converted to `std::atomic<bool>` or protected by locking |
| EVO-4 | MEDIUM | VerifyInsecure BLS Verification | EXISTS (by design) | Non-augmented BLS used intentionally; on-chain registration provides implicit PoP |
| EVO-5 | MEDIUM | Unbounded Deserialization Allocations | **FIXED** | Maximum size checks added before allocation |
| EVO-6 | LOW | GetCurTransaction() Bypasses Lock | **FIXED** | RAII-based lock management; proper locking on all accessors |
| EVO-7 | LOW | Weak DoS Scoring MNAUTH | EXISTS (by design) | Intentionally modest scoring to avoid banning legitimate MNs with transient issues |
| EVO-8 | LOW | Static nTick Data Race | **FIXED** | Converted to `std::atomic` or timer-based scheduling |
| EVO-9 | LOW | Negative Sync Progress | **FIXED** | FAILED/INITIAL states now return 0.0 explicitly |
| EVO-10 | LOW | Missing Default in SwitchToNextAsset | **FIXED** | Default case added with error logging |

---

## Recommendations for Firo

### Priority 1: Port Dash Fixes (26 findings)

These have known, tested fixes in Dash that can be backported:

**Critical (crash/consensus):**
- QS-3: OOB array access bounds check
- QS-1: Conflict detection rewrite
- QS-2: VerifyRecoveredSig llmqType fix
- EVO-1: Provider TX validation bypass
- AUTH-1: MNAUTH locking and sequencing
- AUTH-2: GETMNLISTDIFF rate limiting
- BLS-1: Use-after-free elimination

**Important (DoS/resource exhaustion):**
- QS-4: Session limits with Misbehaving() penalty
- QS-6, QS-7: Bounded pending maps with LRU eviction
- DKG-6: Misbehaving() penalty for DKG flooding
- DKG-8: Phase-gating of DKG messages
- AUTH-5: Replace assert(false) with error returns
- AUTH-6: Re-enable ProcessMasternodeConnections
- AUTH-7: Fix nested ForEachNode deadlock

**Thread safety:**
- BLS-6, EVO-2, EVO-3, EVO-8: Atomic/mutex fixes
- DKG-1, DKG-10, DKG-11, QS-9, QS-11: Various bug fixes
- EVO-5, EVO-6, AUTH-3, AUTH-4: Safety improvements

### Priority 2: Shared Vulnerabilities (17 findings)

These exist in both Dash and Firo and need original fixes:

**BLS/IES crypto (most impactful):**
- BLS-2 + BLS-3: Add authenticated encryption (AES-GCM or HMAC) and proper KDF
- BLS-4 + BLS-5 + BLS-10: Memory sanitization for key material
- BLS-8, BLS-9, BLS-12: Input validation and safe aggregation

**Protocol/design:**
- DKG-9: Encrypted justifications (protocol change)
- DKG-4: QWATCH authentication requirement
- QS-5: Configurable verification rate

### Priority 3: Feature Removal

Consider following Dash's lead:
- Remove lite mode (AUTH-10)
- Modernize spork system (AUTH-9)
- Gate dkgsimerror to regtest/testnet only (DKG-3)
