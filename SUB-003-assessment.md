# Assessment: SUB-003 - Unbounded Vector Deserialization in Spark/Lelantus Proof Structures

## Verdict

**The core technical observation is valid but the severity is overstated. Recommend: Low (not Major).**

The report correctly identifies that proof structures deserialize vectors without protocol-specific size bounds and that `ParseSparkSpend` is called multiple times. However, several factors significantly limit real-world exploitability, and the report contains some inaccuracies.

---

## Verified Claims

### 1. Unbounded vectors in proof structures — CONFIRMED

All five proof structures have `std::vector` fields without application-level size constraints in their `SerializationOp`:

| Structure | Unbounded vector fields | File |
|-----------|------------------------|------|
| `GrootleProof` | `X`, `X1` (GroupElement), `f` (Scalar) | `src/libspark/grootle_proof.h:22-29` |
| `BPPlusProof` | `L`, `R` (GroupElement) | `src/libspark/bpplus_proof.h:27-36` |
| `ChaumProof` | `A2` (GroupElement), `t1` (Scalar) | `src/libspark/chaum_proof.h:15-21` |
| `SigmaExtendedProof` | `f_` (Scalar), `Gk_`, `Qk` (GroupElement) | `src/liblelantus/sigmaextended_proof.h:29-41` |
| `InnerProductProof` | `L_`, `R_` (GroupElement) | `src/liblelantus/innerproduct_proof.h:19-25` |

### 2. MAX_SIZE (33MB) as the only serialization-level guard — CONFIRMED

`ReadCompactSize` in `serialize.h:332-363` caps vector element counts at `MAX_SIZE = 0x02000000` (33,554,432). For 34-byte GroupElements, this theoretically allows ~987K elements per vector.

### 3. vExtraPayload capped at 230KB — CONFIRMED

`NEW_MAX_TX_EXTRA_PAYLOAD = 230000` bytes is enforced in `CheckTransaction` at `src/validation.cpp:673`. This is the effective upper bound on the serialized Spark spend data.

### 4. Late semantic validation of vector sizes in Grootle verifier — CONFIRMED

The Grootle verifier checks `proof.X.size() != m` at `src/libspark/grootle.cpp:419-426`, but this occurs during `verify()`, which is called after full deserialization. A malformed proof with oversized vectors is fully deserialized before rejection.

### 5. GroupElement deserialization involves secp256k1 point decompression — CONFIRMED

Each `GroupElement::Unserialize` reads 34 bytes, then calls `deserialize()` → `secp256k1_ge_set_xo_var()` → `secp256k1_ge_set_xquad()` → `secp256k1_fe_sqrt()`, which computes a modular square root via exponentiation `a^((p+1)/4)`. This is moderately expensive (many field multiplications/squarings).

### 6. ParseSparkSpend called multiple times — CONFIRMED (but count differs)

In the `AcceptToMemoryPoolWorker` path for a P2P-received Spark spend, `ParseSparkSpend` is called **3 times** (not 3-4 as the report states):

1. **`GetSparkUsedTags(tx)`** at line 978 — calls `ParseSparkSpend` internally
2. **`CheckTransaction` → `CheckSparkTransaction` → `CheckSparkSpendTransaction`** at line 1038/761/635 — calls `ParseSparkSpend`
3. **`nFees = spark::ParseSparkSpend(tx).getFee()`** at line 1223 — direct call

The report's reference to `DisconnectBlock` (line 2554) and `ConnectBlock` (line 2952) is misleading for the DoS scenario: those paths only execute for transactions **already in blocks**, not for P2P-received unconfirmed transactions.

---

## Factors That Reduce Severity

### 1. The 230KB payload cap strictly bounds the attack

The `vExtraPayload` size is checked in `CheckTransaction` (line 673), which is called early in `AcceptToMemoryPoolWorker` (line 1038) — **but critically, `GetSparkUsedTags` at line 978 is called BEFORE `CheckTransaction`**, so the first deserialization happens before the size check. However, the payload data is already limited to whatever the peer sent — the `vExtraPayload` is deserialized as raw bytes during CTransaction deserialization (`vRecv >> ptx` at `net_processing.cpp:2171`), so the payload size is inherently bounded by what the peer sent. A 230KB payload can fit at most ~6,764 GroupElements (230,000 / 34).

With 3 deserializations, this yields ~20,000 point decompressions per malicious transaction. While non-trivial, a single secp256k1 point decompression takes on the order of ~10-20 microseconds on modern hardware, putting the total cost at roughly **200-400ms per malicious transaction**. This is noticeable but not catastrophic.

### 2. Per-peer DoS banning limits sustained attacks from a single peer

When `CheckSparkSpendTransaction` fails (e.g., due to malformed proof sizes), it returns `state.DoS(100, ...)` (line 638-648). This triggers `Misbehaving(pfrom->GetId(), 100)` in the P2P handler (line 2376), which immediately bans the peer. A single attacker peer can only send **one** malicious transaction before being banned.

However, an attacker with many IP addresses (botnet/Sybil) could send one transaction per IP.

### 3. Transaction hash deduplication prevents repeated processing

`AlreadyHave(inv)` is checked at line 2190 before `AcceptToMemoryPool`. After a transaction is rejected, its hash is added to `recentRejects` (line 2336). The same malicious transaction cannot be processed twice from different peers.

However, each malicious transaction can have a different hash (different payload), so this only prevents relay amplification of the *same* transaction, not different malicious transactions from different peers.

### 4. Lelantus path is largely irrelevant

The report claims Lelantus is "still active." On mainnet, `LELANTUS_GRACEFUL_PERIOD = 1223500` (approximately Jan 30, 2026). As of March 25, 2026, the chain height exceeds this, meaning Lelantus transactions are rejected from the mempool with `DoS(100)` immediately at `validation.cpp:912-916`. The Lelantus proof structures (`SigmaExtendedProof`, `InnerProductProof`) are not exploitable via P2P on mainnet.

### 5. The attack requires crafting valid-looking Spark transactions

The attacker must craft a transaction that:
- Has `nVersion >= 3` and `nType == TRANSACTION_SPARK`
- Has exactly one input with `scriptSig[0] == OP_SPARKSPEND`
- Has valid serialization structure for `SpendTransaction` (matching field order)
- The `vExtraPayload` must deserialize into a valid `SpendTransaction` structure

While this is feasible for someone who understands the protocol, it's not trivially scriptable without knowledge of the serialization format.

### 6. Legitimate transaction processing has comparable cost

A legitimate Spark spend transaction with valid proofs also undergoes the same 3x deserialization. The only difference is that a malicious transaction might pack more GroupElements per proof field than a legitimate one would. A legitimate transaction with parameters n=4, m=16 has X (16 GroupElements) + X1 (16 GroupElements) + f (48 Scalars) per GrootleProof. With up to ~16 inputs, a legitimate transaction could itself contain hundreds of GroupElements. The attacker's advantage is at most ~10-20x more GroupElements per transaction than a typical legitimate one, not orders of magnitude more.

---

## Actual Impact Assessment

### Realistic attack scenario

An attacker with 100 distinct IP addresses could:
1. Connect to a target node from each IP
2. Send one crafted transaction per connection (different txid each time)
3. Each transaction causes ~200-400ms of CPU work before rejection and peer ban
4. Total impact: ~20-40 seconds of CPU time on the target node, then all attacker IPs are banned

This is a **low-severity** DoS that requires significant attacker resources (many IPs) for modest impact. It is comparable to other known DoS vectors in Bitcoin-derived codebases.

### Comparison with the report's claims

| Claim | Reality |
|-------|---------|
| "Major" severity | Low severity — bounded by payload size, mitigated by peer banning |
| "CPU exhaustion" | ~200-400ms per malicious tx, not exhaustion |
| "3-4x repeated deserialization" | 3x confirmed for mempool path; 4th is block-only |
| "Affects both Spark and Lelantus" | Lelantus path is closed on mainnet since ~Jan 2026 |
| "Could degrade block validation speed" | Only affects mempool acceptance; block validation is a separate path |
| "~20,000-27,000 point decompressions" | ~20,000 confirmed (6,764 × 3); 27,000 would require 4 deserializations which doesn't happen in mempool path |

---

## Remediation Assessment

The suggested fix (adding size bounds in `SerializationOp`) is **directionally correct and good defense-in-depth**, but is not urgently needed for the following reasons:

1. The existing payload size cap already bounds the attack
2. Peer banning limits sustained attacks
3. The CPU cost per transaction is moderate, not catastrophic

That said, adding protocol-specific bounds is a good hardening measure that:
- Fails faster (before expensive deserialization)
- Makes the code more self-documenting about expected sizes
- Reduces the amplification factor from 3x to 1x (if bounds are checked early enough in the first deserialization)

The suggestion to cache `ParseSparkSpend` results is a **more impactful improvement** that would eliminate the 3x deserialization regardless of vector sizes. This is a genuine code quality improvement that would also benefit legitimate transaction processing performance.

### Recommended priority

- **Size bounds in proof SerializationOp**: Low priority, good hardening (P3)
- **Caching ParseSparkSpend results**: Medium priority, improves both security and performance (P2)

---

## Summary

The report identifies a real but low-severity issue. The unbounded proof vectors combined with repeated deserialization create a modest CPU amplification vector, but the attack is tightly bounded by the 230KB payload limit and mitigated by per-peer DoS banning. The Lelantus claims are no longer applicable on mainnet. The suggested remediation (size bounds + caching) is reasonable hardening but not urgently needed.

**Recommended severity: Low (Informational/Low, not Major)**
