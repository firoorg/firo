# Helsing (private masternode collateral): security review, optimizations, and privacy options

Review of Aaron Feickert's technical note *Helsing: Private Masternode Staking* (26 Jan 2022) and the
*Revised Lightweight Specification* (draft dated 2026-05-01, Markdown and PDF versions), checked against
the Lelantus Spark paper (ePrint 2021/1173) and against the Firo implementation at commit `af75057`
(branch `claude/sleepy-hypatia-2z59yg`).

The Markdown and PDF versions of the revised spec were compared section by section; they have the same
content (31 sections, same equations and pseudocode). Nothing in the PDF is missing from the Markdown.

All file references below are relative to `src/` in this repository.

---

## 1. Summary

**The core idea is sound and does what Reuben asked for.** An accepted Helsing stake proves, with exactly
the same assumptions as Spark's own double-spend protection, that some coin in the referenced cover set
has value exactly 1000 FIRO and spend tag `T`, and that no coin with that tag has ever been spent. Any
later Spark spend of that coin must reveal the same `T` (Spark paper, Lemma 1), so the collateral
cannot move without the network noticing. A break of this guarantee is a break of Spark's balance or
non-malleability proofs.

**The every-block check is as cheap as it can be.** Nothing per masternode is recomputed each block. The
only work is, for every tag revealed by a Spark spend in the block, one hash-map lookup against the
active-collateral map. Firo's deterministic masternode list already does precisely this for transparent
collateral (`evo/deterministicmns.cpp:857-877` looks up every `vin.prevout` in `mnUniquePropertyMap`);
replacing the outpoint with the tag keeps the cost at microseconds per block whatever the masternode count.

**Registration is the only expensive step**, and it costs the same as one extra input in a Spark spend:
one parallel one-of-many (Grootle) proof over the cover set. Measured on this sandbox (single core,
Firo parameters n = 8, m = 5, N = 32768):

| Proof | Verify, standalone | Verify, batched on the same cover set | Size |
|---|---|---|---|
| Grootle, 32,768-coin set | 2,370 ms | 321 ms per proof (batch of 8) | 1,624 bytes |
| Grootle, 8,192-coin set | 854 ms | 83 ms per proof | 1,624 bytes |
| Chaum V2 tag proof, 1 input | 0.5 ms | n/a | 164 bytes |
| Schnorr (representation) | 0.1 ms | n/a | 66 bytes |

So migrating a few thousand masternodes costs roughly the same initial-sync time as the same number of
Spark spend inputs, and is amortised by the batch verification Firo already performs. If even that is
unwanted, Section 5.7 describes an "internal collateral" variant (the Spark analogue of today's
`protx register_fund`) that needs no Grootle proof at all (about 0.6 ms per registration) at a modest,
clearly described privacy cost.

**The revised spec closes the gaps of the 2022 note** (one active stake per tag, ledger-validated cover
sets, no `f` term, correct payout arity, non-circular payout id, transcript binding). The remaining
problems are mostly about how it would meet Firo's actual transaction and masternode machinery. The
findings that need a design decision before implementation are:

1. **The stake transaction has no inputs and pays no fee** (H-1). This is a verification-DoS vector,
   makes identical replays possible, and if fees were added from transparent inputs it would deanonymise
   the registrant. The fix is to make the registration a Spark spend that pays its fee from Spark inputs
   and binds the registration payload through the spend's existing `extension_commitment`.
2. **`StakeUpdate` transactions can be replayed** (H-2). They have no inputs and the signed message has no
   nonce, so an old update (an old operator key, an old payout address) can be re-applied by anyone.
   DIP3's `ProUpRegTx`/`ProUpServTx` avoid this because they are ordinary transactions whose
   `inputsHash` binds them to spent inputs; keep that model.
3. **The explicit `InCoinIDs` list cannot be used on Firo** (H-3). At N = 32768 it is about 1.2 MB per
   registration, above the 230 KB payload cap, and it would also break the suffix-based batch
   verification. Spark spends reference a cover set by `(group id, block hash)` plus a bound set hash;
   Helsing must do the same.
4. **Deterministic payout coins collide with Firo's duplicate-coin rule** (H-4) once the pending
   Chaum V2 fork activates. The spec's "allow duplicates" rule is not needed if payout coins get their own
   coin type byte and a deterministic, unique serial context; then no mint can ever be byte-identical to
   a payout coin and wallets reject forged look-alikes automatically.
5. The spec's **same-block payout rule** diverges from DIP3's "pay the parent-list payee one last time"
   semantics without closing a real attack (M-1); keeping DIP3 semantics is simpler.

Everything else is either an optimisation (Section 5) or a wallet-policy item (Section 6).

On privacy (Section 6): the link between a registration and the eventual spend of its collateral is
**inherent** to any scheme whose every-block check is a public predicate, so there is no cheap way to
hide deregistration. What can be added cheaply is listed in 6.2; the most valuable items are paying
registration fees from Spark inputs, never staking a mint-created coin (its value is public), using a
fresh diversified Spark address and fresh owner/operator keys per masternode, and keeping the registration
and the later spend on the same cover-set group.

---

## 2. What was reviewed and how

- *Helsing* technical note (8 pages): the Stake/StakeVerify/Payout/PayoutVerify constructions.
- Revised specification (21 pages, Markdown and PDF): consensus state, block processing, updates,
  payouts, duplicate serial commitments, theorems 1 to 5.
- Lelantus Spark paper: coin structure (Section 4), the modified Chaum-Pedersen and parallel one-of-many
  proofs (Appendices A and B), and the balance / non-malleability / ledger-indistinguishability proofs
  (Appendix C), in particular Lemma 1 (two spends reveal the same tag only for coins with the same
  `(x, y)` representation) and footnote 5 (duplicate serial commitments).
- Firo source: `libspark/` (coin, keys, Chaum, Grootle, spend and mint transactions, hashes),
  `spark/state.cpp` (coin groups, cover sets, used tags, duplicate mints, mempool, reorg),
  `evo/` (ProRegTx, deterministic list, unique properties, collateral-spend detection, payouts),
  `masternode-payments.cpp`, `validation.cpp`, `txmempool.cpp`, `miner.cpp`, `chainparams.cpp`.
- A micro-benchmark (`doc/helsing/bench_helsing.cpp`) compiled against the repository's libspark objects.

---

## 3. Does the design guarantee unmoved collateral, cheaply?

### 3.1 Registration-time soundness

The revised spec's Theorem 2 argument holds and is the same argument as Spark's Condition 5 and Lemma 1:

- The Grootle proof yields an index `l`, scalars `a`, `δ` with `S_l - S' = aH` and `C_l - C' = δH`
  (Firo relation: `grootle.cpp:166-171`).
- The representation proof yields `b` with `C' = V·G + bH`, so `C_l = V·G + (b+δ)H`. Every ledger coin's
  `C` has a known opening `vG + mH` with `v < 2^64` (mint: Schnorr on `C - vG`, `mint_transaction.cpp:62-72`;
  spend output: Bulletproof+ range proof). With `V < 2^64 < q`, binding forces `v = V`.
- The tag proof yields `(x, y, z)` with `S' = xF + yG + zH` and `U = xT + yG`, hence
  `S_l = xF + yG + (z+a)H`. Any Spark spend of the coin at index `l` extracts the same `(x, y)` (Lemma 1)
  and therefore the same `T = (U - yG)/x`. If the coin had already been spent, `T` would be in the
  used-tag set (`usedLTags`, `spark/state.h:305`) and the stake is rejected.

Two implementation conditions must hold for this argument, both already true in Firo:

- The tag equation must be checked **per input**, not in aggregate. Firo's historical `verify_v1`
  checks the `U = x_i T_i + y_i G` equations only summed over inputs (`chaum.cpp:132-195`); that is why the
  single-input rule and the componentwise `verify_v2` (`chaum.cpp:314-350`) exist. Helsing must use
  `ChaumProofV2` (or `verify_single_input`).
- The identity element must be rejected for `T` and `S'`; `verify_v2` already does (`chaum.cpp:328-333`).

A malformed serial commitment does not help an attacker: mints do not prove `S` is well formed
(`mint_transaction.cpp:62-72`), but a coin with `S = xF + yG + wH` still has a unique known
representation, its tag is still `(U - yG)/x`, and that is what any spend of it must reveal.

### 3.2 Ongoing detection and its cost

A Spark coin can only be consumed by a Spark spend, and every spend reveals one tag per input
(`spend_transaction.cpp:131`, `spark/state.cpp:1335-1382`). In Firo there is no other path, so the spec's
`helsing_eligible` flag is unnecessary.

The right home for `ActiveTags` is the existing deterministic masternode list: `collateralOutpoint` is
already a unique property of `CDeterministicMN` (`evo/deterministicmns.cpp:441-515`), lookups go through
`mnUniquePropertyMap` (an `immer::map`, effectively O(1)), and the per-block collateral-spend loop is

```cpp
// evo/deterministicmns.cpp:857-877
for (const auto& in : tx.vin) {
    auto dmn = newList.GetMNByCollateral(in.prevout);
    if (dmn && dmn->collateralOutpoint == in.prevout) { ... newList.RemoveMN(dmn->proTxHash); }
}
```

The Helsing version iterates `block.sparkTxInfo->spentLTags` instead (it is complete by the time
`ProcessSpecialTxsInBlock` runs, `validation.cpp:3012-3019`) and looks each tag up as a unique property.
Snapshots, diffs, undo on reorg, the CbTx merkle root and `MNLISTDIFF` for light clients are inherited
unchanged. Cost per block: one hash lookup per Spark spend input, independent of the masternode count.

### 3.3 Registration cost

Only the Grootle proof matters (table in Section 1). Two properties of Firo's implementation keep this
affordable:

- Grootle proofs of all inputs of all transactions in a block that share a cover-set id are verified in
  one multi-exponentiation (`spend_transaction.cpp:544-598`, `grootle.cpp:375-584`); each extra proof adds
  only about 8 points plus O(N) scalar work. That is the 2,370 ms → 321 ms per proof figure above, and it
  also applies inside a single transaction, so a registration carried by a two-input spend (collateral
  input plus fee input) costs about one plain spend plus 0.3 s.
- During initial sync, proofs from blocks older than a day are deferred and batched across blocks
  (`validation.cpp:2310-2330`, `batchproof_container.cpp`).

Several thousand registrations therefore add on the order of tens of minutes of single-core work to a
full sync on hardware like this sandbox, less on a desktop CPU. A per-block cap on registrations is still
advisable (M-4).

---

## 4. Security findings

Severity reflects impact on Firo if the spec were implemented as written. "Spec" findings apply to the
documents; "Firo" findings come from checking the spec against the code.

### H-1 (High, spec): the stake transaction has no inputs and no fee

`HelsingStakeTx` (spec §9) consumes nothing and pays nothing. Consequences:

- Verification DoS: each stake costs a full-set Grootle verification (seconds) and can be produced for
  free; the mempool verifies spends one transaction at a time (`spark/state.cpp:1303-1312`), so the
  2.4 s standalone figure applies.
- Byte-identical replays: a transaction with no inputs can be rebroadcast and re-mined unchanged. Firo
  (like Bitcoin) assumes unique txids outside coinbases; `stake_id = H(tx)` would also collide, and the
  spec's `StakeRecords[stake_id] = {...}` silently overwrites.
- If the obvious fix (transparent inputs for the fee) were used, the registrant's transparent UTXOs would be
  linked to the masternode, defeating the purpose.

**Fix.** Make the registration a Spark spend (V2) that pays its fee from ordinary Spark inputs. The
registration payload (the DIP3 `CProRegTx` fields minus `collateralOutpoint`, plus the index of the
collateral input) is bound through the V2 Chaum context's `extension_commitment`
(`chaum.cpp:231-263`, `spend_transaction.cpp:276-305`), exactly as Spark Names already bind their
`CSparkNameTxData` extension. This also gives the transaction a unique txid (its fee inputs' tags) and
inherits mempool tag-conflict handling, reorg eviction (`RemoveSpendReferencingBlock`), Dandelion relay,
and batch verification. See Section 7 for the full profile.

### H-2 (High, spec): `StakeUpdate` is replayable

`StakeUpdateTx = {stake_id, m_new, sig_update}` (§14) has no inputs, and the signed message
`H("Helsing/update/v1" || stake_id || H(enc_context(m_new)))` contains no nonce, height or previous-state
reference. After an owner updates `m_1 → m_2 → m_3`, anyone can replay the `m_2` update and revert the
masternode to `m_2`: an old operator key (for example a hosting provider that was rotated out), an old
payout address, or an old service address. DIP3 avoids this because every `ProUp*Tx` is an ordinary
transaction whose payload commits to `inputsHash` (`evo/specialtx.cpp:202-209`) and whose inputs are spent.

**Fix.** Keep DIP3's update transactions as they are (owner-signed `ProUpRegTx`, operator-signed
`ProUpServTx` and `ProUpRevTx`, each with inputs). If a Spark-funded variant is wanted, bind the update to
the spend's tags via `extension_commitment` as in H-1. If the inputless form is kept anyway, add a strictly
increasing `update_nonce` to the signed message and store it in the record.

The single `update_pk` in the spec is also a regression from DIP3's owner/operator/voting separation
(operators update service data, owners update operator and payout data). Firo's context `m` should simply
be the existing `CProRegTx` fields.

### H-3 (High, Firo): explicit `InCoinIDs` cannot be used

Spec §8 requires the transaction to list all `N = n^m` output ids. At Firo's parameters that is
32,768 × 36 bytes ≈ 1.2 MB, above `NEW_MAX_TX_EXTRA_PAYLOAD = 230000` (`consensus/consensus.h:38-39`), and
the spec additionally wants validators to look each one up in a `(txid, vout)` index that Firo does not
keep (coin→outpoint resolution reads the block from disk, `spark/state.cpp:1508-1569`, unless `-mobile`).

Arbitrary subsets also have two bad side effects: they let wallets fingerprint themselves by their choice
of decoys, and they defeat Firo's batch verifier, which assumes all proofs on a group use nested suffixes
of one monotonic list (`spend_transaction.h:24-27`, `grootle.cpp:525`).

**Fix.** Reference the cover set exactly as Spark spends do: `cover_set_id` + `block_hash`, with
`cover_set_representation = set_hash(block) || txHashForMetadata` fed into the Grootle transcript
(`spark/state.cpp:1142-1238`). The set hash is a chained SHA-256 over every coin added to the group
(`spark/state.cpp:561-592`), so it gives the "validators reconstruct commitments from the ledger"
property the spec wants, in 32 bytes. `incoins_root` in `stake_stmt` becomes this representation.

### H-4 (High, Firo): deterministic payout coins versus the duplicate-coin rule

The spec (§19) wants creation-time duplicates of serial commitments allowed, because a payout coin is
predictable from public data (`j` depends on the previous block hash) and an attacker could front-run it
with an identical mint.

Firo's rule is not "unique S". From `nSparkChaumV2StartBlock` (mainnet 1,371,000, `chainparams.cpp:423`)
a block is invalid if two coins have the same `Coin::getHash()`, which covers `type, S, K, C, r_` (and `v`
for mints) (`spark/state.cpp:95-113`, `validation.cpp:2949-2954`). Coins that share only `S` are distinct
keys and coexist (`coin.cpp:194-214`). So the question is whether an attacker can mint a coin that is
**byte-identical** to a payout coin. For a payout coin whose nonce `k` is public, every field is
computable: `K = H_k(k)·H_div(d)`, `S` via a crafted `Q2'` (mints do not prove `S` is well formed),
`C = V·G + H_val(k)·H`, and `r_` (the AEAD key is `H_k(k)·Q1`). If the payout coin were an ordinary
`COIN_TYPE_MINT` coin, the forged mint would hash identically, `CheckSparkMintDuplicates` would reject the
block that contains both, and a miner whose template picked up the mempool mint would produce an invalid
block (`TestBlockValidity` fails and `CreateNewBlock` throws until the mint leaves the mempool). That is
a free miner-griefing attack, which is presumably what the spec's rule is meant to prevent.

**Fix.** Do not relax the duplicate rule. Instead:

- Give payout coins their own type byte (`COIN_TYPE_PAYOUT`), their own AEAD associated data
  ("Payout coin data"), and a deterministic unique serial context, for example
  `enc(height) || enc(payout_index) || proTxHash`. A mint can never be byte-identical (the type byte and
  `r_` differ, and from Chaum V2 the opcode/type pairing is enforced, `validation.cpp:581-598`).
- A forged look-alike with the same `S` is then merely a dead coin: no wallet identifies it, because
  `Coin::identify` recomputes `S` under the identifying transaction's own serial context
  (`coin.cpp:128`) and the forger's mint has a different context. This is exactly the mitigation Spark's
  footnote 5 recommends ("binding unique data like linking tags or other additional context into serial
  commitments to be checked during coin identification"), and Firo already implements it for mints and
  spend outputs (`spark/state.cpp:1571-1591`).
- Spec §17 must include the serial context in `S = Comm(H_ser(k, ctx), 0, 0) + Q2` to match Firo's
  coin construction (`coin.cpp:65`).

Wallet note: Firo's Spark wallet keys coin records by tag hash (`spark/sparkwallet.h:254-262`); two
identified coins with the same tag would collide. Under the rule above no forged coin is ever identified,
so no change is needed, but a test for "same-S look-alike is ignored" belongs in the test plan.

### M-1 (Medium, spec): same-block payout rule changes DIP3 semantics without closing an attack

Spec §12 step 5 and §18 steps 5-6 reject a payout to a masternode whose tag appears in `BlockSpentTags`.
Firo pays the payee chosen from the **parent** list and explicitly pays it one last time even if its
collateral is spent in the same block (`evo/deterministicmns.cpp:879-886`, comment "We still pay that MN
one last time however"; `masternode-payments.cpp:212-248`). The "attack" the spec prevents yields one
payout the node had already earned by queue position; the owner gains nothing they could not get by
spending one block later. The spec's rule, on the other hand, makes the payee depend on the block's own
contents and leaves "who is paid instead" undefined (a deterministic fallback would be needed, and miners
would have to re-derive it when the mempool changes).

**Recommendation.** Keep DIP3 semantics: select the payee from the parent list, deactivate on the spend.
If a different rule is wanted, define the fallback payee deterministically (next in queue) and note that
the coinbase can then only be finalised after the block's transaction set is fixed.

### M-2 (Medium, Firo): Spark outputs in the coinbase are currently silently ignored

Today a coinbase may carry an `OP_SPARKMINT`/`OP_SPARKSMINT` output, but `CheckSparkTransaction` is only
reached for non-coinbase transactions (`validation.cpp:709-735`), so such a coin is never validated,
never added to a coin group, and becomes an unspendable UTXO. Spark payouts therefore need explicit
consensus: a coinbase output type carrying the serialised payout coin, recomputed and compared in
`ConnectBlock` (spec §18), then added to the Spark state.

Maturity: Spark has no coinbase-maturity notion, and does not strictly need one, because a spend
references its cover set by block hash and is evicted when that block is disconnected
(`spark/state.cpp:723-760`), so a reorg that removes a payout coin also removes every spend that used it.
With ChainLocks, deep reorgs are moot anyway. Either add payout coins to the group at connect time (like
mints) or delay by `COINBASE_MATURITY`; the choice only affects how much a reorg can cascade and should be
stated in the spec.

### M-3 (Medium, spec/wallet): staking a mint-created coin leaks its value

Cover sets contain both mint coins (public value, `coin.h:137-139`) and spend outputs (hidden value). The
registration proves the collateral has value exactly 1000 FIRO, so an observer can exclude every mint coin
whose public value is not 1000 FIRO from the candidate set, and if the collateral itself was minted
directly at 1000 FIRO it is one of very few candidates. The spec's privacy analysis does not mention this.

**Fix (wallet policy, spec note).** Only stake coins created as Spark spend outputs; the wallet should
refuse to stake a `COIN_TYPE_MINT` coin and instead perform a self-spend first. The effective anonymity
set is "hidden-value coins plus 1000-FIRO mints in the group", which should be stated.

### M-4 (Medium, Firo): no bound on registration verification work per block

Firo has no per-block limit on the number of Spark spends or inputs, only on transparent value
(`spark/state.cpp:777-798`). A block full of registrations is a block full of Grootle proofs. The same
is true of spends today, but registrations have no value limit to lean on. Add a consensus cap on
Helsing registrations per block (something like 16, i.e. a few seconds of worst-case extra validation),
and keep the DoS-score-100 rejection of invalid proofs.

### M-5 (Medium, implementation hazard): the collateral input must stay out of the balance proof

If registration reuses the spend structure (Section 7), the collateral input's value commitment offset
must **not** be added to the balance statement `Σ C'_in - Σ C_out - (f + vout)·G` (`spend_transaction.cpp:205-222`).
Adding it with a compensating `-V·G` term is unsound: the balance proof would only establish
`v_collateral - V = (Σ v_out + f + vout) - Σ v_fee_inputs`, so a 2,000-FIRO coin could be registered as
collateral while 1,000 FIRO of its value is paid out, and the coin remains unspent and spendable later.
The collateral's value must be fixed independently, by `C' = V·G` (Section 5.2) or by a separate
representation proof, and excluded from the balance. Likewise, never express the stake as "a spend with
fee = V_STAKE": the fee field feeds block fee accounting (`validation.cpp:2965-2981`).

### M-6 (Medium, spec): binding does not cover the proofs themselves

`stake_stmt` (§5.2) binds the cover set, offsets, tag, value and context, but not `Π_par` or `Π_val`.
Spark's non-malleability proof (Appendix C.3) relies on `μ` binding **every** transaction element except
the Chaum proof. Producing a second accepting Σ-protocol transcript for the same statement without the
witness is a forgery, so this is not exploitable by third parties in the random-oracle model, but the
registrant's own ability to produce several distinct valid transactions for one stake, and the spec's
`stake_id = H(canonical(tx))`, should not depend on that argument. Bind everything except the tag proof
(the H-1 design does this for free: `extension_commitment` covers the payload, the Chaum V2 transcript
covers outputs, fee, cover-set references, and `μ` covers the Grootle and balance proofs,
`spend_transaction.cpp:609-647`).

### M-7 (Medium, Firo): mempool and miner conflict handling

A stake and a spend of the same coin may both sit in the mempool. Block validation handles the ordering
(spec §12), but the miner must not include both, and the mempool should treat them as conflicting, the way
`existsProviderTxConflict` and `removeProTxSpentCollateralConflicts` do for transparent collateral
(`txmempool.cpp:936-977, 1389-1410`). With the H-1 design the collateral tag is tracked as a "pending
active" tag next to `mempoolLTags` (`spark/state.h:119-149`); a spend revealing it evicts the stake, and a
stake whose tag is in the mempool's spent set is rejected.

### M-8 (Medium, spec): undefined `expired`/`deactivated` states, and the replay they would enable

`StakeRecord.status` lists `expired` and `deactivated` but no transaction or rule produces them. If a
stake could leave `ActiveTags` without its tag being spent, the tag would become re-registrable, and with
the inputless stake of H-1 a byte-identical replay would re-activate the old registration (old keys,
old payout address) without the owner's involvement. DIP3 has no expiry; PoSe-banned nodes stay in the list
(`evo/deterministicmns.cpp:305-356`) and are revived by `ProUpServTx`. Keep that model and drop the
unused states, or define them together with a rule that a `stake_id` can never be inserted twice.

### M-9 (Medium, spec/Firo): operator reward split

Firo coinbases can pay two outputs per block (owner share and `nOperatorReward` share to
`scriptOperatorPayout`, `masternode-payments.cpp:227-246`). Spec §15 supports one payout address. Either
both shares need Spark addresses (two deterministic coins, distinct `payout_index`) or operator payouts stay
transparent.

### L-1 (Low, spec): Theorem 2 presentation

The binding step should say that uniqueness of the extracted `(x, y)` is what matters (Lemma 1), not that
the ledger coin "has" a particular representation; mint coins are not proven well formed. The conclusion
is unchanged.

### L-2 (Low, spec): unnecessary objects

`helsing_eligible`, the `SparkOutputs` map keyed by `(txid, vout)`, `STAKE_MATURITY` (DIP3's queue puts a
new node at the end: never-paid nodes sort by `nRegisteredHeight`, `evo/deterministicmns.cpp:194-255`),
the `C'` mask `b` and `Π_val` (Section 5.2), and the "non-subgroup point" checks (secp256k1 has cofactor 1;
only on-curve and non-infinity checks apply) can all be removed for Firo.

### L-3 (Low, spec): `StakeVerify` state checks versus block ordering

§11 step 4 checks `state.ActiveTags` and `state.SpentTags`; §12 step 3 repeats them against
`BlockSpentTags` and other stakes in the block. That is correct, but the spec should say that the
`state_at_parent` used by `StakeVerify` is the parent list and that intra-block ordering is defined by
§12 only (spends first, then registrations, then updates), matching `BuildNewListFromBlock`.

### I-1 (Informational, pre-existing in Firo): incoming view keys can compute tags

Firo derives `s2` from a fixed prefix only (`libspark/keys.cpp:33-41`, documented as consensus-critical
and shared by every deployed wallet). Since `P2 = s2·F + D`, anyone holding an incoming view key `(s1, P2)`
can compute `D` and hence every tag of that wallet. For Helsing this means a party with a masternode
owner's incoming view key can identify which coin is the collateral by recomputing tags and matching the
published `T`. The Spark paper's "full view key required to link a tag to a coin" is, in Firo, "incoming
view key suffices". This is not caused by Helsing and the team is evidently aware of it, but the privacy
analysis should state it.

### I-2 (Informational): `-mobile` index keyed by `S`

`sparkTxHashContext` (`spark/state.cpp:1810-1818`) is keyed by `S` alone and would silently merge a payout
coin with a same-`S` look-alike. It is a mobile-only convenience index, but the H-4 design should key it by
the full coin hash or include the type.

---

## 5. Optimisations

### 5.1 Reference the cover set, do not list it (H-3)

Saves about 1.2 MB per registration and enables batching. Required on Firo in any case.

### 5.2 Drop `C'`, `b`, `H_VAL2` and `Π_val`: set `C' = V_STAKE·G`

The value offset is masked only out of habit from Spark spends, where it feeds a hidden balance equation.
Here `V_STAKE` is public, so hiding it is pointless. Let the verifier compute `C' = V_STAKE·G` itself and
run the Grootle proof with witness `δ = H_val(k)` (the coin's own mask): the relation `C_l - V·G = δH`
with binding already gives `v_l = V` (Section 3.1). This removes one group element, one 66-byte Schnorr
proof, one hash function and one verification from every registration, and shortens the soundness proof.
Zero knowledge is unaffected: the Grootle proof reveals nothing beyond the (public) statement.

### 5.3 Build the registration as a Spark V2 spend with one "collateral input" (H-1)

Reuses verbatim: Grootle proving/verification and per-block batching, Chaum V2 with per-input
equations, the binding hash and `extension_commitment`, mempool tag conflict tracking, reorg eviction,
proof caching, Dandelion relay, fee policy. New logic is confined to: (a) the input marked as collateral is
checked against used tags and active tags but not added to used tags; (b) its `C'` is `V·G` and is
excluded from the balance statement (M-5); (c) the payload is parsed and handed to the deterministic
masternode list. Serialisation: one extra byte per input (collateral flag) and the payload in the
extension, matching the existing Spark Names extension mechanism.

### 5.4 Fold `ActiveTags`/`StakeRecords` into `CDeterministicMNList`

Replace `collateralOutpoint` by a tagged union `{COutPoint | GroupElement collateralTag}` in
`CDeterministicMN` (serialisation versioned; `UpgradeDBIfNeeded` path exists,
`evo/deterministicmns.cpp:1042-1152`), register the tag as a unique property, add `GetMNByCollateralTag`.
This gives the "at most one active stake per tag" invariant, per-block undo, snapshots every 576 blocks,
and light-client list diffs without new consensus state. `CalculateQuorum`'s tie-break on
`collateralOutpoint` (`evo/deterministicmns.cpp:265`) needs an equivalent (tag hash).

### 5.5 Batch registrations with the block's spends

Firo's batch verifier buckets Grootle proofs by cover-set id across all transactions in the block and uses
suffix semantics, so a registration that references any block of the current group is verified together
with every spend on that group (321 ms marginal rather than 2,370 ms standalone in the measurement).
Wallets should reference the newest block of the group (they already do for spends,
`spark/state.cpp:2019-2073`), which also maximises the anonymity set.

### 5.6 Bound the work: cap registrations per block (M-4)

### 5.7 "Internal collateral" variant: no Grootle proof at all

DIP3 has two registration modes: `register` (existing external UTXO, signed by its key) and
`register_fund` (the ProRegTx itself creates the 1000-FIRO output, no signature needed). Helsing as
specified is the Spark analogue of `register`. The analogue of `register_fund` is cheaper:

- The registration is a Spark spend whose outputs include a fresh 1000-FIRO coin `(S_out, K_out, C_out)`
  to the registrant's own address.
- The payload publishes `T` for that coin plus a Chaum V2 proof for `(S_out, T)` (the registrant knows
  `s` and `r` because it is their own address) and a Schnorr proof that `C_out - 1000·G` is a multiple of
  `H` (or simply reveals `H_val(k)`; the value is public by design).
- No one-of-many proof: verification is about 0.6 ms (Chaum + Schnorr) instead of 300 to 2,400 ms, and
  nothing about cover sets, offsets, `H_SER2`, or overlap-aware later spending is needed.

Privacy comparison with the spec's design (both assuming fees come from Spark inputs):

- Same: the registration's funding inputs are hidden in their cover sets; the later spend of the
  collateral is linked to the registration by `T` (inherent, Section 6.1); outputs of the deregistration
  spend are hidden.
- Worse: the collateral coin is a *known* coin. Its later spend has one input with zero ambiguity (versus
  "one of the staking cover set"), and third parties lose a little: every active collateral coin is known
  to be unspendable while active, and known-spent afterwards, so it can be excluded from other users'
  effective anonymity sets (a few thousand coins spread over 32,000-coin groups).
- Equivalent in practice for the registrant: in the spec's design the eventual spend tells an observer the
  collateral was one of the staking cover set, created before the referenced block; in this variant it
  tells them it was the registration's output, created by a transaction whose inputs are hidden. Neither
  reveals the collateral's history beyond "funded by hidden Spark inputs".

Both modes can coexist (as `register` and `register_fund` do today). If initial-sync cost or
implementation size is the main concern, this variant is the lightweight path; if hiding the collateral
coin inside the regular anonymity set matters, keep the one-of-many design.

### 5.8 Payout coins as ordinary Spark coins with deterministic data (H-4)

Use the standard `Coin` constructor with deterministic `k = H_PAYOUT(j, d, Q1, Q2)`, type
`COIN_TYPE_PAYOUT`, payout-specific AEAD associated data, deterministic serial context, and the normal
encrypted recipient data (the AEAD key `H_k(k)·Q1` and the zero nonce are fine: distinct `j` give distinct
keys, and payout coins have no confidentiality to protect). Wallets then identify payout coins through the
unchanged `identify`/`recover` path, only needing to know the serial context rule.

---

## 6. Privacy

### 6.1 What cannot be hidden cheaply

Let `P(reg, spend)` be the every-block predicate that decides whether a spend deactivates a registration.
Soundness requires `P = deactivate` whenever the spend consumes the collateral; correctness requires
`P = ignore` for every other spend (or honest nodes would be deactivated by strangers). Every validator
evaluates `P` on public data, so `P` is a public distinguisher between "this spend moves the collateral"
and "it does not". **Linkability of the deregistration spend to the registration is therefore inherent to
any design with a cheap public check**, not a weakness of this one.

The only known way around it is to make every Spark spend carry a proof that its tag is *not* among the
active collateral tags (a non-membership proof, cost proportional to the number of masternodes or an
accumulator), have consensus reject spends of active collateral, and deregister through an explicit
revoke. That would also hard-lock the collateral. It is incompatible with the "cheap every block" goal
and is not recommended.

For the same reason, payouts cannot hide the payee, the amount (consensus-fixed anyway) or the payout
address: validators must recompute the coin. Variants that hide the address (a commitment in `m`, a
payment proof against a hidden address) need either the address or a SNARK.

### 6.2 What can be added at low cost

1. **Pay registration fees from Spark inputs** (H-1). Without this, every registration is linked to a
   transparent UTXO.
2. **Never stake a mint-created coin** (M-3); self-spend first. State the effective anonymity set.
3. **Use the full group as cover set**, referencing the newest block (5.5), and **spend the collateral
   later on the same `cover_set_id`**. In Firo, groups are monotonic and overlap by about 8,000 coins at
   roll-over (`spark/state.cpp:1768-1820`), so a spend on the same group has the staking set as a subset and
   the spec's "intersection" leak collapses to the staking set itself. A spend on the *next* group (if the
   coin is in the overlap window) shrinks the intersection to that window; wallets should avoid it.
4. **One diversified Spark address per masternode, fresh owner/operator/voting keys per masternode.**
   Diversified addresses are unlinkable without the incoming view key, so an operator running several
   nodes is not linkable across them through payouts (today's transparent payout addresses are).
5. **Relay registrations over Dandelion++** like spends (policy; follows from the H-1 design).
6. **Spark payouts** are a fee and convenience improvement rather than a privacy one: a transparent payout
   followed by a mint leaks exactly the same information (address, amount, resulting coin). Phase 1 could
   ship private collateral with transparent payouts and add Spark payouts later without redesign.
7. **Domain-separate the stake offsets** (`H_SER2` with chain id and a "stake" label, as the spec does) so
   a registration's `S'` never equals the later spend's `S'`; they are linked by `T` anyway, but there is
   no reason to hand out a second linking handle.
8. **Internal-collateral mode** (5.7) does not hide the collateral coin but does hide its funding; if
   adopted, consider keeping collateral coins in regular groups (no pollution of regular cover sets beyond
   what is listed in 5.7) and let the wallet consolidate payout coins only through spends.

### 6.3 Residual leaks to document

- Registration time and the referenced block bound the collateral's creation height from above.
- The context `m` (service address, keys, payout address) is public, as today.
- Anyone with the owner's incoming view key can identify the collateral (I-1).
- The number of registrations per epoch and their cover-set groups are public.

---

## 7. Suggested Firo profile (delta from the revised spec)

Registration (replaces §8 to §11):

- A `TRANSACTION_SPARK_V2` spend (hard fork, could ride with Chaum V2 at 1,371,000) with
  `w ≥ 2` inputs; one input carries a `collateral` flag. The extension (bound by `extension_commitment`)
  holds `CProRegTx` fields minus `collateralOutpoint` plus `collateralInputIndex`.
- For the collateral input: Grootle statement `(S_i, C_i)`, `S' = sF + rG - H_SER2(s, D)·H`,
  `C' = V_STAKE·G` (verifier-computed, not transmitted), witness `(l, H_SER2(s, D), H_val(k))`;
  Chaum V2 entry `(S', T)` with witness `(s, r, -H_SER2(s, D))`; `T` checked against `usedLTags`,
  the mempool's spent and pending-active tags, and the DML's unique properties; not added to `usedLTags`;
  excluded from the balance statement (M-5).
- Fee inputs are ordinary. Outputs are ordinary (change). `f` is the real fee.
- Payload rules as `CheckProRegTx` today minus the collateral checks (`evo/providertx.cpp:86-213`), plus:
  registrations per block ≤ cap.

State (replaces §6, §12, §13): `CDeterministicMN.collateral` is `{outpoint | tag}`; tag is a unique
property; `BuildNewListFromBlock` removes masternodes whose tag is in `block.sparkTxInfo->spentLTags`
(spends are processed before registrations, registrations before updates, as the spec orders); payee from
the parent list as today.

Updates (replaces §14): unchanged DIP3 `ProUpServTx`/`ProUpRegTx`/`ProUpRevTx`; drop the collateral
key-reuse check in `CheckProUpRegTx` for tag collateral.

Payouts (replaces §15 to §19), if adopted: coinbase output carrying a `COIN_TYPE_PAYOUT` coin,
`j = H(chain_id || height || prev_block_hash || payout_index || proTxHash)`, serial context
`height || payout_index || proTxHash`, recomputed in `ConnectBlock`; duplicate rule unchanged.

Wallet: lock the collateral coin by tag (`coinMeta` lookup by tag hash) the way
`AutoLockMasternodeCollaterals` locks outpoints; refuse mint-created coins; prefer the newest block of the
group; spend collateral only on its own group.

---

## 8. Questions for the team before implementation

1. Is private **payout** in scope for the first release, or only private **collateral**? Transparent payouts
   plus Spark collateral is a much smaller change (no coinbase coin type, no H-4, no M-2, no M-9).
2. Keep DIP3's "spending the collateral deregisters the node" semantics (recommended), or hard-lock active
   collateral and require an explicit revoke before it can be spent?
3. Cover-set registration (spec design), internal-collateral registration (5.7), or both modes?
4. If Spark payouts: must the operator-reward share also be a Spark coin?
5. Is a registration cost equal to one extra Spark spend input, with a per-block cap, acceptable for the
   migration period?
6. Should the activation be tied to the pending Chaum V2 hard fork, since Helsing requires `ChaumProofV2`
   semantics and is a hard fork in any case?

---

## Appendix A: benchmark

`doc/helsing/bench_helsing.cpp` links against the repository's `libspark` objects
(`src/CMakeFiles/firo_node.dir/libspark/*.o` from a CMake configure with `BUILD_GUI=OFF`,
`ENABLE_WALLET=OFF`, `BUILD_DAEMON=OFF`) plus `libbitcoin_util`, `libbitcoin_crypto`, `libsecp256k1pp`,
`libunivalue`. It builds a random cover set, proves `batch` Grootle statements over it at indices chosen at
random, verifies one standalone and all in a batch, then times one Chaum V2 proof and one Schnorr proof.
Results above are from one run on this sandbox (`-O2`, single thread, 4-core VM); treat them as
order-of-magnitude figures and re-measure on target hardware.

## Appendix B: spec errata (both documents)

- Technical note, §3: the `f` term makes the coin "of value v + f" but the coin is not consumed, so no fee
  is actually paid; the revised spec removes it correctly but does not say where the fee comes from (H-1).
- Technical note, §4.2: `Payout` is called with three arguments and needs four; fixed in the revised spec.
- Revised spec §4.3 and §10: "tag randomness `r`" is the spend-key component `r` (`D = rG`), not
  randomness; matches Firo's Chaum witness `y = r` (`spend_transaction.cpp:152-155`).
- Revised spec §5: "non-subgroup points" does not apply to secp256k1 (cofactor 1).
- Revised spec §6 and §19: Firo identifies coins by the full coin, not `(txid, vout)`; there is no such
  index in consensus.
- Revised spec §17: `S` omits the serial context that Firo binds into `H_ser` (`coin.cpp:65`); `K` matches
  Firo (`hash_div(d) * hash_k(k)`, `coin.cpp:62`).
- Revised spec §14: signature scheme unspecified; no replay protection (H-2).
- Revised spec §28 checklist item "Duplicate serial commitments are allowed at output creation" should
  become "payout coins are a distinct coin type with a unique serial context" (H-4).
- Revised spec §29 item 9 claims the same-block rule prevents a payout after a collateral spend; see M-1.
