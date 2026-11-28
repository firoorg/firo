# DIP-0024 quorum rotation in Firo

[DIP-0024](https://github.com/dashpay/dips/blob/master/dip-0024.md)
rotates InstantSend quorums a quarter at a time. It does not change
Firo's ChainLocks or the construction of existing quorum types.

## Activation

Rotation is unscheduled on public networks. On a fresh regtest network use
`-dip24height=600` on every node. Quarter selection starts at the first cycle
boundary on or after that height. The first three cycles only record quarters.
The fourth can run DKG. InstantSend switches once every index has a mined quorum
at a completed mining window at least eight blocks behind the tip.

Mainnet parameters are 60 members, a 45-signature threshold, 32 indexes and a
288-block cycle. Testnet uses eight indexes. Regtest uses two four-member
quorums and a 24-block cycle. A public deployment also needs a coordinated fork
height and a masternode upgrade plan.

## Rotation and signing

Each cycle uses the deterministic masternode list eight blocks before its
start. Confirmed, eligible nodes are ranked by the existing quorum score,
with unused nodes first. The selector walks that list once per index at most,
skipping identities retained by that index. Quorum order is oldest to newest
quarter. A retained identity uses the operator key in the current work list;
removed or banned identities cannot contribute. An incomplete quarter history
or fewer than the configured minimum participants prevents a non-null
commitment.

DKG starts at cycle height plus index. Commitments for all slots share a mining
window. A null commitment never removes the previous quorum for that index.
Quarter snapshots are saved even when DKG fails, and are disconnected with the
block that created them. The coinbase quorum root commits to the latest mined
commitment per rotating index, plus the existing active non-rotating quorums.

The signing set only changes after a completed mining window is eight blocks
deep. The low bits of the request ID choose the index. A Firo version-2
`isdlock` names that signing set's cycle, not the quorum base block. Its wire
layout is otherwise the same as version 1. The verifier uses the named current
or previous cycle and its assigned slot, including a prior commitment retained
when DKG failed. Version 1 retains its meaning before the switch.

## Light-client response

Peers advertising protocol version 90033 can request `getqrinfo`: a vector
of up to 32 known active-chain base hashes, a target block hash, and an
`extraShare` boolean. Firo's `qrinfo` response consists of:

1. A CompactSize vector of cycle records in height order. Each record has
   the cycle hash, a snapshot, and an existing `mnlistdiff` for the work block.
2. The target block's `mnlistdiff`.
3. A CompactSize vector of active indexed commitments at the target block.

A snapshot is a 32-bit mode, a dynamic bitset over the score-ordered eligible
nodes (set bits indicate previous use), and a CompactSize vector of 32-bit
positions in the partitioned list. Mode 0 takes entries sequentially, wrapping
as needed. Mode 2 explicitly lists the accepted positions in slot order. Mode
3 has no quarters. The response includes the four cycles needed to reconstruct
each active commitment, even when an index still uses an older commitment.
An extra share requests another prior cycle for the target. Each diff is
relative to a supplied base or an earlier diff in the same response; its
coinbase proof authenticates the masternode and commitment roots. The layout
uses Firo's commitment and masternode formats, not Dash network encodings.
