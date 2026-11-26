#!/usr/bin/env python3
# Distributed under the MIT software license, see the accompanying file COPYING.

import hashlib
import struct
from io import BytesIO
from time import sleep

from test_framework import mininode
from test_framework.mininode import (
    CBlock, CBlockHeader, CCbTx, CFinalCommitment, CMerkleBlock, FromHex, NetworkThread,
    NodeConn, SingleNodeConnCB, deser_compact_size, deser_dyn_bitset, deser_uint256,
    deser_vector, hash256, msg_mnlistdiff, ser_string, ser_uint256, ser_vector, wait_until,
)
from test_framework.test_framework import EvoZnodeTestFramework
from test_framework.util import assert_equal, p2p_port, sync_blocks

ACTIVATION = 600
INTERVAL = 24
FIRST = ACTIVATION + 3 * INTERVAL
WINDOW_END = 20
SIGN_OFFSET = 8
TYPE = 103
NAME = "llmq_test_dip24"


class GetRotationInfo:
    command = b"getqrinfo"

    def __init__(self, block_hash):
        self.block_hash = block_hash

    def serialize(self):
        # No known bases; request one additional historical quarter.
        return b"\x00" + ser_uint256(self.block_hash) + b"\x01"


class RotationInfo:
    command = b"qrinfo"

    def deserialize(self, f):
        self.cycles = []
        for _ in range(deser_compact_size(f)):
            cycle_hash = deser_uint256(f)
            mode = struct.unpack("<i", f.read(4))[0]
            active = deser_dyn_bitset(f, False)
            kept = [struct.unpack("<I", f.read(4))[0] for _ in range(deser_compact_size(f))]
            diff = msg_mnlistdiff()
            diff.deserialize(f)
            self.cycles.append((cycle_hash, mode, active, kept, diff))
        self.diff = msg_mnlistdiff()
        self.diff.deserialize(f)
        self.commitments = deser_vector(f, CFinalCommitment)
        assert_equal(f.read(), b"")


class Observer(SingleNodeConnCB):
    def __init__(self):
        super().__init__()
        self.info = None
        self.locks = {}

    def on_qrinfo(self, conn, message):
        self.info = message

    def on_isdlock(self, conn, message):
        self.locks[message.txid] = message


class RotationTest(EvoZnodeTestFramework):
    def __init__(self):
        super().__init__(6, 5, [["-dip24height=%d" % ACTIVATION, "-debug=llmq-dkg"]] * 6)

    def advance(self, height, nodes=None):
        self.nodes[0].generate(height - self.nodes[0].getblockcount())
        sync_blocks(self.nodes if nodes is None else nodes)

    def mine_cycle(self, height, on_signing_switch=None):
        for offset in range(12):
            self.advance(height + offset)

            def ready():
                statuses = [mn.node.quorum("dkgstatus")["session"] for mn in self.mninfo]
                for index in range(min(2, offset + 1)):
                    phase = (offset - index) // 2 + 1
                    members = [s.get(NAME + "_%d" % index, {}) for s in statuses]
                    members = [s for s in members if s.get("quorumHeight") == height + index and s["phase"] == phase]
                    if len(members) != 4:
                        return False
                    counter = {2: "receivedContributions", 5: "receivedPrematureCommitments"}.get(phase)
                    if counter and any(s[counter] != 4 for s in members):
                        return False
                return True

            assert wait_until(ready, timeout=25), "DKG phase at height %d" % (height + offset)
            if offset in (0, 1):
                sleep(2)  # Allow the masternode authentication handshake.
            if offset == WINDOW_END + SIGN_OFFSET - INTERVAL and on_signing_switch:
                on_signing_switch()

        def commitments_ready():
            commitments = self.nodes[0].quorum("dkgstatus")["minableCommitments"]
            return all(commitments.get(NAME + "_%d" % index, {}).get("signersCount") == 4 for index in range(2))

        assert wait_until(commitments_ready, timeout=20)
        self.advance(height + 12)
        hashes = self.nodes[0].quorum("list")[NAME]
        assert_equal(hashes, [self.nodes[0].getblockhash(height + index) for index in range(2)])
        return [self.nodes[0].quorum("info", TYPE, h) for h in hashes]

    def verify_lock(self, peer, cycle):
        node = self.nodes[0]
        txid = node.sendtoaddress(node.getnewaddress(), 1)
        assert self.wait_for_instantlock(txid, node, do_assert=True)
        assert wait_until(lambda: int(txid, 16) in peer.locks, timeout=15)
        lock = peer.locks[int(txid, 16)]
        assert_equal(lock.version, 2)
        assert_equal(lock.cycleHash, int(node.getblockhash(cycle), 16))
        request_id = hash256(ser_string(b"islock") + ser_vector(lock.inputs))
        index = request_id[0] & 1
        sig = node.quorum("getrecsig", TYPE, request_id[::-1].hex(), txid)
        assert_equal(sig["quorumHash"], node.getblockhash(cycle + index))

    def verify_rotation_info(self, peer, block_hash, quorums):
        node = self.nodes[0]
        peer.send_message(GetRotationInfo(int(block_hash, 16)))
        assert wait_until(lambda: peer.info is not None, timeout=10)
        mn_lists, quorum_lists, quarters = {0: {}}, {0: {}}, {}

        def apply_diff(diff):
            header = FromHex(CBlockHeader(), node.getblockheader("%064x" % diff.blockHash, False))
            assert_equal(node.verifytxoutproof(CMerkleBlock(header, diff.merkleProof).serialize().hex()), [diff.cbTx.hash])
            cbtx = CCbTx()
            cbtx.deserialize(BytesIO(diff.cbTx.vExtraPayload))

            mns = mn_lists[diff.baseBlockHash].copy()
            for key in diff.deletedMNs:
                del mns[key]
            mns.update((mn.proRegTxHash, mn) for mn in diff.mnList)
            leaves = [hash256(mns[key].serialize()) for key in sorted(mns, key=ser_uint256)]
            assert_equal(CBlock.get_merkle_root(leaves), cbtx.merkleRootMNList)
            mn_lists[diff.blockHash] = mns

            active = quorum_lists[diff.baseBlockHash].copy()
            for key in diff.deletedQuorums:
                del active[key]
            active.update(((qc.llmqType, qc.quorumHash), qc) for qc in diff.newQuorums)
            leaves = sorted(hash256(qc.serialize()) for qc in active.values())
            assert_equal(CBlock.get_merkle_root(leaves) if leaves else 0, cbtx.merkleRootQuorums)
            quorum_lists[diff.blockHash] = active
            return mns

        for cycle_hash, mode, active, kept, diff in peer.info.cycles:
            height = node.getblockheader("%064x" % cycle_hash)["height"]
            assert_equal(diff.blockHash, int(node.getblockhash(height - 8), 16))
            mns = apply_diff(diff)
            modifier = hash256(bytes([TYPE]) + ser_uint256(diff.blockHash))

            def ranking(mn):
                seed = hashlib.sha256(ser_uint256(mn.proRegTxHash) + ser_uint256(mn.confirmedHash)).digest()
                return (-int.from_bytes(hashlib.sha256(seed + modifier).digest(), "little"), ser_uint256(mn.proRegTxHash))

            ranked = sorted((mn for mn in mns.values() if mn.isValid and mn.confirmedHash), key=ranking)
            assert_equal(len(active), len(ranked))
            candidates = [mn for flag in (False, True) for mn, used in zip(ranked, active) if used == flag]
            assert mode in (0, 2)
            if mode == 0:
                kept = [0, 1]
            assert_equal(len(kept), 2)
            quarters[height] = [candidates[pos].proRegTxHash for pos in kept]

        assert_equal(peer.info.diff.blockHash, int(block_hash, 16))
        apply_diff(peer.info.diff)
        committed = quorum_lists[peer.info.diff.blockHash]
        expected_commitments = [committed[(TYPE, int(q["quorumHash"], 16))].serialize() for q in quorums]
        assert_equal([qc.serialize() for qc in peer.info.commitments], expected_commitments)
        for q in quorums:
            h, index = q["height"], q["quorumIndex"]
            expected = [quarters[h - index - INTERVAL * depth][index] for depth in (3, 2, 1, 0)]
            assert_equal([int(m["proTxHash"], 16) for m in q["members"]], expected)

    def run_test(self):
        node = self.nodes[0]
        mininode.MY_VERSION = 90033
        NodeConn.messagemap[b"qrinfo"] = RotationInfo
        peer = Observer()
        peer.add_connection(NodeConn("127.0.0.1", p2p_port(0), node, peer))
        NetworkThread().start()
        peer.wait_for_verack()

        self.advance(FIRST - 1)
        assert_equal(node.quorum("list")[NAME], [])
        first = self.mine_cycle(FIRST)
        second = self.mine_cycle(FIRST + INTERVAL, lambda: self.verify_lock(peer, FIRST))
        for old, new in zip(first, second):
            assert_equal([m["proTxHash"] for m in old["members"][1:]],
                         [m["proTxHash"] for m in new["members"][:3]])

        # With no online masternodes, the third cycle mines only null commitments.
        for mn in self.mninfo:
            mn.node.setnetworkactive(False)
        third = FIRST + 2 * INTERVAL
        self.advance(third + WINDOW_END + SIGN_OFFSET, [node])
        expected = [q["quorumHash"] for q in second]
        assert_equal(node.quorum("list")[NAME], expected)
        tip = node.getbestblockhash()
        changed = node.getblockhash(third)
        node.invalidateblock(changed)
        node.reconsiderblock(changed)
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(node.quorum("list")[NAME], expected)
        assert_equal(node.quorum("list", 10)[NAME], expected + [q["quorumHash"] for q in first])
        assert node.verifychain(4, 2 * INTERVAL)
        self.verify_rotation_info(peer, tip, second)


if __name__ == "__main__":
    RotationTest().main()
