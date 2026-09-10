#!/usr/bin/env python3
# Copyright (c) 2026 The Firo developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from copy import deepcopy

from test_framework.blocktools import create_block, create_coinbase, create_transaction
from test_framework.mininode import (
    CTxInWitness,
    HeaderAndShortIDs,
    NetworkThread,
    NodeConn,
    SingleNodeConnCB,
    mininode_lock,
    msg_block,
    msg_blocktxn,
    msg_cmpctblock,
    msg_ping,
    msg_witness_block,
    wait_until,
)
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port


class BlockSourcePeer(SingleNodeConnCB):
    def __init__(self):
        super().__init__()
        self.last_getblocktxn = None
        self.peer_disconnected = False

    def on_getblocktxn(self, conn, message):
        self.last_getblocktxn = message

    def on_inv(self, conn, message):
        pass

    def on_close(self, conn):
        self.peer_disconnected = True

    def wait_for_getblocktxn(self):
        return wait_until(lambda: self.last_getblocktxn is not None, timeout=10)

    def send_and_sync_or_disconnect(self, message):
        nonce = self.ping_counter
        self.send_message(message)
        self.send_message(msg_ping(nonce=nonce))
        processed = wait_until(
            lambda: self.peer_disconnected or self.last_pong.nonce == nonce,
            timeout=10,
        )
        self.ping_counter += 1
        return processed


class BlockSourceTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    @staticmethod
    def build_block(node, transactions=None):
        transactions = transactions or []
        height = node.getblockcount() + 1
        tip = node.getbestblockhash()
        block_time = node.getblockheader(tip)["mediantime"] + 1
        block = create_block(int(tip, 16), create_coinbase(height), block_time)
        block.nVersion = 4
        block.vtx.extend(transactions)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()
        block.solve()
        return block

    def run_test(self):
        node = self.nodes[0]
        honest_peer = BlockSourcePeer()
        attacker_peer = BlockSourcePeer()
        delivery_peer = BlockSourcePeer()

        honest_connection = NodeConn(
            "127.0.0.1", p2p_port(0), node, honest_peer
        )
        attacker_connection = NodeConn(
            "127.0.0.1", p2p_port(0), node, attacker_peer
        )
        delivery_connection = NodeConn(
            "127.0.0.1", p2p_port(0), node, delivery_peer
        )
        honest_peer.add_connection(honest_connection)
        attacker_peer.add_connection(attacker_connection)
        delivery_peer.add_connection(delivery_connection)

        NetworkThread().start()
        honest_peer.wait_for_verack()
        attacker_peer.wait_for_verack()
        delivery_peer.wait_for_verack()

        mature_block = self.build_block(node)
        honest_peer.send_and_ping(msg_block(mature_block))
        assert_equal(int(node.getbestblockhash(), 16), mature_block.sha256)
        node.generate(100)

        spend_value = mature_block.vtx[0].vout[0].nValue
        first_spend = create_transaction(
            mature_block.vtx[0],
            0,
            b"",
            spend_value - 1000,
            CScript([OP_TRUE]),
        )
        second_spend = create_transaction(
            first_spend,
            0,
            b"",
            first_spend.vout[0].nValue - 1000,
            CScript([OP_TRUE]),
        )
        valid_block = self.build_block(node, [first_spend, second_spend])
        previous_tip = int(node.getbestblockhash(), 16)

        # Leave a compact reconstruction owned by the honest peer.
        compact_block = HeaderAndShortIDs()
        compact_block.initialize_from_block(valid_block)
        honest_peer.send_and_ping(msg_cmpctblock(compact_block.to_p2p()))
        assert honest_peer.wait_for_getblocktxn()

        with mininode_lock:
            request = honest_peer.last_getblocktxn.block_txn_request
            assert_equal(request.blockhash, valid_block.sha256)
            requested_indexes = request.to_absolute()
        assert_equal(requested_indexes, [1, 2])

        # Adding non-committed witness data preserves the header.
        mutated_block = deepcopy(valid_block)
        mutated_tx = mutated_block.vtx[-1]
        original_txid = mutated_tx.sha256
        original_wtxid = mutated_tx.calc_sha256(with_witness=True)
        mutated_tx.wit.vtxinwit = [CTxInWitness() for _ in mutated_tx.vin]
        mutated_tx.wit.vtxinwit[0].scriptWitness.stack = [b"\x01"]
        mutated_tx.rehash()
        assert_equal(mutated_tx.sha256, original_txid)
        assert mutated_tx.calc_sha256(with_witness=True) != original_wtxid
        assert_equal(mutated_block.calc_merkle_root(), valid_block.hashMerkleRoot)
        mutated_block.rehash()
        assert_equal(mutated_block.sha256, valid_block.sha256)

        assert attacker_peer.send_and_sync_or_disconnect(
            msg_witness_block(mutated_block)
        )
        assert_equal(int(node.getbestblockhash(), 16), previous_tip)
        assert honest_peer.sync_with_ping(timeout=10)

        response = msg_blocktxn()
        response.block_transactions.blockhash = valid_block.sha256
        response.block_transactions.transactions = [
            valid_block.vtx[index] for index in requested_indexes
        ]
        honest_peer.send_and_ping(response)
        assert_equal(int(node.getbestblockhash(), 16), valid_block.sha256)

        # A valid full block from another peer must clear the residual owner.
        final_spend = create_transaction(
            second_spend,
            0,
            b"",
            second_spend.vout[0].nValue - 1000,
            CScript([OP_TRUE]),
        )
        delivered_block = self.build_block(node, [final_spend])
        with mininode_lock:
            honest_peer.last_getblocktxn = None

        compact_block = HeaderAndShortIDs()
        compact_block.initialize_from_block(delivered_block)
        honest_peer.send_and_ping(msg_cmpctblock(compact_block.to_p2p()))
        assert honest_peer.wait_for_getblocktxn()
        with mininode_lock:
            request = honest_peer.last_getblocktxn.block_txn_request
            assert_equal(request.blockhash, delivered_block.sha256)
            assert_equal(request.to_absolute(), [1])

        delivery_peer.send_and_ping(msg_block(delivered_block))
        assert_equal(int(node.getbestblockhash(), 16), delivered_block.sha256)

        late_response = msg_blocktxn()
        late_response.block_transactions.blockhash = delivered_block.sha256
        honest_peer.send_and_ping(late_response)
        assert not honest_peer.peer_disconnected


if __name__ == "__main__":
    BlockSourceTest().main()
