#!/usr/bin/env python3
# Copyright (c) 2026 The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from test_framework.mininode import *
from test_framework.test_framework import (EvoZnodeTestFramework, REGTEST_INSTANTSEND_EXPIRY_START_BLOCK,
                                           REGTEST_INSTANTSEND_LOCK_LIFETIME, REGTEST_LLMQ_INSTANTSEND_DKG_INTERVAL)
from test_framework.util import *
from decimal import Decimal
from time import *

'''
llmq-is-expiry.py

Checks that past the activation height InstantSend locks are isdlocks, which carry a quorum-signed cycle block, and
that a lock stops protecting its inputs a lifetime after that block.
'''

class TestNode(SingleNodeConnCB):
    def __init__(self):
        SingleNodeConnCB.__init__(self)
        self.islocks = {}

    def send_islock(self, islock):
        hash = uint256_from_str(hash256(islock.serialize()))
        self.islocks[hash] = islock

        inv = msg_inv([CInv(31 if isinstance(islock, msg_isdlock) else 30, hash)])
        self.send_message(inv)

    def on_getdata(self, conn, message):
        for inv in message.inv:
            if inv.hash in self.islocks:
                self.send_message(self.islocks[inv.hash])


class LLMQ_IS_Expiry(EvoZnodeTestFramework):
    def __init__(self):
        super().__init__(6, 5)

    def run_test(self):
        self.test_node = TestNode()
        self.test_node.add_connection(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node))
        NetworkThread().start()  # Start up network handling in another thread
        self.test_node.wait_for_verack()

        self.mine_quorum()
        self.nodes[0].generate(800 - self.nodes[0].getblockcount())
        self.sync_all()
        assert(self.nodes[0].getblockcount() > REGTEST_INSTANTSEND_EXPIRY_START_BLOCK)

        self.test_masternodes_create_isdlocks()
        self.test_lock_expires()

    def test_masternodes_create_isdlocks(self):
        # The nodes only accept the lock if the quorum signed the txid together with the cycle block
        txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 1)
        for node in self.nodes:
            self.wait_for_instantlock(txid, node, do_assert=True)

    def test_lock_expires(self):
        # Two pairs of TXs conflicting with each other. Only tx2 and tx4 get locked, tx2 and tx4 are never relayed.
        rawtx1 = self.create_raw_tx(self.nodes[0], self.nodes[0], 1, 1, 100)['hex']
        rawtx2 = self.create_raw_tx(self.nodes[0], self.nodes[0], 1, 1, 100)['hex']
        rawtx1_txid = encode(hash256(hex_str_to_bytes(rawtx1))[::-1], 'hex_codec').decode('ascii')
        tx1_inputs = set(("%064x" % txin.prevout.hash, txin.prevout.n) for txin in FromHex(CTransaction(), rawtx1).vin)
        tx2_inputs = set(("%064x" % txin.prevout.hash, txin.prevout.n) for txin in FromHex(CTransaction(), rawtx2).vin)
        assert(tx1_inputs & tx2_inputs)

        tip = self.nodes[0].getblockcount()
        cycle_height = tip - tip % REGTEST_LLMQ_INSTANTSEND_DKG_INTERVAL

        # tx4's lock is signed over a cycle block that is too old: it's expired on arrival and must be ignored
        expired_cycle_height = cycle_height
        while tip + 1 - expired_cycle_height < REGTEST_INSTANTSEND_LOCK_LIFETIME:
            expired_cycle_height -= REGTEST_LLMQ_INSTANTSEND_DKG_INTERVAL
        utxos = [u for u in self.nodes[0].listunspent()
                 if u['amount'] > 2 and (u['txid'], u['vout']) not in tx1_inputs | tx2_inputs]
        rawtx3, rawtx4 = self.create_conflicting_pair(utxos[-1])
        locks_before = self.nodes[0].getmempoolinfo()['instantsendlocks']
        expired_islock = self.create_islock(rawtx4, expired_cycle_height)
        assert(isinstance(expired_islock, msg_isdlock))
        self.test_node.send_islock(expired_islock)

        islock = self.create_islock(rawtx2)
        assert(isinstance(islock, msg_isdlock))
        assert_equal(islock.cycleHash, int(self.nodes[0].getblockhash(cycle_height), 16))
        self.test_node.send_islock(islock)

        assert(wait_until(lambda: self.nodes[0].getmempoolinfo()['instantsendlocks'] > locks_before, timeout=15))
        # The expired lock arrived first and was dropped: it neither got stored nor locks tx4's inputs
        assert_equal(self.nodes[0].getmempoolinfo()['instantsendlocks'], locks_before + 1)
        assert_raises_jsonrpc(-26, "tx-txlock-conflict", self.nodes[0].sendrawtransaction, rawtx1)
        self.nodes[0].sendrawtransaction(rawtx3)

        # The lock still applies to the block a lifetime after the cycle block minus one...
        self.nodes[0].generate(cycle_height + REGTEST_INSTANTSEND_LOCK_LIFETIME - 2 - self.nodes[0].getblockcount())
        self.sync_all()
        assert_raises_jsonrpc(-26, "tx-txlock-conflict", self.nodes[0].sendrawtransaction, rawtx1)

        # ...but not to the next one
        self.nodes[0].generate(1)
        self.sync_all()
        self.nodes[0].sendrawtransaction(rawtx1)

        # Not locked TXs are only mined once they are old enough
        set_mocktime(get_mocktime() + int(60 * 11))
        set_node_times(self.nodes, get_mocktime())
        self.nodes[0].generate(1)
        self.sync_all()
        for node in self.nodes:
            assert(node.getrawtransaction(rawtx1_txid, True)['confirmations'] > 0)

    def create_conflicting_pair(self, utxo):
        txs = []
        for i in range(2):
            raw = self.nodes[0].createrawtransaction([{"txid": utxo['txid'], "vout": utxo['vout']}],
                                                     {self.nodes[0].getnewaddress(): satoshi_round(utxo['amount'] - Decimal('0.01') * (i + 1))})
            txs.append(self.nodes[0].signrawtransaction(raw)['hex'])
        return txs


if __name__ == '__main__':
    LLMQ_IS_Expiry().main()
