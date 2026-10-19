#!/usr/bin/env python3
# Copyright (c) 2026 The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.mininode import *
from test_framework.test_framework import EvoZnodeTestFramework
from test_framework.util import *

'''
llmq-is-dandelion.py

A masternode must not vote on the InstantSend input locks of a Dandelion
stem-phase tx: its sig shares would tell the other quorum members that it holds
the tx before the tx is public. It votes once the tx is fluffed.

"quorum sign" is the probe: it returns false if the masternode has already
voted on the input.
'''

class LLMQ_IS_Dandelion(EvoZnodeTestFramework):
    def __init__(self):
        super().__init__(6, 5)

    def run_test(self):
        self.mine_quorum()

        self.mn = self.mninfo[0].node
        self.test_node = SingleNodeConnCB()
        self.test_node.add_connection(NodeConn('127.0.0.1', p2p_port(self.mninfo[0].nodeIdx), self.mn, self.test_node))
        NetworkThread().start()
        self.test_node.wait_for_verack()

        self.log.info("no vote while the tx is in the stem phase")
        for _ in range(10):
            tx = self.send_stem_tx()
            voted = not self.mn.quorum("sign", 100, inlock_id(tx), tx.hash)
            # A fluff (10% at once, else when the embargo ends) makes the vote legitimate: retry
            if tx.hash not in self.mn.getrawmempool():
                break
        else:
            raise AssertionError("every tx was fluffed before the check")
        assert(not voted)

        self.log.info("vote and lock once the tx is fluffed")
        tx = self.send_stem_tx()
        def fluffed():
            # Embargoes are only checked when the node processes a message
            self.test_node.send_message(msg_ping())
            return tx.hash in self.mn.getrawmempool()
        assert(wait_until(fluffed, timeout=30))
        self.wait_for_instantlock(tx.hash, self.mn, do_assert=True)
        assert(not self.mn.quorum("sign", 100, inlock_id(tx), tx.hash))

    def send_stem_tx(self):
        raw = self.create_raw_tx(self.nodes[0], self.nodes[0], 1, 1, 1)
        # node0 sees the tx only once it is fluffed, don't let it spend the input again
        self.nodes[0].lockunspent(False, [{"txid": raw["vin"][0]["txid"], "vout": raw["vin"][0]["vout"]}])
        tx = FromHex(CTransaction(), raw["hex"])
        tx.rehash()
        self.test_node.send_and_ping(msg_dandeliontx(tx))
        return tx

def inlock_id(tx):
    # SerializeHash(std::make_pair("inlock", outpoint)) of the first input
    return encode(hash256(ser_string(b"inlock") + tx.vin[0].prevout.serialize())[::-1], 'hex_codec').decode('ascii')

if __name__ == '__main__':
    LLMQ_IS_Dandelion().main()
