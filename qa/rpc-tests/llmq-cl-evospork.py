#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.mininode import *
from test_framework.test_framework import EvoZnodeTestFramework
from test_framework.util import *
from time import *

'''
llmq-chainlocks.py

Checks LLMQs based ChainLocks

00 Mine quorum and produce chainlocks
01 Make sure the chainlocked tip does not change after invalidateblock
02 Make sure a rogue miner cannot inject a longer chain
10 Disable chainlocks
11 Make sure 01-09 work as usual
- 
'''

class LLMQChainLocksTest(EvoZnodeTestFramework):
    def __init__(self):
        super().__init__(6, 5, extra_args=[['-debug=chainlocks']] * 6)
        self.sporkprivkey = "cW2YM2xaeCaebfpKguBahUAgEzLXgSserWRuD29kSyKHq1TTgwRQ"

    def run_test(self):

        for i in range(4):
            self.mine_quorum()

        # mine single block, wait for chainlock
        self.nodes[0].generate(1)

        self.wait_for_chainlock_tip_all_nodes()
        self.payment_address = self.nodes[0].getaccountaddress("")
        self.nodes[0].sendtoaddress(self.payment_address, 1)

        # mine many blocks, wait for chainlock
        while self.nodes[0].getblockcount() < 1000:
            self.nodes[0].generate(20)
        self.wait_for_chainlock_tip_all_nodes()

        # assert that all blocks up until the tip are chainlocked
        for h in range(1, self.nodes[0].getblockcount()):
            block = self.nodes[0].getblock(self.nodes[0].getblockhash(h))
            assert(block['chainlock'])

        # cannot invalidate tip
        current_tip = self.nodes[0].getbestblockhash()
        self.nodes[0].invalidateblock(current_tip)
        assert(current_tip == self.nodes[0].getbestblockhash())

        ##### Disable chainlocks for 10 blocks

        self.nodes[0].importprivkey(self.sporkprivkey)
        self.disable_chainlocks(self.nodes[0].getblockcount() + 10)
        self.nodes[0].generate(1)
        assert(False == self.nodes[0].getblock(self.nodes[0].getbestblockhash())["chainlock"])

        # can invalidate block now
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())
        assert(current_tip == self.nodes[0].getbestblockhash())

        isolate_node(self.nodes[5])

        ##### Enable chainlocks

        self.nodes[0].generate(10)
        self.nodes[0].spork('list')
        self.wait_for_chainlock_tip_all_nodes()
        sporks = self.nodes[0].spork("list")
        assert(not sporks["blockchain"])
        assert(not sporks["mempool"])
        assert(True == self.nodes[0].getblock(self.nodes[0].getbestblockhash())["chainlock"])

        # generate a longer chain on the isolated node then reconnect it back and make sure it picks the chainlocked chain
        self.nodes[5].generate(20)
        reconnect_isolated_node(self.nodes[5], 1)
        self.nodes[0].generate(1)
        current_tip = self.nodes[0].getbestblockhash()
        timeout = 10
        while current_tip != self.nodes[5].getbestblockhash():
            assert timeout > 0, "Timed out when waiting for a chainlocked chain"
            sleep(1)
            timeout = timeout - 1


    def wait_for_chainlock_tip_all_nodes(self):
        for node in self.nodes:
            tip = node.getbestblockhash()
            self.wait_for_chainlock(node, tip)

    def wait_for_chainlock_tip(self, node):
        tip = node.getbestblockhash()
        self.wait_for_chainlock(node, tip)

    def wait_for_chainlock(self, node, block_hash):
        t = time()
        while time() - t < 30:
            try:
                block = node.getblock(block_hash)
                if block["confirmations"] > 0 and block["chainlock"]:
                    return
            except:
                # block might not be on the node yet
                pass
            sleep(0.1)
        raise AssertionError("wait_for_chainlock timed out")

    def disable_chainlocks(self, till_height):
        self.nodes[0].spork(self.sporkprivkey, self.payment_address, {"disable":{"chainlocks": till_height}})


if __name__ == '__main__':
    LLMQChainLocksTest().main()
