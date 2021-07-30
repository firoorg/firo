#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.mininode import *
from test_framework.test_framework import EvoZnodeTestFramework
from test_framework.util import sync_blocks, set_node_times, \
    isolate_node, reconnect_isolated_node, set_mocktime, get_mocktime
from test_framework.util import assert_equal, assert_raises_jsonrpc, \
    bitcoind_processes, start_nodes

'''
llmq-is-retroactive.py

Tests retroactive signing

We have 6 nodes where node 0 is the control node, nodes 1-5 are masternodes.
Mempool inconsistencies are simulated via disconnecting/reconnecting node 3
and by having a higher relay fee on nodes 4 and 5.
'''

class LLMQ_IS_Lelantus(EvoZnodeTestFramework):
    def __init__(self):
        super().__init__(6, 5)
        self.sporkprivkey = "cW2YM2xaeCaebfpKguBahUAgEzLXgSserWRuD29kSyKHq1TTgwRQ"

    def run_test(self):
        self.sporkAddress = self.nodes[0].getaccountaddress("")
        print(self.nodes[0].sendtoaddress(self.sporkAddress, 1))
        self.mine_quorum()
        self.wait_for_chainlocked_block_all_nodes(self.nodes[0].getbestblockhash())

        self.nodes[0].generate(1000 - self.nodes[0].getblockcount())
        mintTxid = self.nodes[0].mintlelantus(1)
        self.wait_for_instantlock(mintTxid, self.nodes[0])
        mintTx = self.nodes[0].getrawtransaction(mintTxid[0], 1)

        rawTxDspend = self.nodes[0].createrawtransaction(mintTx['vin'], {self.nodes[0].getnewaddress(): 0.999})
        assert_raises_jsonrpc(-26, 'tx-txlock-conflict', self.nodes[1].sendrawtransaction, rawTxDspend)

        self.nodes[0].importprivkey(self.sporkprivkey)
        self.nodes[0].spork(self.sporkprivkey, self.sporkAddress, {"disable": {"instantsend": self.nodes[0].getblockcount() + 3}})
        self.nodes[0].generate(3)
        sync_blocks(self.nodes)

        mintTxid = self.nodes[0].mintlelantus(1)
        self.wait_for_instantlock(mintTxid, self.nodes[0],  False, 15, do_assert=True) #There should be no islock

        rawTxDspend = self.nodes[0].createrawtransaction(mintTx['vin'], {self.nodes[0].getnewaddress(): 0.999})
        assert_raises_jsonrpc(-25, 'Missing inputs', self.nodes[0].sendrawtransaction, rawTxDspend)

if __name__ == '__main__':
    LLMQ_IS_Lelantus().main()
