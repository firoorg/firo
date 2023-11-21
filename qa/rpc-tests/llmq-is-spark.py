#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.mininode import *
from test_framework.test_framework import EvoZnodeTestFramework
from test_framework.util import sync_blocks, set_node_times, \
    isolate_node, reconnect_isolated_node, set_mocktime, get_mocktime
from test_framework.util import assert_equal, assert_raises_jsonrpc, \
    bitcoind_processes, start_nodes, start_node, connect_nodes_bi

from decimal import Decimal

'''
llmq-is-spark.py

Testing Instantsend for Spark transactions
'''

class LLMQ_IS_Lelantus(EvoZnodeTestFramework):
    def __init__(self):
        super().__init__(6, 5, extra_args=[['-debug=instantsend']] * 6 )
        self.sporkprivkey = "cW2YM2xaeCaebfpKguBahUAgEzLXgSserWRuD29kSyKHq1TTgwRQ"

    def run_test(self):
        self.sporkAddress = self.nodes[0].getaccountaddress("")
        self.mine_quorum()
        self.wait_for_chainlocked_block_all_nodes(self.nodes[0].getbestblockhash())

        self.nodes[0].generate(1001 - self.nodes[0].getblockcount())

        sparkaddress = self.nodes[0].getnewsparkaddress()[0]
        for i in range(0, 3):
            mintTxids = self.nodes[0].mintspark({sparkaddress: {"amount": 1, "memo":"Test memo"}})

        for mintTxid in mintTxids:
            mintTx = self.nodes[0].getrawtransaction(mintTxid, 1)
            val = 0
            for vi in mintTx['vin']:
                val += vi['valueSat']
            if val > 10000:
                break;
        val = Decimal((val - 10000) / 1e+8).quantize(Decimal('1e-7'))

        assert(self.wait_for_instantlock(mintTxid, self.nodes[0]))

        mintDspend = self.nodes[0].createrawtransaction(mintTx['vin'], {self.nodes[0].getnewaddress(): str(val)})
        assert_raises_jsonrpc(-26, 'tx-txlock-conflict', self.nodes[0].sendrawtransaction, mintDspend)

        self.nodes[0].generate(3)
        assert (self.nodes[0].getrawtransaction(mintTxid, True)['confirmations'] > 0)

        spendTxid = self.nodes[0].spendspark({self.sporkAddress: {"amount": 0.1, "subtractFee": False}})
        assert(self.wait_for_instantlock(spendTxid, self.nodes[0]))

if __name__ == '__main__':
    LLMQ_IS_Lelantus().main()
