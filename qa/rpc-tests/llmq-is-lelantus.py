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
llmq-is-lelantus.py

Testing Instantsend for Lelantus transactions
'''

class LLMQ_IS_Lelantus(EvoZnodeTestFramework):
    def __init__(self):
        super().__init__(6, 5, extra_args=[['-debug=instantsend']] * 6 )
        self.sporkprivkey = "cW2YM2xaeCaebfpKguBahUAgEzLXgSserWRuD29kSyKHq1TTgwRQ"

    def run_test(self):
        self.sporkAddress = self.nodes[0].getaccountaddress("")
        self.mine_quorum()
        self.wait_for_chainlocked_block_all_nodes(self.nodes[0].getbestblockhash())

        self.nodes[0].generate(120 - self.nodes[0].getblockcount())
        for i in range(0, 3):
            mintTxids = self.nodes[0].mintlelantus(1)

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

        jsplitTxid = self.nodes[0].joinsplit({self.sporkAddress: 0.1})
        assert(self.wait_for_instantlock(jsplitTxid, self.nodes[0]))

        self.nodes[0].stop()
        bitcoind_processes[0].wait()
        self.nodes[0] = start_node(0, self.options.tmpdir, ["-zapwallettxes=1"])
        for i in range(1, self.num_nodes):
            if i < len(self.nodes) and self.nodes[i] is not None:
                connect_nodes_bi(self.nodes, 0, i)

        jsplitTx1id = self.nodes[0].joinsplit({self.sporkAddress: 0.11}) # This uses the already islocked coin serial. No islock expected.
        self.wait_for_instantlock(jsplitTx1id, self.nodes[1], False, 5, True)
        jsplitTx2id = self.nodes[0].joinsplit({self.sporkAddress: 0.11}) # This uses a new coin serial. An islock is expected.
        self.wait_for_instantlock(jsplitTx2id, self.nodes[1], True, 5, True)

        # Disabling IS
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
