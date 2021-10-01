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

def find_vout(vout, amount):
    for i in range(0, len(vout)):
        if vout[i]['value'] == amount:
            return i
    raise AssertionError('Could not find unspent with amount={}'.format(amount))

def create_chained_tx(nnode, address):
    parentTxid = nnode.sendtoaddress(address, 1)
    parentTx = nnode.getrawtransaction(parentTxid, True)

    inputs = [{'txid': parentTx['txid'], 'vout': find_vout(parentTx['vout'], 1)}]
    childTxRaw = nnode.createrawtransaction(inputs, {address: 0.99})
    childTxRaw = nnode.signrawtransaction(childTxRaw)['hex']
    childTxid = nnode.sendrawtransaction(childTxRaw)
    return childTxid

class LLMQ_IS_Lelantus(EvoZnodeTestFramework):
    def __init__(self):
        super().__init__(4, 0)
        self.sporkprivkey = "cW2YM2xaeCaebfpKguBahUAgEzLXgSserWRuD29kSyKHq1TTgwRQ"

    def run_test(self):
        self.sporkAddress = self.nodes[0].getaccountaddress("")

        nnode = self.nodes[0]

        while nnode.getinfo()["blocks"] <= 800:                 # Bfiltering enabled at 800
            nnode.generate(1)

        for i in range(0, 3):
            mintTxids = nnode.mintlelantus(1)

        nnode.generate(3)

        jsplitTxid = nnode.joinsplit({self.sporkAddress: 0.1})
        nnode.generate(1)
        assert (nnode.getrawtransaction(jsplitTxid, True)['confirmations'] > 0)


if __name__ == '__main__':
    LLMQ_IS_Lelantus().main()
