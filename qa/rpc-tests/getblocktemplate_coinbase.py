#!/usr/bin/env python3
# Copyright (c) 2026 The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test coinbase messages for solo mining through getblocktemplate and pprpcsb.

getblocktemplate({"coinbase_message": text}, reward_address) puts text into the
coinbase of the block the node builds for pprpcsb and echoes it in the result.
"""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_jsonrpc, connect_nodes_bi, start_nodes, sync_blocks

RPC_TYPE_ERROR = -3
RPC_INVALID_PARAMETER = -8
RPC_INVALID_PARAMS = -32602


class GetBlockTemplateCoinbaseMessageTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = False

    def setup_network(self):
        # ProgPoW has to be active on regtest for getblocktemplate to hand out pprpcsb jobs
        args = ['-ppswitchtime=%d' % (int(time.time()) - 10)]
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [args] * self.num_nodes)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        node = self.nodes[0]
        node.generate(1)  # getblocktemplate refuses to work on a stale tip
        sync_blocks(self.nodes)
        address = node.getnewaddress()

        plain = node.getblocktemplate({}, address)
        assert 'coinbase_message' not in plain

        # The message is acknowledged and, being part of the coinbase, changes the job
        hello = node.getblocktemplate({'coinbase_message': 'hello'}, address)
        assert_equal(hello['coinbase_message'], 'hello')
        assert hello['pprpcheader'] != plain['pprpcheader']

        # The same request keeps its job while it is fresh; a different message gets a job of its own
        assert_equal(node.getblocktemplate({'coinbase_message': 'hello'}, address)['pprpcheader'], hello['pprpcheader'])
        world = node.getblocktemplate({'coinbase_message': 'world'}, address)
        assert world['pprpcheader'] not in (plain['pprpcheader'], hello['pprpcheader'])

        # An empty message gives back the job built from the original coinbase
        assert_equal(node.getblocktemplate({'coinbase_message': ''}, address)['pprpcheader'], plain['pprpcheader'])

        # Every job handed out can still be submitted: a wrong solution is a bad solution, not an unknown job
        for header in (plain['pprpcheader'], hello['pprpcheader'], world['pprpcheader']):
            assert_raises_jsonrpc(RPC_INVALID_PARAMS, 'Bad solution', node.pprpcsb, header, '00' * 32, '0x1')

        # 80 UTF-8 bytes fit, more do not, and the value must be a string
        longest = 'a' * 80
        assert_equal(node.getblocktemplate({'coinbase_message': longest}, address)['coinbase_message'], longest)
        assert_raises_jsonrpc(RPC_INVALID_PARAMETER, 'too long', node.getblocktemplate, {'coinbase_message': longest + 'a'}, address)
        assert_raises_jsonrpc(RPC_INVALID_PARAMETER, 'too long', node.getblocktemplate, {'coinbase_message': 'é' * 41}, address)
        assert_raises_jsonrpc(RPC_TYPE_ERROR, 'must be a string', node.getblocktemplate, {'coinbase_message': 1}, address)


if __name__ == '__main__':
    GetBlockTemplateCoinbaseMessageTest().main()
