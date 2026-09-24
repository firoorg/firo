#!/usr/bin/env python3
# Copyright (c) 2026 The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test coinbase messages for solo mining through getblocktemplate and pprpcsb.

getblocktemplate({"coinbase_message": text}, reward_address) puts text into the
coinbase of the block the node builds for pprpcsb and echoes it in the result.
"""

from io import BytesIO
import os
import subprocess
import time

from test_framework.mininode import CTransaction
from test_framework.script import CScript, OP_0, OP_RETURN
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
        now = int(time.time())
        for peer in self.nodes:
            peer.setmocktime(now)
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

        other = node.getblocktemplate({'coinbase_message': 'hello'}, node.getnewaddress())
        assert other['pprpcheader'] != hello['pprpcheader']
        assert_equal(node.getblocktemplate({'coinbase_message': 'hello'}, address)['pprpcheader'], hello['pprpcheader'])

        # An empty message gives back the job built from the original coinbase
        assert_equal(node.getblocktemplate({'coinbase_message': ''}, address)['pprpcheader'], plain['pprpcheader'])

        # A message without a reward address is echoed, but its job is not saved
        unsaved = node.getblocktemplate({'coinbase_message': 'hello'})
        assert_equal(unsaved['coinbase_message'], 'hello')
        assert_raises_jsonrpc(RPC_INVALID_PARAMS, 'Job not found', node.pprpcsb, unsaved['pprpcheader'], '00' * 32, '0x1')

        # 80 UTF-8 bytes fit, more do not, and the value must be a string
        longest = 'a' * 80
        ascii_limit = node.getblocktemplate({'coinbase_message': longest}, address)
        assert_equal(ascii_limit['coinbase_message'], longest)
        utf8_limit = node.getblocktemplate({'coinbase_message': 'é' * 40}, address)
        assert_equal(utf8_limit['coinbase_message'], 'é' * 40)
        assert_raises_jsonrpc(RPC_INVALID_PARAMETER, 'too long', node.getblocktemplate, {'coinbase_message': longest + 'a'}, address)
        assert_raises_jsonrpc(RPC_INVALID_PARAMETER, 'too long', node.getblocktemplate, {'coinbase_message': 'é' * 41}, address)
        assert_raises_jsonrpc(RPC_TYPE_ERROR, 'must be a string', node.getblocktemplate, {'coinbase_message': 1}, address)

        # Saved jobs reach solution checking, including both 80-byte message encodings
        for job in (plain, hello, world, other, ascii_limit, utf8_limit):
            assert_raises_jsonrpc(RPC_INVALID_PARAMS, 'Bad solution', node.pprpcsb, job['pprpcheader'], '00' * 32, '0x1')

        # Start with an empty cache and give each of its 64 jobs a distinct timestamp
        node.setmocktime(now + 1)
        node.generate(1)
        sync_blocks(self.nodes)
        headers = []
        for i in range(64):
            node.setmocktime(now + 2 + i)
            headers.append(node.getblocktemplate({'coinbase_message': str(i)}, address)['pprpcheader'])

        # Reusing a job or requesting an unsaved job must not evict anything at capacity
        node.setmocktime(now + 66)
        assert_equal(node.getblocktemplate({'coinbase_message': '63'}, address)['pprpcheader'], headers[-1])
        node.getblocktemplate({'coinbase_message': 'unsaved'})
        assert_raises_jsonrpc(RPC_INVALID_PARAMS, 'Bad solution', node.pprpcsb, headers[0], '00' * 32, '0x1')

        # Saving one more job evicts only the oldest timestamp
        newest = node.getblocktemplate({'coinbase_message': 'overflow'}, address)['pprpcheader']
        assert_raises_jsonrpc(RPC_INVALID_PARAMS, 'Job not found', node.pprpcsb, headers[0], '00' * 32, '0x1')
        for header in (headers[1], headers[-1], newest):
            assert_raises_jsonrpc(RPC_INVALID_PARAMS, 'Bad solution', node.pprpcsb, header, '00' * 32, '0x1')

        miner = os.path.join(os.path.dirname(os.getenv('FIROD', 'firod')),
                             'progpow_test_miner' + ('.exe' if os.name == 'nt' else ''))

        def solve(job):
            nonce, mix = subprocess.check_output(
                [miner, str(job['height']), job['pprpcheader'], job['target']],
                universal_newlines=True, timeout=60).split()
            return job['pprpcheader'], mix, hex(int(nonce))

        # Submit real proofs across DIP3 activation, including an 80-byte UTF-8 message.
        node.generate(498 - node.getblockcount())
        sync_blocks(self.nodes)
        for message in ('a' * 80, 'é' * 40, ''):
            job = node.getblocktemplate({'coinbase_message': message}, address)
            solution = solve(job)
            assert_equal(node.pprpcsb(*solution), None)
            assert_equal(node.getblockcount(), job['height'])
            block = node.getblock(node.getbestblockhash())
            coinbase = node.getrawtransaction(block['tx'][0], True)
            prefix = CScript([OP_RETURN]) if job['height'] >= 500 else CScript([job['height'], OP_0])
            expected = prefix + message.encode('utf-8') if message else prefix
            assert_equal(coinbase['vin'][0]['coinbase'], expected.hex())
            assert_equal(coinbase['vout'][0]['scriptPubKey']['addresses'], [address])
            assert_equal(coinbase['vout'][0]['value'] * 100000000, job['coinbasevalue'])
            if job['height'] >= 500:
                tx = CTransaction()
                tx.deserialize(BytesIO(bytes.fromhex(coinbase['hex'])))
                assert_equal(tx.nType, 5)
                assert_equal(tx.vExtraPayload.hex(), job['coinbase_payload'])
            assert_equal(node.pprpcsb(*solution), 'duplicate')
            sync_blocks(self.nodes)

        # A real proof can still fail block validation after a clock correction.
        # It must not be reported as an accepted duplicate.
        node.setmocktime(now + 3 * 3600)
        job = node.getblocktemplate({'coinbase_message': 'future'}, address)
        solution = solve(job)
        node.setmocktime(now + 66)
        tip = node.getbestblockhash()
        assert_equal(node.pprpcsb(*solution), 'time-too-new')
        assert_equal(node.getbestblockhash(), tip)


if __name__ == '__main__':
    GetBlockTemplateCoinbaseMessageTest().main()
