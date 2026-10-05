#!/usr/bin/env python3
# Copyright (c) 2026 The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that solo-mining jobs survive template rebuilds while their parent is the tip.

When the mempool changes, getblocktemplate rebuilds its template and hands out a new
pprpcsb job. Miners keep hashing the previous job until they next ask for work, and a
solution to it is still a valid block, so pprpcsb must accept it until the tip changes.
"""

from decimal import Decimal
import os
import subprocess
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_jsonrpc, connect_nodes_bi, start_nodes, sync_blocks

RPC_INVALID_PARAMS = -32602


class GetBlockTemplateRetainedJobsTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = False

    def setup_network(self):
        # ProgPoW has to be active on regtest for getblocktemplate to hand out pprpcsb jobs
        args = ['-ppswitchtime=%d' % (int(time.time()) - 10)]
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [args] * self.num_nodes, timewait=120)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def set_time(self, t):
        for peer in self.nodes:
            peer.setmocktime(t)

    def spend(self, node, fee):
        utxo = next(u for u in node.listunspent() if u['txid'] not in self.spent)
        self.spent.add(utxo['txid'])
        raw = node.createrawtransaction([{'txid': utxo['txid'], 'vout': utxo['vout']}],
                                        {node.getnewaddress(): utxo['amount'] - fee})
        return node.signrawtransaction(raw)['hex']

    def run_test(self):
        node = self.nodes[0]
        now = int(time.time())
        self.set_time(now)
        node.generate(1)  # getblocktemplate refuses to work on a stale tip
        sync_blocks(self.nodes)
        address = node.getnewaddress()
        self.spent = set()

        miner = os.path.join(os.path.dirname(os.getenv('FIROD', 'firod')),
                             'progpow_test_miner' + ('.exe' if os.name == 'nt' else ''))

        def solve(job):
            nonce, mix = subprocess.check_output(
                [miner, str(job['height']), job['pprpcheader'], job['target']],
                universal_newlines=True, timeout=60).split()
            return job['pprpcheader'], mix, hex(int(nonce))

        def txids(job):
            return [tx['txid'] for tx in job['transactions']]

        # A new transaction produces a new job once the template is rebuilt, at least 5 s after the last
        old = node.getblocktemplate({}, address)
        assert_equal(txids(old), [])
        paid = node.sendrawtransaction(self.spend(node, Decimal('0.001')))
        self.set_time(now + 6)
        new = node.getblocktemplate({}, address)
        assert_equal(txids(new), [paid])
        assert_equal(new['height'], old['height'])
        assert new['pprpcheader'] != old['pprpcheader']

        # A miner still working on the previous job finds a valid block, and the node accepts it
        assert_equal(node.pprpcsb(*solve(old)), None)
        assert_equal(node.getblockcount(), old['height'])
        assert_equal(len(node.getblock(node.getbestblockhash())['tx']), 1)
        assert paid in node.getrawmempool()
        sync_blocks(self.nodes)

        # Jobs on the replaced tip are dropped when the template is rebuilt on the new tip
        current = node.getblocktemplate({}, address)
        assert_equal(txids(current), [paid])
        assert_raises_jsonrpc(RPC_INVALID_PARAMS, 'Job not found', node.pprpcsb, new['pprpcheader'], '00' * 32, '0x1')

        # A transaction paying no fee leaves the coinbase unchanged. The cached job with the same
        # coinbase but different transactions must not be handed out again, but stays solvable.
        free = self.spend(node, Decimal('0'))
        free_txid = node.decoderawtransaction(free)['txid']
        node.prioritisetransaction(free_txid, 0, 100000)  # relay and mine it although it pays no fee
        node.sendrawtransaction(free)
        self.set_time(now + 12)
        both = node.getblocktemplate({}, address)
        assert_equal(both['coinbasevalue'], current['coinbasevalue'])
        assert_equal(sorted(txids(both)), sorted([paid, free_txid]))
        assert both['pprpcheader'] != current['pprpcheader']
        assert_raises_jsonrpc(RPC_INVALID_PARAMS, 'Bad solution', node.pprpcsb, current['pprpcheader'], '00' * 32, '0x1')

        # While fresh, a job is reused for the same transactions
        assert_equal(node.getblocktemplate({}, address)['pprpcheader'], both['pprpcheader'])

        assert_equal(node.pprpcsb(*solve(both)), None)
        assert_equal(node.getblockcount(), both['height'])
        assert_equal(sorted(node.getblock(node.getbestblockhash())['tx'][1:]), sorted([paid, free_txid]))
        sync_blocks(self.nodes)


if __name__ == '__main__':
    GetBlockTemplateRetainedJobsTest().main()
