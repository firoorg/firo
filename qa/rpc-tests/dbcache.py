#!/usr/bin/env python3
# Copyright (c) 2026 The Firo developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Check that all database caches and the UTXO cache share the -dbcache budget."""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import start_nodes


class DbCacheTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4

    def setup_network(self):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [
            ['-disablewallet', '-txindex=0'],
            ['-disablewallet', '-txindex=0', '-dbcache=2048'],
            ['-disablewallet', '-txindex=0', '-dbcache=4'],
            ['-disablewallet', '-txindex=1'],
        ])

    def run_test(self):
        # Reserve EvoDB inside the budget, including at the 4 MiB minimum.
        cache_names = ['in-memory UTXO set', 'block index database',
                       'EvoDB database', 'chain state database']
        for node, allocations in enumerate([
            ['424.0', '2.0', '16.0', '8.0'],
            ['2022.0', '2.0', '16.0', '8.0'],
            ['1.5', '0.5', '0.4', '1.5'],
            ['369.8', '56.2', '16.0', '8.0'],
        ]):
            log_path = os.path.join(self.options.tmpdir, 'node' + str(node),
                                    'regtest', 'debug.log')
            with open(log_path, encoding='utf-8') as log_file:
                log = log_file.read()
            for expected_mib, cache_name in zip(allocations, cache_names):
                expected = '* Using {}MiB for {}'.format(expected_mib, cache_name)
                assert expected in log, 'node {}: missing cache allocation: {}'.format(node, expected)


if __name__ == '__main__':
    DbCacheTest().main()
