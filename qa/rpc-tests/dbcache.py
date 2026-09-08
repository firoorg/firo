#!/usr/bin/env python3
# Copyright (c) 2026 The Firo developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Check that the remaining -dbcache budget is assigned to the UTXO cache."""

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
        # The block-index and coin database caches are deducted first.
        for node, expected_mib in enumerate(['440.0', '2038.0', '1.8', '385.8']):
            log_path = os.path.join(self.options.tmpdir, 'node' + str(node),
                                    'regtest', 'debug.log')
            with open(log_path, encoding='utf-8') as log_file:
                log = log_file.read()
            expected = '* Using {}MiB for in-memory UTXO set'.format(expected_mib)
            assert expected in log, 'node {}: missing cache allocation: {}'.format(node, expected)


if __name__ == '__main__':
    DbCacheTest().main()
