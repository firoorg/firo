#!/usr/bin/env python3
# Copyright (c) 2026 The Firo developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""-newwallet and -rescan only apply to the startup wallet scan.

Node 0 runs with both, like a session after "Create new wallet" in the GUI.
A later importmulti must still rescan, from its own start block: -newwallet
used to skip the scan (and crash importmulti), -rescan to restart it at block 0.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, connect_nodes_bi, log_filename, start_nodes


class WalletStartupScanArgsTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [["-newwallet=1", "-rescan"], []])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        # A payment node 0's wallet has never seen.
        address = self.nodes[1].getnewaddress()
        txid = self.nodes[1].sendtoaddress(address, 1)
        self.nodes[1].generate(1)
        self.sync_all()

        result = self.nodes[0].importmulti([{"scriptPubKey": {"address": address}, "timestamp": "now", "watchonly": True}])
        assert_equal(result, [{"success": True}])
        assert_equal(self.nodes[0].gettransaction(txid, True)["txid"], txid)

        with open(log_filename(self.options.tmpdir, 0, "debug.log"), encoding="utf8", errors="replace") as log:
            scans = [line for line in log if "Rescanning last" in line]
        assert "(from block 0)" not in scans[-1], scans[-1]


if __name__ == '__main__':
    WalletStartupScanArgsTest().main()
