#!/usr/bin/env python3
# Copyright (c) 2019 The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import (
    start_nodes,
    assert_raises_message,
)

class SigmaNonHDWalletTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [["-usehd=0"]])

    def assert_disable_nonhd(self, fn, *args):
        assert_raises_message(JSONRPCException, "sigma mint/spend is not allowed for legacy wallet", \
            fn, *args)

    def run_test(self):
        node = self.nodes[0]
        node.generate(300)

        self.assert_disable_nonhd(node.listunspentsigmamints)
        self.assert_disable_nonhd(node.mint, 1)
        self.assert_disable_nonhd(node.spendmany, "", {"THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU": 1})
        self.assert_disable_nonhd(node.resetsigmamint)
        self.assert_disable_nonhd(node.listsigmamints)
        self.assert_disable_nonhd(node.listsigmapubcoins)
        self.assert_disable_nonhd(node.setsigmamintstatus, "abc", True)
        self.assert_disable_nonhd(node.listsigmaspends, 0)

if __name__ == '__main__':
    SigmaNonHDWalletTest().main()
