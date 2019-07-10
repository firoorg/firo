#!/usr/bin/env python3
# Copyright (c) 2019 The Zcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import (
    start_nodes,
    assert_raises_message,
)

class EnableHDSigmaTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [["-usehd=1"]])

    def assert_enable_hd(self, fn, args = []):
        try:
            fn(args)
        except JSONRPCException as e:
            msg = e.error["message"]
            assert msg != "sigma mint/spend is not allowed for legacy wallet"

    def run_test(self):
        self.nodes[0].generate(500)
        node = self.nodes[0]

        fn_to_tests = [
            node.listsigmamints,
            node.listsigmapubcoins,
            node.listsigmaspends,
            node.mint,
            node.remintzerocointosigma,
            node.setsigmamintstatus,
            node.spendmany,
        ]

        for fn in fn_to_tests:
            self.assert_enable_hd(fn)

if __name__ == '__main__':
    EnableHDSigmaTest().main()
