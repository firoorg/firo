#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


class SigmaBlockLimitTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False

    def setup_nodes(self):
        # This test requires mocktime
        enable_mocktime()
        return start_nodes(self.num_nodes, self.options.tmpdir)

    def run_test(self):
        getcontext().prec = 6
        self.nodes[0].generate(100)
        self.sync_all()

        self.nodes[0].mint(1000)
        self.nodes[0].generate(10)
        self.sync_all()
        args = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 501}

        assert_raises_message(JSONRPCException, 'Required amount exceed value spend limit',
                              self.nodes[0].spendmany, "", args)

if __name__ == '__main__':
    SigmaBlockLimitTest().main()

