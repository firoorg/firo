#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


class ResetSigmaValidationTest(BitcoinTestFramework):
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
        self.sync_all()

        txid = self.nodes[0].mint(10)

        sigma_mint = self.nodes[0].listsigmamints()

        assert len(sigma_mint) == 1, 'Should be only one mint.'

        mint_info = sigma_mint[0]

        assert not mint_info['IsUsed'], \
            'This mint with txid: {} should not be Used.'.format(txid)

        # Set mint status from False to True.
        self.nodes[0].setsigmamintstatus(mint_info['serialNumber'], True)

        # Call reset mint status. IsUsed should become False.
        self.nodes[0].resetsigmamint()

        sigma_mint = self.nodes[0].listsigmamints()

        assert len(sigma_mint) == 1, 'Should be only one mint.'

        mint_info = sigma_mint[0]

        assert not mint_info['IsUsed'], \
            'This mint with txid: {} should not be Used.'.format(txid)

        assert_raises(JSONRPCException, self.nodes[0].resetsigmamint, [(1, "sometext")])
        assert_raises(JSONRPCException, self.nodes[0].resetsigmamint, 1)
        assert_raises(JSONRPCException, self.nodes[0].resetsigmamint, [])
        assert_raises(JSONRPCException, self.nodes[0].resetsigmamint, ["sometext"])
        assert_raises(JSONRPCException, self.nodes[0].resetsigmamint, [123])


if __name__ == '__main__':
    ResetSigmaValidationTest().main()

