#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


class SetSigmaMintSatusValidationWithFundsTest(BitcoinTestFramework):
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

        print('Set mint status from False to True.')

        self.nodes[0].setsigmamintstatus(mint_info['serialNumber'], True)

        sigma_mint = self.nodes[0].listsigmamints()

        assert len(sigma_mint) == 1, 'Should be only one mint.'

        mint_info = sigma_mint[0]

        assert mint_info['IsUsed'], \
            'This mint with txid: {} should be Used.'.format(txid)

        print('Set mint status from True to False back.')

        self.nodes[0].setsigmamintstatus(mint_info['serialNumber'], False)

        sigma_mint = self.nodes[0].listsigmamints()

        assert len(sigma_mint) == 1, 'Should be only one mint.'

        mint_info = sigma_mint[0]

        assert not mint_info['IsUsed'], \
            'This mint with txid: {} should not be Used.'.format(txid)

        
        assert_raises(JSONRPCException, self.nodes[0].setsigmamintstatus, [(mint_info['serialNumber'], "sometext")])
        assert_raises(JSONRPCException, self.nodes[0].setsigmamintstatus, [mint_info['serialNumber']])
        assert_raises(JSONRPCException, self.nodes[0].setsigmamintstatus, [])
        assert_raises(JSONRPCException, self.nodes[0].setsigmamintstatus, ["sometext"])
        assert_raises(JSONRPCException, self.nodes[0].setsigmamintstatus, [123])


if __name__ == '__main__':
    SetSigmaMintSatusValidationWithFundsTest().main()

