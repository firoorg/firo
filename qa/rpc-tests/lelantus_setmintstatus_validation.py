#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class SetLelantusMintSatusValidationWithFundsTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False

    def setup_nodes(self):
        # This test requires mocktime
        enable_mocktime()
        return start_nodes(self.num_nodes, self.options.tmpdir)

    def run_test(self):
        self.nodes[0].generate(1000)
        self.sync_all()

        txid = self.nodes[0].mintlelantus(10)

        lelantus_mint = self.nodes[0].listlelantusmints()

        assert len(lelantus_mint) == len(txid), 'Should be same number.'

        mint_info = lelantus_mint[0]

        assert not mint_info['IsUsed'], \
            'This mint with txid: {} should not be Used.'.format(txid)

        print('Set mint status from False to True.')

        self.nodes[0].setlelantusmintstatus(mint_info['serialNumber'], True)

        lelantus_mint = self.nodes[0].listlelantusmints()

        assert len(lelantus_mint) == len(txid), 'Should be same number.'

        mint_info = lelantus_mint[0]

        assert mint_info['IsUsed'], \
            'This mint with txid: {} should be Used.'.format(txid)

        print('Set mint status from True to False back.')

        self.nodes[0].setlelantusmintstatus(mint_info['serialNumber'], False)

        lelantus_mint = self.nodes[0].listlelantusmints()

        assert len(lelantus_mint) == len(txid), 'Should be same number.'

        mint_info = lelantus_mint[0]

        assert not mint_info['IsUsed'], \
            'This mint with txid: {} should not be Used.'.format(txid)


        assert_raises(JSONRPCException, self.nodes[0].setlelantusmintstatus, [(mint_info['serialNumber'], "sometext")])
        assert_raises(JSONRPCException, self.nodes[0].setlelantusmintstatus, [mint_info['serialNumber']])
        assert_raises(JSONRPCException, self.nodes[0].setlelantusmintstatus, [])
        assert_raises(JSONRPCException, self.nodes[0].setlelantusmintstatus, ["sometext"])
        assert_raises(JSONRPCException, self.nodes[0].setlelantusmintstatus, [123])


if __name__ == '__main__':
    SetLelantusMintSatusValidationWithFundsTest().main()