#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class SetSparkMintSatusValidation(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False

    def setup_nodes(self):
        # This test requires mocktime
        enable_mocktime()
        return start_nodes(self.num_nodes, self.options.tmpdir)

    def run_test(self):
        self.nodes[0].generate(801)
        self.sync_all()

        sparkAddress = self.nodes[0].getnewsparkaddress()[0]
        txid = list()
        txid.append(self.nodes[0].mintspark({sparkAddress: {"amount": 1, "memo":"Test memo"}}))

        spark_mint = self.nodes[0].listsparkmints()

        assert len(spark_mint) == len(txid), 'Should be same number.'

        mint_info = spark_mint[0]

        assert not mint_info['isUsed'], \
            'This mint with txid: {} should not be Used.'.format(txid)

        print('Set mint status from False to True.')

        self.nodes[0].setsparkmintstatus(mint_info['lTagHash'], True)

        spark_mint = self.nodes[0].listsparkmints()
 
        assert len(spark_mint) == len(txid), 'Should be same number.'

        mint_info = spark_mint[0]

        assert mint_info['isUsed'], \
            'This mint with txid: {} should be Used.'.format(txid)

        print('Set mint status from True to False back.')

        self.nodes[0].setsparkmintstatus(mint_info['lTagHash'], False)

        spark_mint = self.nodes[0].listsparkmints()

        assert len(spark_mint) == len(txid[0]), 'Should be same number.'

        mint_info = spark_mint[0]

        assert not mint_info['isUsed'], \
            'This mint with txid: {} should not be Used.'.format(txid)


        assert_raises(JSONRPCException, self.nodes[0].setsparkmintstatus, [(mint_info['lTagHash'], "sometext")])
        assert_raises(JSONRPCException, self.nodes[0].setsparkmintstatus, [mint_info['lTagHash']])
        assert_raises(JSONRPCException, self.nodes[0].setsparkmintstatus, [])
        assert_raises(JSONRPCException, self.nodes[0].setsparkmintstatus, ["sometext"])
        assert_raises(JSONRPCException, self.nodes[0].setsparkmintstatus, [123])


if __name__ == '__main__':
    SetSparkMintSatusValidation().main()