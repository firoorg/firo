#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

denoms = [
    ('denom_0.05', 0.05),
    ('denom_0.1', 0.1),
    ('denom_0.5', 0.5),
    ('denom_1', 1),
    ('denom_10', 10),
    ('denom_25', 25),
    ('denom_100', 100),
]


class ListSigmaUnspentMintsValidationWithFundsTest(BitcoinTestFramework):
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
        self.nodes[0].generate(400)
        self.sync_all()

        assert not self.nodes[0].listunspentsigmamints(), 'List sigma unspent mints should be empty.'
        assert not self.nodes[0].listunspentsigmamints(1), 'List sigma unspent mints should be empty.'
        assert not self.nodes[0].listunspentsigmamints(1, 1), 'List sigma unspent mints should be empty.'
        assert not self.nodes[0].listunspentsigmamints(1, 2), 'List sigma unspent mints should be empty.'
        assert not self.nodes[0].listunspentsigmamints(100, 0), 'List sigma unspent mints should be empty.'

        assert_raises(JSONRPCException, self.nodes[0].listunspentsigmamints, 10000000000)
        assert_raises(JSONRPCException, self.nodes[0].listunspentsigmamints, 'test')
        assert_raises(JSONRPCException, self.nodes[0].listunspentsigmamints, [1, 'test'])
        assert_raises(JSONRPCException, self.nodes[0].listunspentsigmamints, ['test', 'test'])
        assert_raises(JSONRPCException, self.nodes[0].listunspentsigmamints, [10000000000, False])

        denoms_total = 0
        for case_name, denom in denoms:
            denoms_total +=2
            mint1 = self.nodes[0].mint(denom)
            mint2 = self.nodes[0].mint(denom)
            self.nodes[0].generate(6)
            self.sync_all()

            unspent_sigma_mints = self.nodes[0].listunspentsigmamints(1)

            # check that sigma mints count with min conf count=1 was changed
            assert len(unspent_sigma_mints) == denoms_total, \
            'Unexpected amount unspent sigma mints, expected: {}, actual: {}'.format(denoms_total, unspent_sigma_mints)

            mints = [(mint['txid'], mint['amount']) for mint in unspent_sigma_mints]

            denom = Decimal(denom) + Decimal(0)
            assert (mint1, denom) in mints, \
            'This txid with denom {} should be in list of unspent mints: {}, but was not'.format((mint1, denom), mints)
            assert (mint2, denom) in mints, \
            'This txid with denom {} should be in list of unspent mints: {}, but was not'.format((mint2, denom), mints)
            
        
        self.nodes[0].generate(10)
        self.sync_all()

        # check that all sigma mints has at least 6 confirmations
        assert len(self.nodes[0].listunspentsigmamints(6)) == denoms_total

        for case_name, denom in denoms:
            args = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': denom}
            self.nodes[0].spendmany("", args)

        unspent_mints = len(self.nodes[0].listunspentsigmamints(6))
        print(self.nodes[0].listunspentsigmamints(6))
        # check that unspent mint count total decreased after spend 
        assert unspent_mints == denoms_total // 2, \
            'Amount of unspent mints was not decreased as expected: {}.'.format(unspent_mints)
        

if __name__ == '__main__':
    ListSigmaUnspentMintsValidationWithFundsTest().main()

