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


class ListSigmaSpendValidationWithFundsTest(BitcoinTestFramework):
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

        assert not self.nodes[0].listsigmaspends(1), 'List sigma spends should be empty.'
        assert not self.nodes[0].listsigmaspends(1, True), 'List sigma spends should be empty.'
        assert not self.nodes[0].listsigmaspends(1, False), 'List sigma spends should be empty.'

        assert not self.nodes[0].listsigmaspends(100), 'List sigma spends should be empty.'
        assert not self.nodes[0].listsigmaspends(100, True), 'List sigma spends should be empty.'
        assert not self.nodes[0].listsigmaspends(100, False), 'List sigma spends should be empty.'

        assert_raises(JSONRPCException, self.nodes[0].listsigmaspends, 10000000000)
        assert_raises(JSONRPCException, self.nodes[0].listsigmaspends, 'test')
        assert_raises(JSONRPCException, self.nodes[0].listsigmaspends, [1, 'test'])
        assert_raises(JSONRPCException, self.nodes[0].listsigmaspends, ['test', 'test'])
        assert_raises(JSONRPCException, self.nodes[0].listsigmaspends, [10000000000, False])

        for case_name, denom in denoms:
            self.nodes[0].mint(denom)
            self.nodes[0].mint(denom)
            self.nodes[0].generate(10)
            self.sync_all()
            args = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': denom}
            self.nodes[0].spendmany("", args)

        self.nodes[0].generate(1)
        self.sync_all()
        
        assert len(self.nodes[0].listsigmaspends(5)) == 5, 'Should be 5 spends.'

        conf_spends = all(sp for sp in self.nodes[0].listsigmaspends(5, False) \
                          if sp['confirmations'] >= 1)
        assert conf_spends, 'In list should be only confirmed spends, but was: {}'.format(conf_spends)

        len_confirmed_no_more_than_10 = len(self.nodes[0].listsigmaspends(10, False))

        assert len_confirmed_no_more_than_10 == 7, \
            'Should be 7 spends, but was: {}.'.format(len_confirmed_no_more_than_10)

        args = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1}
        self.nodes[0].spendmany("", args)

        unconf_spends_amount = len([sp for sp in self.nodes[0].listsigmaspends(5, True) \
                                    if sp['confirmations'] <= 0])

        assert unconf_spends_amount == 1, \
            'Should be 1 uncofirmed spend, but was: {}.'.format(unconf_spends_amount)


if __name__ == '__main__':
    ListSigmaSpendValidationWithFundsTest().main()

