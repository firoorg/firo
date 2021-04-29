#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

denoms = {
    '0.05': 0.05,
    '0.1': 0.1,
    '0.5': 0.5,
    '1': 1,
    '10': 10,
    '25': 25,
    '100': 100
}

# Should be unused pair of each denomination, due two mints
expected_pubcoins_before_spend = \
    [
     ('0.05', False), ('0.05', False),
     ('0.1', False), ('0.1', False),
     ('0.5', False), ('0.5', False),
     ('1', False), ('1', False),
     ('10', False), ('10', False),
     ('25', False), ('25', False),
     ('100', False), ('100', False),
     ]

expected_pubcoins_after_denom_spend = {
    '0.05': [('0.05', False), ('0.05', False), ('0.1', False), ('0.1', True),
             ('0.5', False), ('0.5', False), ('1', False), ('1', False),
             ('10', False), ('10', False), ('100', False), ('100', False), ('25', False), ('25', False)],

    '0.1': [('0.05', False), ('0.05', True), ('0.1', True), ('0.1', True),
            ('0.5', False), ('0.5', False), ('1', False), ('1', False), ('10', False),
            ('10', False), ('100', False), ('100', False), ('25', False), ('25', False)],

    '0.5': [('0.05', True), ('0.05', True), ('0.1', True), ('0.1', True), ('0.5', False),
            ('0.5', True), ('1', False), ('1', False), ('10', False), ('10', False), ('100', False),
            ('100', False), ('25', False), ('25', False)],

    '1': [('0.05', False), ('0.05', True), ('0.05', True), ('0.1', False), ('0.1', False), ('0.1', False),
          ('0.1', False), ('0.1', True), ('0.1', True), ('0.5', True), ('0.5', True), ('1', False), ('1', True),
          ('10', False), ('10', False), ('100', False), ('100', False), ('25', False), ('25', False)],

    '10': [('0.05', False), ('0.05', False), ('0.05', True), ('0.05', True), ('0.1', False), ('0.1', False),
           ('0.1', False), ('0.1', False), ('0.1', False), ('0.1', False), ('0.1', False), ('0.1', False),
           ('0.1', True), ('0.1', True), ('0.5', False), ('0.5', True), ('0.5', True), ('1', True), ('1', True),
           ('10', False), ('10', True), ('100', False), ('100', False), ('25', False), ('25', False)],

    '25': [('0.05', False), ('0.05', True), ('0.05', True), ('0.05', True), ('0.1', False), ('0.1', False),
           ('0.1', False), ('0.1', False), ('0.1', False), ('0.1', False), ('0.1', False), ('0.1', False),
           ('0.1', True), ('0.1', True), ('0.5', False), ('0.5', True), ('0.5', True), ('1', True), ('1', True),
           ('10', False), ('10', True), ('100', False), ('100', False), ('25', False), ('25', True)],

    '100':  [('0.05', True), ('0.05', True), ('0.05', True), ('0.05', True), ('0.1', False), ('0.1', False),
             ('0.1', False), ('0.1', False), ('0.1', False), ('0.1', False), ('0.1', False), ('0.1', False),
             ('0.1', True), ('0.1', True), ('0.5', False), ('0.5', True), ('0.5', True), ('1', True), ('1', True),
             ('10', False), ('10', True), ('100', False), ('100', True), ('25', False), ('25', True)]
}


class ListSigmaPubCoinsValidationWithFundsTest(BitcoinTestFramework):
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

        for denom in denoms.values():
            assert not self.nodes[0].listsigmapubcoins(str(denom)), 'List sigma pubcoins should be empty.'

        assert_raises(JSONRPCException, self.nodes[0].listsigmapubcoins, "0.15")
        assert_raises(JSONRPCException, self.nodes[0].listsigmapubcoins, 0.1)
        assert_raises(JSONRPCException, self.nodes[0].listsigmapubcoins, ["0.1", 1])

        for denom in denoms.values():
            self.nodes[0].mint(denom)
            self.nodes[0].mint(denom)
            self.nodes[0].generate(2)
        self.sync_all()

        pubcoins = [(pubcoin['denomination'], pubcoin['IsUsed'])
                    for pubcoin in self.nodes[0].listsigmapubcoins()]

        assert sorted(pubcoins) == sorted(expected_pubcoins_before_spend), \
            'Unexpected pubcoins list returned. Should be: {}, but was: {}.' \
                .format(expected_pubcoins_before_spend, pubcoins)

        for denom_value in sorted(denoms.items(),key=lambda x:x[1]):
            denom_name = denom_value[0]
            denom = denom_value[1]
            print("denom: " + denom_name)
            args = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': denom}
            self.nodes[0].spendmany("", args)
            self.nodes[0].generate(1)
            self.sync_all()

            pubcoins = [(pubcoin['denomination'], pubcoin['IsUsed'])
                        for pubcoin in self.nodes[0].listsigmapubcoins()]

            assert sorted(pubcoins) == sorted(expected_pubcoins_after_denom_spend[denom_name]), \
                'Unexpected pubcoins list returned after spend: {}. Should be: {}, but was: {}.' \
                    .format(denom, sorted(expected_pubcoins_after_denom_spend[denom_name]), sorted(pubcoins))



        unused_pubcoins_sum = sum([Decimal(pubcoin['denomination'])
                         for pubcoin in self.nodes[0].listsigmapubcoins() if pubcoin['IsUsed'] == False])
        expected_unused_pubcoins_sum = sum(denoms.values()) - len(denoms) * 0.05

        diff = int(unused_pubcoins_sum)-int(expected_unused_pubcoins_sum)
        assert diff == 0, \
            'Unexpected diff between unused coins sum expected and actual.'


if __name__ == '__main__':
    ListSigmaPubCoinsValidationWithFundsTest().main()

