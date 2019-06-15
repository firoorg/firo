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

expected_pubcoins = [
    ('0.05', 5),
    ('0.1', 3),
    ('0.5', 2),
    ('1', 1),
    ('10', 1),
    ('25', 1),
    ('100', 1)
    ]

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
        self.nodes[0].generate(400)
        self.sync_all()

        for input_data in denoms:
            case_name, denom = input_data
            assert not self.nodes[0].listsigmapubcoins(str(denom)), 'List sigma pubcoins should be empty.'

        assert_raises(JSONRPCException, self.nodes[0].listsigmapubcoins, "0.15")
        assert_raises(JSONRPCException, self.nodes[0].listsigmapubcoins, 0.1)
        assert_raises(JSONRPCException, self.nodes[0].listsigmapubcoins, ["0.1", 1])

        for input_data in denoms:
            case_name, denom = input_data
            self.nodes[0].mint(denom)
            self.nodes[0].mint(denom)
            self.nodes[0].generate(6)
            self.sync_all()

            args = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': denom}
            res = self.nodes[0].spendmany("", args)

        self.nodes[0].generate(10)
        self.sync_all()
        
        for input_data in expected_pubcoins:
            denom, count = input_data
            pubcoins = [(pubcoin['denomination'], pubcoin['IsUsed']) for pubcoin in self.nodes[0].listsigmapubcoins(denom)]
            assert len(pubcoins) == count, 'Unexpected pubcoins count.'
            for act_denom, isUsed in pubcoins:
                assert isUsed, 'PubCoin should be used.'
                assert act_denom == denom, 'Unexpected denomination returned via listpubcoins.'



if __name__ == '__main__':
    ListSigmaPubCoinsValidationWithFundsTest().main()

