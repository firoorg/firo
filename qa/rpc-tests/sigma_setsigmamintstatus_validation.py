#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

denoms = [
    ('denom_1', 1),
    ('denom_0.05', 0.05),
    ('denom_0.1', 0.1),
    ('denom_0.5', 0.5),
    ('denom_5', 5),
    ('denom_10', 10),
    ('denom_25', 25),
    ('denom_100', 100),
]


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
        self.nodes[0].generate(400)
        self.sync_all()

        denoms_total = 0
        args = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': denoms_total}
        for input_data in denoms:
            case_name, denom = input_data
            denoms_total +=2*denom
            res = self.nodes[0].mint(2*denom)

            #set sigmamint to true - should work
            self.nodes[0].setsigmamintstatus(res['txid'], True)
            self.nodes[0].generate(10)
            self.sync_all()
            assert_raises(JSONRPCException, self.nodes[0].spendmany, ["", args])

            self.nodes[0].setsigmamintstatus(res['txid'], False)
            res = self.nodes[0].spendmany("", args)
        
        assert_raises(JSONRPCException, self.nodes[0].setsigmamintstatus, [(res['txid'], "sometext")])
        assert_raises(JSONRPCException, self.nodes[0].setsigmamintstatus, [res['txid']])
        assert_raises(JSONRPCException, self.nodes[0].setsigmamintstatus, [])
        assert_raises(JSONRPCException, self.nodes[0].setsigmamintstatus, ["sometext"])
        assert_raises(JSONRPCException, self.nodes[0].setsigmamintstatus, [123])


if __name__ == '__main__':
    SetSigmaMintSatusValidationWithFundsTest().main()

