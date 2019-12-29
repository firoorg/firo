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


class ListSigmaMintValidationWithFundsTest(BitcoinTestFramework):
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

        assert not self.nodes[0].listsigmamints(False), 'List sigma own mints should be empty.'
        assert not self.nodes[0].listsigmamints(True), 'List sigma all mints should be empty.'
        
        assert_raises(JSONRPCException, self.nodes[0].listsigmamints, 'Some data')
        assert_raises(JSONRPCException, self.nodes[0].listsigmamints, 1)

        for input_data in denoms:
            case_name, denom = input_data
            self.nodes[0].mint(denom)

        self.nodes[0].generate(10)
        self.sync_all()

        listsigmamints = self.nodes[0].listsigmamints(False)
        
        # check that for 0 node all mints shown correct
        assert len(listsigmamints) == len(denoms), \
         'Amount of mints should be equal to expected for this node.' \
          'Expected: {}, Actual: {}.'.format(len(denoms), len(listsigmamints))

        sigmamints = [str(Decimal(mint['denomination'])/100000000) for mint in listsigmamints]
        exp_sigmamints = [str(denom[1]) for denom in denoms]
       
        assert sorted(exp_sigmamints) == sorted(sigmamints), \
         'Unexpected sigmamints shown in listsigmamints.'


if __name__ == '__main__':
    ListSigmaMintValidationWithFundsTest().main()

