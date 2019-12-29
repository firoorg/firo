#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


#Check remint 
class RemintSigmaValidationTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False

    def setup_nodes(self):
        # This test requires mocktime
        enable_mocktime()
        return start_nodes(self.num_nodes, self.options.tmpdir)


    # 1. All denoms except zcoint not acceptable
    # 2. All other inputs except valid ints not acceptable
    def run_test(self):
        getcontext().prec = 6
        self.nodes[0].generate(101)
        self.sync_all()

        zcoin_denoms = [1, 10, 25, 50, 100]
        for denom in zcoin_denoms:
            self.nodes[0].mintzerocoin(denom)
            self.nodes[0].mintzerocoin(denom)

        self.nodes[0].generate(300)

        # 1. All denoms except zcoint not acceptable
        assert_raises(JSONRPCException, self.nodes[0].remintzerocointosigma, 5)
        assert_raises(JSONRPCException, self.nodes[0].remintzerocointosigma, 0.1)
        assert_raises(JSONRPCException, self.nodes[0].remintzerocointosigma, -1)
        assert_raises(JSONRPCException, self.nodes[0].remintzerocointosigma, 101)

        # text arg is invalid
        assert_raises(JSONRPCException, self.nodes[0].remintzerocointosigma, "1")
        assert_raises(JSONRPCException, self.nodes[0].remintzerocointosigma, "test")
        assert_raises(JSONRPCException, self.nodes[0].remintzerocointosigma, [1, "1"])

        for denom in zcoin_denoms:
            try:
                self.nodes[0].remintzerocointosigma(denom)
                self.nodes[0].remintzerocointosigma(denom)
            except JSONRPCException as e:
                assert False, "Could not remint denomination {} with next exception {}." \
                    .format(denom, e.error['message'])

        #should fail cause no zcoin mints
        assert_raises(JSONRPCException, self.nodes[0].remintzerocointosigma, 1)
        


if __name__ == '__main__':
    RemintSigmaValidationTest().main()

