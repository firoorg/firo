#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


#Check remint 
class RemintSigmaTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False

    def setup_nodes(self):
        # This test requires mocktime
        enable_mocktime()
        return start_nodes(self.num_nodes, self.options.tmpdir)


    # 1. Zerocoin mint for all denoms
    # 2. Generate blocks to activate sigma
    # 3. Remint all denoms
    # 4. Check reminted coins are spendable in sigma
    # 5. Check that we are able to generate blocks after sigma spend 
    def run_test(self):
        getcontext().prec = 6
        self.nodes[0].generate(101)
        self.sync_all()

        firo_denoms = [1, 10, 25, 50, 100]
        for denom in firo_denoms:
            self.nodes[0].mintzerocoin(denom)
            self.nodes[0].mintzerocoin(denom)

        self.nodes[0].generate(300)

        firo_mint = self.nodes[0].listunspentmintzerocoins()

        assert len(firo_mint) == 10, 'Should be 10 firo mints after firo mint, but was: {}' \
                .format(len(firo_mint))
        
        for denom in firo_denoms:
            try:
                self.nodes[0].remintzerocointosigma(denom)
                self.nodes[0].remintzerocointosigma(denom)
            except JSONRPCException as e:
                assert False, "Could not remint denomination {} with next exception {}." \
                    .format(denom, e.error['message'])

        self.nodes[0].generate(50)

        sigma_mint = self.nodes[0].listunspentsigmamints()

        # In sigma there is no denom - 50, so should be 2 of 25.
        assert len(sigma_mint) == 12, 'Should be 12 sigma mints after remint, but was: {}' \
                .format(len(sigma_mint))

        sigma_mints = set([mint['amount'] for mint in sigma_mint])
        expected_mints = set([Decimal('25.00000000'), Decimal('10.00000000'), Decimal('100.00000000'), Decimal('1.00000000')])

        assert sigma_mints == expected_mints, 'Unexpected sigma mints after remint.' \
                            '\n Actual: {}, \n expected {}'.format(sigma_mint, expected_mints)

        # fee size to extract when spend all coins
        total_amount_to_spend = -1* len(firo_denoms)*0.05*2
        
        for denom in firo_denoms:
            total_amount_to_spend +=denom*2

        val = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': total_amount_to_spend}
        
        self.nodes[0].spendmany('', val)

        sigma_mint = self.nodes[0].listunspentsigmamints()

        assert len(sigma_mint) == 0, 'Looks like sigma mints unspendable after remint.'

        #Check that we can generate blocks after
        self.nodes[0].generate(1)

        


if __name__ == '__main__':
    RemintSigmaTest().main()

