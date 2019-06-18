#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from collections import Counter

class SigmaMeetSpendTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = True

    def setup_nodes(self):
        # This test requires mocktime
        enable_mocktime()
        return start_nodes(self.num_nodes, self.options.tmpdir)

    def run_test(self):
        # Decimal formating: 6 digits for balance will be enought 000.000
        getcontext().prec = 6

        self.nodes[0].generate(400)
        self.sync_all()

        start_bal = self.nodes[0].getbalance()
        assert start_bal != 0.0, 'Unexpected start balance: {}'.format(start_bal)

        # Cases:
        # Should be spended 100, 1 reminted
        # Remint is 0.95(0.1*4, 0.5, 0.05) - 0.05 to fee
        denoms1 = [(10, 9), (2, 100), (9, 1)]
        spend_size1 = 99
        spend1 = ['100']
        remint1 = ['0.1', '0.1', '0.5', '0.1', '0.05', '0.1'] 


        # Before mint new coins were: {'1': 99, '0.1': 4, '0.05': 1, '100': 1, '0.5': 1}
        # Remint, coins priority by size 100*1, 1*100
        # Should be spended 100.1, due to priority
        # Remint is 0.05 - 0.05 to fee
        denoms2 = [(100, 1)]
        spend_size2 = 100
        spend2 = ['100', '0.1']
        remint2 = ['0.05'] 


        # Before mint new coins were: {'1': 199, '0.1': 3, '0.05': 2, '0.5': 1}
        # Remint, coins priority by size, multiple denomination to spend
        # I have 11*1, 1*0.05, 2*100, I want to spend 210.5
        # Remint is 0.5 - 0.05 to fee
        denoms3 = [(1, 0.05), (2, 100), (100, 1)]
        spend_size3 = 210.5
        spend3 = ['100', '100', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '0.05']
        remint3 = ['0.5']


        # Before mint new coins were: {'1': 288, '0.1': 3, '0.05': 2, '0.5': 2}
        # No Remint, select denom by priority
        # I have 3*0.5, 1*100, 1*100, I want to spend 111
        # Should be spended 2*100 and 1*0.5, 10*1, 0.05 (for fee)
        denoms4 = [(2, 0.05), (2, 100)]
        spend_size4 = 210.5
        spend4 = ['100', '100', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '0.5', '0.05']
        remint4 = [] 

        print('Case 1, Remint is 1 of 100. Spend is 99.')
        activate_sigma_spend(denoms1, spend_size1, spend1, remint1, self)

        print('Case 2, Remint is 0.1 of 100.1. Spend is 100.')
        activate_sigma_spend(denoms2, spend_size2, spend2, remint2, self)

        print('Case 3, Remint is 0.5 of 211.5 Spend is 210.5. Select by priority')
        activate_sigma_spend(denoms3, spend_size3, spend3, remint3, self)

        print('Case 4, No Remint. Spend is 210.5.')
        activate_sigma_spend(denoms4, spend_size4, spend4, remint4, self)


def activate_sigma_spend(denoms, spendsize, exp_spends, exp_remints, zcoind):
    for denom in denoms:
        count, size = denom
        for i in range(count):
            zcoind.nodes[0].mint(size)
            zcoind.nodes[0].generate(6)

    myaddr = zcoind.nodes[0].listreceivedbyaddress(0, True)[0]['address']
    args = {myaddr: spendsize}
    txid = zcoind.nodes[0].spendmany("", args)
    zcoind.nodes[0].generate(2)

    # Should be checked spends
    spends = zcoind.nodes[0].listsigmaspends(0)
    cur_spend = [sp for sp in spends if sp['txid'] == txid]
    assert len(cur_spend) == 1, 'Txid not found in list of spends'
    cur_remints = [denom['denomination'] for denom in cur_spend[0]['remints']]
    cur_spends = [denom['denomination'] for denom in cur_spend[0]['spends']]

    assert sorted(exp_spends) == sorted(cur_spends), \
     'Unexpected spends. Expected: {}, But was: {}'.format(exp_spends, cur_spends)

    assert sorted(exp_remints) == sorted(cur_remints), \
     'Unexpected remints. Expected: {}, But was: {}'.format(exp_remints, cur_remints)


if __name__ == '__main__':
    SigmaMeetSpendTest().main()