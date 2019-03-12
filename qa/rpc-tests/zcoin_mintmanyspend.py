#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Exercise the listreceivedbyaddress API
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class ZcoinMintSpendManyTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False

    def setup_nodes(self):
        #This test requires mocktime
        enable_mocktime()
        return start_nodes(self.num_nodes, self.options.tmpdir)

    def run_test(self):
        # Decimal formating: 6 digits for balance will be enought 000.000 
        getcontext().prec = 6

        # old denomination
        # TODO should be changed after RPC will be updated
        denoms = [1, 10, 25, 50, 100]

        start_bal = self.nodes[0].getbalance()
        assert start_bal == 1000.000, f'Unexpected start balance: {start_bal}'

        mint_trans = list()
        for denom in denoms:
            mint_trans.append(self.nodes[0].mintmanyzerocoin(str(denom), str(2)))

            # Get last added transaction and fee for it
            info = self.nodes[0].gettransaction(mint_trans[-1])

            mint_amount = Decimal(info['amount'])
            assert Decimal(-denom*2) == mint_amount, \
                f'Unexpected mint amount {mint_amount}' \

            # fee is negative here
            fee = info['fee']

            start_bal = start_bal - Decimal(2*denom - fee)
        
        # Generate confirmation blocks for mint
        self.nodes[0].generate(6)
        self.sync_all()

        # Many spend to yourself
        spend_trans = list()
        spend_total = Decimal(0)
        for denom in denoms:
            val = {'value': denom, 'amount': 2}
            args = { 
                 'address': '',
                 'denominations': [val]
                 }
            spend_trans.append(self.nodes[0].spendmanyzerocoin(args))
            spend_total += 2*denom

            info = self.nodes[0].gettransaction(spend_trans[-1])
            confrms = info['confirmations']
            assert confrms == 0, \
                f'Confirmations should be 0, ' \
                f'due to 0 blocks was generated after transaction was created,' \
                f'but was {confrms}.'

            tr_type = info['details'][0]['category']
            assert tr_type == 'spend', 'Unexpected transaction type'

            cur_amount = Decimal(info['amount'])
            exp_spend = Decimal(denom) * 2
            assert exp_spend == cur_amount, \
                f'Unexpected spend amount {cur_amount}' \
                f' but should be: {exp_spend}.'

        # Verify, that balance did not change, cause we did not confirm the operation
        # Start balance increase on generated blocks to confirm
        start_bal += 40 * 6
        cur_bal = self.nodes[0].getbalance()
        assert start_bal == cur_bal, \
            f'Unexpected current balance: {cur_bal}, should not change after spend, ' \
            f' while we do not confirm, but start was {start_bal}'

        # Verify, that after one confirmation balance would NOT be updated on spends
        # Cause MAX_SPEND_ZC_TX_PER_BLOCK=5
        self.nodes[0].generate(1)
        self.sync_all()

        # Start balance increase on generated blocks to confirm
        start_bal += 40 * 1

        confrms_1 = 0
        for tr in spend_trans:
            info = self.nodes[0].gettransaction(tr)
            confrms_1 += info['confirmations']

        assert confrms_1 == 2, \
            f'Total confirmations should be 2 for 5 manyspend operations size of 2, ' \
            f'due to 1 blocks was generated after transaction was created ' \
            f'and MAX_SPEND_ZC_TX_PER_BLOCK=5, but was {confrms_1}.'

        # Start balance increase on generated blocks to confirm
        start_bal += 40 * 2

        self.nodes[0].generate(2)
        self.sync_all()

        confrms_2 = 0
        for tr in spend_trans:
            info = self.nodes[0].gettransaction(tr)
            confrms_2 += info['confirmations']

        assert confrms_2 == 11, \
            f'Confirmations should be 11, for 5 manyspend operations size of 2' \
            f'due to 3 blocks was generated after transaction was created ' \
            f'and MAX_SPEND_ZC_TX_PER_BLOCK=5, but was {confrms_2}.'

        cur_bal = self.nodes[0].getbalance()
        start_bal = start_bal + spend_total
        assert start_bal == cur_bal, \
            f'Unexpected current balance: {cur_bal}, should increase on {spend_total}, ' \
            f'but start was {start_bal}'


if __name__ == '__main__':
    ZcoinMintSpendManyTest().main()
