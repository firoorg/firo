#!/usr/bin/env python3
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
        getcontext().prec = 16

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
            fee = Decimal(info['fee']) # fee in transaction is negative

            # mint is treated as send to yourself so the amount will be zero
            assert mint_amount == 0, \
                f'Unexpected mint amount {mint_amount}'

            start_bal += fee

        # Generate confirmation blocks for mint
        self.nodes[0].generate(6)
        self.sync_all()

        # Many spend to yourself
        spend_trans = list()

        for denom in denoms:
            val = {'value': denom, 'amount': 2}
            args = {
                 'address': '',
                 'denominations': [val]
                 }
            spend_trans.append(self.nodes[0].spendmanyzerocoin(args))

            info = self.nodes[0].gettransaction(spend_trans[-1])
            confrms = info['confirmations']
            assert confrms == 0, \
                f'Confirmations should be 0, ' \
                f'due to 0 blocks was generated after transaction was created,' \
                f'but was {confrms}.'

            tr_type = info['details'][0]['category']
            assert tr_type == 'spend', 'Unexpected transaction type'

            cur_amount = Decimal(info['amount'])
            fee = Decimal(info['fee']) # fee in transaction is negative

            # this is send to yourself so the amount will be zero
            assert cur_amount == 0, \
                f'Unexpected spend amount {cur_amount}'

            start_bal += fee

        # Verify, that balance did not change, cause we did not confirm the operation
        # Start balance increase on generated blocks to confirm
        start_bal += 40 * 6
        cur_bal = self.nodes[0].getbalance()
        assert start_bal == cur_bal, \
            f'Unexpected current balance: {cur_bal} {start_bal}'

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

if __name__ == '__main__':
    ZcoinMintSpendManyTest().main()
