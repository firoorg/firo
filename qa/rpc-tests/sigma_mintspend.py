#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


class SigmaMintSpendTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False

    def setup_nodes(self):
        # This test requires mocktime
        enable_mocktime()
        return start_nodes(self.num_nodes, self.options.tmpdir)

    def run_test(self):
        # Decimal formating: 6 digits for balance will be enought 000.000
        getcontext().prec = 6
        self.nodes[0].generate(400)

        # old denomination
        # TODO should be changed after RPC will be updated
        denoms = [0.1, 0.5, 1, 10, 100]

        start_bal = self.nodes[0].getbalance()
        assert start_bal == 14918.000, 'Unexpected start balance: {}'.format(start_bal)

        mint_trans = list()
        for denom in denoms:
            mint_trans.append(self.nodes[0].mint(2 * denom))

            # Get last added transaction and fee for it
            info = self.nodes[0].gettransaction(mint_trans[-1])

            # fee in transaction is negative
            fee = -info['fee']
            cur_bal = self.nodes[0].getbalance()
            start_bal = float(start_bal) - float(fee) - denom * 2
            start_bal = Decimal(format(start_bal, '.8f'))

            assert start_bal == cur_bal, \
                'Unexpected current balance: {}, should be minus two mints and two fee, ' \
                'but start was {}'.format(cur_bal, start_bal)

        # confirmations should be i due to less than 4 blocks was generated after transactions send
        for i in range(5):
            for tr in mint_trans:
                info = self.nodes[0].gettransaction(tr)
                confrms = info['confirmations']
                assert confrms == i, \
                    'Confirmations should be {}, ' \
                    'due to {} blocks was generated after transaction was created,' \
                    'but was {}'.format(i, i, confrms)

                tr_type = info['details'][0]['category']
                assert tr_type == 'mint', 'Unexpected transaction type: {}'.format(tr_type)

            for denom in denoms:
                res = False
                args = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': denom}
                try:
                    res = self.nodes[0].spendmany("", args)
                except JSONRPCException as ex:
                    assert ex.error['message'] == 'Insufficient funds'

                assert not res, 'Did not raise spend exception, but should be.'

            self.nodes[0].generate(1)
            self.sync_all()

        # generate last confirmation block - now all transactions should be confimed
        self.nodes[0].generate(1)
        self.sync_all()

        for tr in mint_trans:
            info = self.nodes[0].gettransaction(tr)
            confrms = info['confirmations']
            assert confrms == 6, \
                f'Confirmations should be 6, ' \
                f'due to 6 blocks was generated after transaction was created,' \
                f'but was {confrms}.'
            tr_type = info['details'][0]['category']
            assert tr_type == 'mint', 'Unexpected transaction type'

        spend_trans = list()
        spend_total = Decimal(0)

        self.sync_all()

        start_bal = self.nodes[0].getbalance()
        print(start_bal)
        total_spend_fee = 0
        for denom in denoms:
            myaddr = self.nodes[0].listreceivedbyaddress(0, True)[0]['address']

            args = {myaddr: denom}

            spend_trans.append(self.nodes[0].spendmany("", args))
            info = self.nodes[0].gettransaction(spend_trans[-1])
            confrms = info['confirmations']
            tr_type = info['details'][0]['category']
            total_spend_fee += -info['fee']
            spend_total = float(spend_total) + denom
            assert confrms == 0, \
                f'Confirmations should be 0, ' \
                f'due to 0 blocks was generated after transaction was created,' \
                f'but was {confrms}.'
            assert tr_type == 'spend', 'Unexpected transaction type'

        before_new = self.nodes[0].getbalance()
        self.nodes[0].generate(2)
        after_new = self.nodes[0].getbalance()
        delta = after_new - before_new
        self.sync_all()

        # # Start balance increase on generated blocks to confirm
        start_bal += delta
        cur_bal = Decimal(format(self.nodes[0].getbalance(), '.1f'))
        spend_total = Decimal(format(spend_total, '.8f'))

        #TODO check why currently was not minused from total sum
        start_bal = start_bal + spend_total

        assert start_bal == cur_bal, \
            f'Unexpected current balance: {cur_bal}, should increase on {spend_total}, ' \
            f'but start was {start_bal}'

        for tr in spend_trans:
            info = self.nodes[0].gettransaction(tr)

            confrms = info['confirmations']
            tr_type = info['details'][0]['category']
            assert confrms >= 1, \
                f'Confirmations should be 1 or more, ' \
                f'due to 1 blocks was generated after transaction was created,' \
                f'but was {confrms}.'
            assert tr_type == 'spend', 'Unexpected transaction type'


if __name__ == '__main__':
    SigmaMintSpendTest().main()