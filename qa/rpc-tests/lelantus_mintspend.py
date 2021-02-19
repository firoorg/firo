#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


class LelantusMintSpendTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False

    def run_test(self):
        # Decimal formating: 6 digits for balance will be enought 000.000
        getcontext().prec = 6
        self.nodes[0].generate(1001)
        self.sync_all()

        start_bal = self.nodes[0].getbalance()

        mint_trans = list()
        mint_trans.append(self.nodes[0].mintlelantus(1))
        mint_trans.append(self.nodes[0].mintlelantus(2))

        # Get last added transaction and fee for it
        info = self.nodes[0].gettransaction(mint_trans[-1][0])

        # fee in transaction is negative
        fee = -(info['fee'] * 2)
        cur_bal = self.nodes[0].getbalance()
        start_bal = float(start_bal) - float(fee) - 3
        start_bal = Decimal(format(start_bal, '.8f'))

        assert start_bal == cur_bal, \
            'Unexpected current balance: {}, should be minus two mints and two fee, ' \
            'but start was {}'.format(cur_bal, start_bal)

        for tr in mint_trans:
            info = self.nodes[0].gettransaction(tr[0])
            confrms = info['confirmations']
            assert confrms == 0, \
                'Confirmations should be {}, ' \
                'due to {} blocks was generated after transaction was created,' \
                'but was {}'.format(0, 0, confrms)

            tr_type = info['details'][0]['category']
            assert tr_type == 'mint', 'Unexpected transaction type: {}'.format(tr_type)

        res = False
        args = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1}
        try:
            res = self.nodes[0].joinsplit(args)
        except JSONRPCException as ex:
            assert ex.error['message'] == 'Insufficient funds'

        assert not res, 'Did not raise spend exception, but should be.'

        self.nodes[0].generate(1)
        self.sync_all()

        # generate last confirmation block - now all transactions should be confimed
        self.nodes[0].generate(1)
        self.sync_all()

        for tr in mint_trans:
            info = self.nodes[0].gettransaction(tr[0])
            confrms = info['confirmations']
            assert confrms == 2, \
                'Confirmations should be 2, ' \
                'due to 2 blocks was generated after transaction was created,' \
                'but was {}.'.format(confrms)
            tr_type = info['details'][0]['category']
            assert tr_type == 'mint', 'Unexpected transaction type'

        spend_trans = list()
        spend_total = Decimal(0)

        self.sync_all()

        start_bal = self.nodes[0].getbalance()
        print(start_bal)
        total_spend_fee = 0

        myaddr = self.nodes[0].listreceivedbyaddress(0, True)[0]['address']
        print(1)
        args = {myaddr: 1}

        spend_trans.append(self.nodes[0].joinsplit(args))

        info = self.nodes[0].gettransaction(spend_trans[-1])
        confrms = info['confirmations']
        tr_type = info['details'][0]['category']
        total_spend_fee += -info['fee']
        print(info['fee'])
        print(self.nodes[0].getbalance())
        spend_total = float(spend_total) + 1
        assert confrms == 0, \
            'Confirmations should be 0, ' \
            'due to 0 blocks was generated after transaction was created,' \
            'but was {}.'.format(confrms)
        assert tr_type == 'spend', 'Unexpected transaction type'
        print(self.nodes[0].getbalance())

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
            'Unexpected current balance: {}, should increase on {}, ' \
            'but start was {}'.format(cur_bal, spend_total, start_bal)

        for tr in spend_trans:
            info = self.nodes[0].gettransaction(tr)

            confrms = info['confirmations']
            tr_type = info['details'][0]['category']
            assert confrms >= 1, \
                'Confirmations should be 1 or more, ' \
                'due to 1 blocks was generated after transaction was created,' \
                'but was {}.'.format(confrms)
            assert tr_type == 'spend', 'Unexpected transaction type'


if __name__ == '__main__':
    LelantusMintSpendTest().main()
