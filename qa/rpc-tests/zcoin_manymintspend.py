#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Exercise the listreceivedbyaddress API
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class ZcoinManyMintSpendTest(BitcoinTestFramework):

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

            # fee is negative here
            fee = info['fee']

            cur_bal = self.nodes[0].getbalance()
            start_bal = start_bal - Decimal(2*denom - fee)
            assert start_bal == cur_bal, \
                f'Unexpected current balance: {cur_bal}, should be minus two mints and 1 fee, ' \
                f'but start was {start_bal}'


        # confirmations should be i due to less than 6 blocks was generated after transactions send
        for i in range(5):
            for tr in mint_trans:
                info = self.nodes[0].gettransaction(tr)
                confrms = info['confirmations']
                tr_type = info['details'][0]['category']
                assert confrms == i, \
                    f'Confirmations should be {i}, '\
                    f'due to {i} blocks was generated after transaction was created,' \
                    f'but was {confrms}' 

                assert tr_type == 'mint', 'Unexpected transaction type'
            for denom in denoms:
                res = False
                try: 
                    res = self.nodes[0].spendzerocoin(denom)
                except JSONRPCException as ex:
                    assert ex.error['message'] == \
                        'it has to have at least two mint coins with at least 6 confirmation in order to spend a coin'
                assert not res, 'Did not raise spend exception, but should be.'
                
            self.nodes[0].generate(1)
            self.sync_all()
        
        # generate last confirmation block - now all transactions should be confimed
        self.nodes[0].generate(1)
        self.sync_all()

        for tr in mint_trans:
            info = self.nodes[0].gettransaction(tr)
            confrms = info['confirmations']
            tr_type = info['details'][0]['category']
            assert confrms == 6, \
                f'Confirmations should be 6, ' \
                f'due to 6 blocks was generated after transaction was created,' \
                f'but was {confrms}.' 
            assert tr_type == 'mint', 'Unexpected transaction type'

        # Verify that now we are able to spend
        spend_trans = list()  
        spend_total = Decimal(0)        
        for denom in denoms:
            spend_trans.append(self.nodes[0].spendzerocoin(denom))
            spend_total += denom

        # Verify, that after one confirmation balance will be updated on spends
        self.nodes[0].generate(1)
        self.sync_all()

        # Start balance increase on generated blocks to confirm
        start_bal += 40 * 7
        cur_bal = self.nodes[0].getbalance()
        start_bal = start_bal + spend_total
        assert start_bal == cur_bal, \
            f'Unexpected current balance: {cur_bal}, should increase on {spend_total}, ' \
            f'but start was {start_bal}'


if __name__ == '__main__':
    ZcoinManyMintSpendTest().main()
