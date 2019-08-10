#!/usr/bin/env python3
import time
import os
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.test_helper import get_dumpwallet_opt

#Scenario:
#Generate 101 block
#Mint zerocoins of all denominations multiple 3
#generate 6 blocks
#spend zerocoin of all denominations
#generate one block
#Mint zerocoins of all denominations and not confirm them
#getlistunspendzerocoins
#getlistspendzerocoins
#dumpwallet
#importwallet
#verify actual list unspendzerocoins
#verify actual list spend zerocoins

class WalletDumpZerocoinTest(BitcoinTestFramework):
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
        self.nodes[0].generate(101)
        self.sync_all()

        zcoin_denoms = [1, 10, 25, 50, 100]

        # make confirmed mints and spends
        for denom in zcoin_denoms:
            self.nodes[0].mintzerocoin(denom)
            self.nodes[0].mintzerocoin(denom)
            self.nodes[0].mintzerocoin(denom)

        self.nodes[0].generate(6)
        
        for denom in zcoin_denoms:
            self.nodes[0].spendzerocoin(denom)

        self.nodes[0].generate(1)

        #make unconfirmed mints and spends
        for denom in zcoin_denoms:
            self.nodes[0].mintzerocoin(denom)

        for denom in zcoin_denoms:
            self.nodes[0].spendzerocoin(denom) 

        #get list of unspent mints and spends, mints
        zcoin_unspentmints = self.nodes[0].listmintzerocoins()
        zcoin_unspentmints = self.nodes[0].listunspentmintzerocoins()
        zcoin_spendzcoins = self.nodes[0].listspendzerocoins(100) 

        try:
            self.nodes[0].dumpwallet(tmpdir + "/node0/wallet.unencrypted.dump")
        except Exception as ex:
            key = get_dumpwallet_opt(ex.error['message'])
            self.nodes[0].dumpwallet(tmpdir + "/node0/wallet.unencrypted.dump", key)
        
        os.remove(tmpdir + "wallet.data")

        self.nodes[0].importwallet(tmpdir + "/node0/wallet.unencrypted.dump")
        # encrypt wallet
        encr_key = 'testtesttesttest'

        self.nodes[0].encryptwallet(encr_key)
        time.sleep(10)
        self.nodes[0] = start_nodes(1, self.options.tmpdir)[0]

        # try to remint without unlocking
        assert_raises(JSONRPCException, self.nodes[0].remintzerocointosigma, zcoin_denoms[0])

        # unlock for 10 secs
        self.nodes[0].walletpassphrase(encr_key, 10)
        time.sleep(5)

        # remint should work
        self.nodes[0].remintzerocointosigma(zcoin_denoms[0])

        self.nodes[0].generate(10)

        sigma_mint = self.nodes[0].listunspentsigmamints()
        assert len(sigma_mint) == 1, 'Should be 1 sigma mints after remint, but was: {}' \
            .format(len(sigma_mint))

        # lock wallet
        self.nodes[0].walletlock()
        # try to remint without unlocking
        assert_raises(JSONRPCException, self.nodes[0].remintzerocointosigma, zcoin_denoms[0])

        # unlock for 20 secs
        self.nodes[0].walletpassphrase(encr_key, 20)

        for denom in zcoin_denoms[1:]:
            try:
                self.nodes[0].remintzerocointosigma(denom)
            except JSONRPCException as e:
                assert False, "Could not remint denomination {} with next exception {}." \
                    .format(denom, e.error['message'])

        self.nodes[0].generate(50)

        sigma_mint = self.nodes[0].listunspentsigmamints()

        assert len(sigma_mint) == len(zcoin_denoms)+1, \
            'Looks like sigma mints unspendable after remint on encrypted wallet.'

        # check that we are able to mint/spend
        self.nodes[0].mint(1)
        self.nodes[0].generate(10)

        sigma_mint = self.nodes[0].listunspentsigmamints()

        assert len(sigma_mint) == len(zcoin_denoms) + 2, \
            'Looks like we cant mint on encrypted wallet'

        args = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 10}
        self.nodes[0].spendmany("", args)
        self.nodes[0].generate(10)

        sigma_mint = self.nodes[0].listunspentsigmamints()

        assert len(sigma_mint) > len(zcoin_denoms) + 2, \
            'Looks like we cant spend on encrypted wallet.'

        # Check that we can generate blocks after
        self.nodes[0].generate(1)


if __name__ == '__main__':
    WalletDumpZerocoinTest().main()