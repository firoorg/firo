#!/usr/bin/env python3
import time
import os
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.test_helper import get_dumpwallet_otp

#Scenario:
#Generate 401 block to activate sigma
#Mint sigmacoins of all denominations multiple 3
#generate 6 blocks
#spend sigma of all denominations
#generate one block
#Mint sigma of all denominations and not confirm them
#getlistunspendsigma
#getlistspendsigma
#dumpwallet
#importwallet
#verify actual list unspendsigma
#verify actual list spend sigma

class WalletDumpSigmaTest(BitcoinTestFramework):
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
        self.nodes[0].generate(401)
        self.sync_all()


        sigma_denoms = [0.05, 0.1, 0.5, 1, 10, 25, 100]

        # make confirmed mints and spends
        for denom in sigma_denoms:
            self.nodes[0].mint(denom)
            self.nodes[0].mint(denom)
            self.nodes[0].mint(denom)

        self.nodes[0].generate(6)
        
        for denom in sigma_denoms:
            args = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': denom}
            self.nodes[0].spendmany("", args)

        self.nodes[0].generate(1)

        #make unconfirmed mints and spends
        for denom in sigma_denoms:
            self.nodes[0].mint(denom)

        for denom in sigma_denoms:
            args = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': denom}
            self.nodes[0].spendmany("", args) 

        #get list of unspent mints and spends, mints
        sigma_mint = self.nodes[0].listsigmamints()
        sigma_unspentmints = self.nodes[0].listunspentsigmamints(100)
        sigma_spendsigmas = self.nodes[0].listsigmaspends(100)
        tmpdir = self.options.tmpdir

        try:
            self.nodes[0].dumpwallet(tmpdir + "/node0/wallet.unencrypted.dump")
        except Exception as ex:
            key = get_dumpwallet_otp(ex.error['message'])
            self.nodes[0].dumpwallet(tmpdir + "/node0/wallet.unencrypted.dump", key)
        
        stop_node(self.nodes[0], 0)
        os.remove(self.options.tmpdir + "/node0/regtest/wallet.dat")
        start_node(0, self.options.tmpdir)

        self.nodes[0].importwallet(tmpdir + "/node0/wallet.unencrypted.dump")

        exp_sigma_mint = self.nodes[0].listsigmamints()
        exp_sigma_unspentmints = self.nodes[0].listunspentsigmamints(100)
        exp_sigma_spendsigmas = self.nodes[0].listsigmaspends(100)

        assert_equal(exp_sigma_unspentmints, exp_sigma_unspentmints)
        
        assert_equal(exp_sigma_mints, sigma_mints)

        assert_equal (exp_sigma_spendsigmas, sigma_spendsigmas)      


if __name__ == '__main__':
    WalletDumpSigmaTest().main()