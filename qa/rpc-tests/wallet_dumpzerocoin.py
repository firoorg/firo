#!/usr/bin/env python3
import time
import os
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.test_helper import get_dumpwallet_otp

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
        zcoin_mints = self.nodes[0].listmintzerocoins()
        zcoin_unspentmints = self.nodes[0].listunspentmintzerocoins()
        zcoin_spendzcoins = self.nodes[0].listspendzerocoins(100) 
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

        exp_zcoin_mints = self.nodes[0].listmintzerocoins()
        exp_zcoin_unspentmints = self.nodes[0].listunspentmintzerocoins()
        exp_zcoin_spendzcoins = self.nodes[0].listspendzerocoins(100) 

        assert_equal(exp_zcoin_unspentmints, exp_zcoin_unspentmints)
        
        assert_equal(exp_zcoin_mints, zcoin_mints)

        assert_equal (exp_zcoin_spendzcoins, zcoin_spendzcoins)    


if __name__ == '__main__':
    WalletDumpZerocoinTest().main()