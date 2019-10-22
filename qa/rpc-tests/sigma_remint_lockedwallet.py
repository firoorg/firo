#!/usr/bin/env python3
import time
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


#Locking wallet disable mint/spend functionality

#1. Generate some blocks
#2. Mint zcoins
#4. Encrypt wallet
#5. Try to remint
#6. Unlock wallet
#7. Try to remint
#8. Lock wallet before timeout finished
#9. Try to remint
#10. Unlock wallet
#11. Check all remint will pass
#12. Check can mint/spend
# Expected:  Check available to mint/spend (edited)
class SigmaRemintLockedWalletTest(BitcoinTestFramework):
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

        # try to mint without decrypt
        for denom in zcoin_denoms:
            self.nodes[0].mintzerocoin(denom)
            self.nodes[0].mintzerocoin(denom)

        self.nodes[0].generate(300)

        zcoin_mints = self.nodes[0].listunspentmintzerocoins()

        assert len(zcoin_mints) == 10, 'Should be 10 zcoin mints after zcoin mint, but was: {}' \
            .format(len(zcoin_mints))


        # encrypt wallet
        encr_key = 'testtesttesttest'

        self.nodes[0].encryptwallet(encr_key)
        bitcoind_processes[0].wait()
        self.nodes[0] = start_nodes(1, self.options.tmpdir)[0]

        # try to remint without unlocking
        assert_raises(JSONRPCException, self.nodes[0].remintzerocointosigma, zcoin_denoms[0])

        # unlock for 10 secs
        self.nodes[0].walletpassphrase(encr_key, 10)
        time.sleep(5)
        
        self.nodes[0].generate(1)

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
    SigmaRemintLockedWalletTest().main()
