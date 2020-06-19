#!/usr/bin/env python3
import time
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


#`-zapwallettxes` with unconfirmed transactions


# 1. start wallet
# 2. mine blocks to activate sigma
# 3. mint some coins
# 4. generate blocks
# 5. get listunspent transactions
# 6. mint one more unconfirmed
# 7. restart with `-zapwallettxes=1`
# 8. check listunspentmints - should be as on step 5 (cause -zapwallettxes=1 clean mempool)
# 9. spend and not confirm
# 10. restart with `-zapwallettxes=1`
# 11. check listunspentmints - should be as on step 5 (cause -zapwallettxes=1 clean mempool)
# 12. mint
# 13. generate blocks
# 14. check listunspentmints, it should increased on mint
# 15. spend
# 16. generate block
# 17. check listunspentmints it should decreased
class HDMintMempoolZapTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = False

    def setup_nodes(self):
        # This test requires mocktime
        enable_mocktime()
        return start_nodes(self.num_nodes, self.options.tmpdir)

    def list_unspent_sigma_mints(self):
        mints = self.nodes[0].listunspentsigmamints()
        for mint in mints:
            mint.pop('confirmations', None)
        return sorted(mints,  key=lambda k: k['txid'] + str(k['vout']))

    def hdmint_zap(self, configuration):

        sigma_denoms = [0.05, 0.1, 0.5, 1, 10, 25, 100]

        self.nodes[0].generate(401)

        for denom in sigma_denoms:
            self.nodes[0].mint(denom)
            self.nodes[0].mint(denom)

        self.nodes[0].generate(10)

        sigma_mints1 = self.list_unspent_sigma_mints()
        assert len(sigma_mints1) > 1, 'Should be some sigma mints after mint, but was: {}' \
            .format(len(sigma_mints1))

        self.nodes[0].mint(1)

        self.nodes[0].stop()
        bitcoind_processes[0].wait()

        self.nodes[0] = start_node(0,self.options.tmpdir, configuration)
        time.sleep(1) # rescan time
        sigma_mints2 = self.list_unspent_sigma_mints()

        assert sigma_mints2 == sigma_mints1, \
            'Unconfirmed mints should pass away with ' + str(configuration)

        val = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1}
        self.nodes[0].spendmany('', val)

        self.nodes[0].stop()
        bitcoind_processes[0].wait()

        self.nodes[0] = start_node(0, self.options.tmpdir, configuration)
        time.sleep(1) # rescan time
        sigma_mints3 = self.list_unspent_sigma_mints()

        assert sigma_mints3 == sigma_mints1, \
            'Unconfirmed spends should pass away with ' + str(configuration)

        mint_txid = self.nodes[0].mint(sigma_denoms[0])

        self.nodes[0].generate(1)

        sigma_mints4 = self.list_unspent_sigma_mints()

        assert len(sigma_mints4) == len(sigma_mints1) + 1, \
            'Mints are not generated after restarting with ' + str(configuration)

        sigma_mints4_set = set(str(mint) for mint in sigma_mints4)
        sigma_mints1_set = set(str(mint) for mint in sigma_mints1)

        assert sigma_mints4_set & sigma_mints1_set == sigma_mints1_set, \
            'Initial mint set should not change. Params: ' + str(configuration)

        diff_set = sigma_mints4_set - sigma_mints1_set

        assert len(diff_set) == 1 and mint_txid in diff_set.pop(), \
            'The new mint should be in the set diff. Params: ' + str(configuration)

    def run_test(self):
        getcontext().prec = 6
        self.sync_all()

        zapwal1 = ["-zapwallettxes=1"]
        self.hdmint_zap(zapwal1)

        zapwal2 = ["-zapwallettxes=2"]
        self.hdmint_zap(zapwal2)

if __name__ == '__main__':
    HDMintMempoolZapTest().main()
