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

    def hdmint_zap(self, configuration):

        sigma_denoms = [0.05, 0.1, 0.5, 1, 10, 25, 100]

        # 2. mine blocks to activate sigma
        self.nodes[0].generate(401)

        # 3. mint some coins
        self.nodes[0].mint(2 * sum(sigma_denoms))

        # 4. generate blocks
        self.nodes[0].generate(10)

        # 5. get listunspent transactions
        sigma_mints1 = self.nodes[0].listunspentsigmamints()
        assert len(sigma_mints1) > 1, 'Should be some sigma mints after mint, but was: {}' \
            .format(len(sigma_mints1))

        # 6. mint one more unconfirmed
        self.nodes[0].mint(1)

        # 7. restart with `["-zapwallettxes"]`
        self.nodes[0].stop()
        bitcoind_processes[0].wait()

        self.nodes[0] = start_node(0,self.options.tmpdir, configuration)

        # 8. check listunspentmints - should be as on step 5 (cause ["-zapwallettxes"] clean mempool)
        sigma_mints2 = self.nodes[0].listunspentsigmamints()

        assert len(sigma_mints2) == len(sigma_mints1), \
            'The amount of mints should be same as before unconfirmed mint after restart with ["-zapwallettxes"].'

        val = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1}
        # 9. spend and not confirm
        self.nodes[0].spendmany('', val)

        # 10. restart with `["-zapwallettxes"]`
        self.nodes[0].stop()
        bitcoind_processes[0].wait()

        self.nodes[0] = start_node(0, self.options.tmpdir, configuration)

        # 11. check listunspentmints - should be as on step 5 (cause ["-zapwallettxes"] clean mempool)
        sigma_mints3 = self.nodes[0].listunspentsigmamints()

        assert len(sigma_mints3) == len(sigma_mints1), \
            'The amount of mints should be same as before unconfirmed spend after restart with ["-zapwallettxes"].'

        # 12. mint
        # Minting after restart with '-["-zapwallettxes"]'
        self.nodes[0].mint(sigma_denoms[0])

        # 13. generate blocks
        self.nodes[0].generate(50)

        # 14. check listunspentmints, it should increased on mint
        sigma_mints4 = self.nodes[0].listunspentsigmamints()

        # Mints count should pass even after restart with '-["-zapwallettxes"]'
        assert len(sigma_mints4) == len(sigma_mints1) + 1, \
            'After restart with ["-zapwallettxes"] mint does not work.'

        val = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1}

        # 15. spend
        self.nodes[0].spendmany('', val)

        # Check that we can generate blocks after
        self.nodes[0].generate(1)

        # 16. generate block
        sigma_mints5 = self.nodes[0].listunspentsigmamints()

        # 17. check listunspentmints it should decreased
        # Mints count should pass even after restart with '-["-zapwallettxes"]'

    def run_test(self):
        getcontext().prec = 6
        self.sync_all()

        zapwal1 = ["-zapwallettxes=1"]
        print('HD mint test with -zapwallettxes=1')
        self.hdmint_zap(zapwal1)

        print('HD mint test with -zapwallettxes=2')
        zapwal2 = ["-zapwallettxes=2"]
        self.hdmint_zap(zapwal2)

if __name__ == '__main__':
    HDMintMempoolZapTest().main()
