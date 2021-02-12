#!/usr/bin/env python3
import time
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


#`-zapwalletmints` with unconfirmed transactions


# 1. start wallet
# 2. mine blocks to activate sigma
# 3. mint some coins
# 4. generate blocks
# 5. get listunspent transactions
# 6. mint one more unconfirmed
# 7. restart with `-zapwalletmints`
# 8. check listunspentmints - should be as on step 5 (cause -zapwalletmints clean mempool)
# 9. spend and not confirm
# 10. restart with `-zapwalletmints`
# 11. check listunspentmints - should be as on step 5 (cause -zapwalletmints clean mempool)
# 12. mint
# 13. generate blocks
# 14. check listunspentmints, it should increased on mint
# 15. spend
# 16. generate block
# 17. check listunspentmints it should decreased
class SigmaZapWalletMintsUnconfirmedTest(BitcoinTestFramework):
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
        self.sync_all()

        sigma_denoms = [0.05, 0.1, 0.5, 1, 10, 25, 100]

        # 1. mint some coins
        self.nodes[0].mint(2 * sum(sigma_denoms))

        # 2. generate blocks
        self.nodes[0].generate(10)

        # 3. get listunspent transactions
        sigma_mints1 = self.nodes[0].listunspentsigmamints()
        assert len(sigma_mints1) > 1, 'Should be some sigma mints after mint, but was: {}' \
            .format(len(sigma_mints1))

        # 4. mint one more unconfirmed
        self.nodes[0].mint(1)

        # 5. restart with `["-zapwalletmints"]`
        last_block_height = self.nodes[0].getinfo()["blocks"]
        self.nodes[0].stop()
        bitcoind_processes[0].wait()

        self.nodes[0] = start_node(0,self.options.tmpdir, ["-zapwalletmints"])
        while self.nodes[0].getinfo()["blocks"] != last_block_height:
            time.sleep(1)

        # 6. check listunspentmints - should be as on step 5 (cause ["-zapwalletmints"] clean mempool)
        sigma_mints2 = self.nodes[0].listunspentsigmamints()

        assert len(sigma_mints2) == len(sigma_mints1), \
            'The amount of mints should be same as before unconfirmed mint after restart with ["-zapwalletmints"].'

        val = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1}
        # 7. spend and not confirm
        self.nodes[0].spendmany('', val)

        # 8. restart with `["-zapwalletmints"]`
        last_block_height = self.nodes[0].getinfo()["blocks"]
        self.nodes[0].stop()
        bitcoind_processes[0].wait()

        self.nodes[0] = start_node(0, self.options.tmpdir, ["-zapwalletmints"])
        while self.nodes[0].getinfo()["blocks"] != last_block_height:
            time.sleep(1)        

        # 9. check listunspentmints - should be as on step 5 (cause ["-zapwalletmints"] clean mempool)
        sigma_mints3 = self.nodes[0].listunspentsigmamints()

        assert len(sigma_mints3) == len(sigma_mints1), \
            'The amount of mints should be same as before unconfirmed spend after restart with ["-zapwalletmints"].'

        # 10. mint
        # Minting after restart with '-["-zapwalletmints"]'
        self.nodes[0].mint(sigma_denoms[0])

        # 11. generate blocks
        self.nodes[0].generate(50)

        # 12. check listunspentmints, it should increased on mint
        sigma_mints4 = self.nodes[0].listunspentsigmamints()

        # Mints count should pass even after restart with '-["-zapwalletmints"]'
        assert len(sigma_mints4) == len(sigma_mints1) + 1, \
            'After restart with ["-zapwalletmints"] mint does not work.'

        val = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1}

        # 13. spend
        self.nodes[0].spendmany('', val)

        # Check that we can generate blocks after
        self.nodes[0].generate(1)

        # 14. generate block
        sigma_mints5 = self.nodes[0].listunspentsigmamints()

        # 15. check listunspentmints it should decreased
        # Mints count should pass even after restart with '-["-zapwalletmints"]'
        assert len(sigma_mints5) <= len(sigma_mints1), \
            'After restart with ["-zapwalletmints"] mint does not work.'


if __name__ == '__main__':
    SigmaZapWalletMintsUnconfirmedTest().main()
