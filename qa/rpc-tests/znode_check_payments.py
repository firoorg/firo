#!/usr/bin/env python3
import time
from decimal import *

from test_framework.test_framework import ZnodeTestFramework
from test_framework.util import *

# Description: a very straightforward check of Znode operability
# 1. start Znodes
# 2. mine blocks
# 3. check znode reward
class ZnodeCheckPayments(ZnodeTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = True

    def run_test(self):
        self.generate_znode_collateral()
        sync_blocks(self.nodes)

        collateral = self.send_mature_znode_collateral(1)

        self.generate_znode_privkey(1, 1)
        self.write_master_znode_conf(1, self.znode_priv_keys[1], collateral.tx_id, collateral.n, 1)
        self.restart_as_znode(1)

        self.znode_start(1)

        self.wait_znode_enabled(0)

        self.nodes[0].generate(1)
        sync_blocks(self.nodes)

        assert_equal(15, self.nodes[1].getwalletinfo()["immature_balance"])

if __name__ == '__main__':
    ZnodeCheckPayments().main()