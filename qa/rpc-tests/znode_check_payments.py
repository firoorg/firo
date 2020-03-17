#!/usr/bin/env python3
import time
from decimal import *

from test_framework.test_framework import ZnodeTestFramework
from test_framework.util import *

# Description: a very straightforward check of Znode operability
# 1. Start several nodes
# 2. Mine blocks and check the reward comes to the proper nodes
# 3. Shut down a node and make sure no more reward
# 5+6n formula is explained at the bottom of the file

class ZnodeCheckPayments(ZnodeTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 5
        self.num_znodes = 3
        self.setup_clean_chain = True

    def run_test(self):

        for zn in range(self.num_znodes):
            self.generate_znode_collateral()
            collateral = self.send_mature_znode_collateral(zn)

            self.generate_znode_privkey(zn)
            self.write_master_znode_conf(zn, collateral)

        self.generate_znode_collateral()
        collateral3 = self.send_mature_znode_collateral(3)

        for zn in range(self.num_znodes):
            self.restart_as_znode(zn)
            self.znode_start(zn)

        self.wait_znode_enabled(self.num_znodes)

        self.generate(5 + 3*6)

        for zn in range(self.num_znodes):
            assert_equal(1000 + 4*15, get_full_balance(self.nodes[zn]))

# New Znode
        self.generate_znode_privkey(3)
        self.write_master_znode_conf(3, collateral3)

        self.restart_as_znode(3)
        self.znode_start(3)

        self.wait_znode_enabled(4)

        self.generate(6)

        for zn in range(self.num_znodes):
            assert_equal(1000 + 5*15, get_full_balance(self.nodes[zn]))

        assert_equal(1000 + 15, get_full_balance(self.nodes[3]))

# Spend Znode output
        generator_address = self.nodes[self.num_nodes - 1].getaccountaddress("")
        znode_output = self.nodes[3].listlockunspent()
        print(self.nodes[3].lockunspent(True, znode_output))
        self.nodes[3].sendtoaddress(generator_address, 1000, "", "", True)

        self.generate(6) #The Znode has been scheduled already, need one run for the schedule to get updated

        assert_equal(1000 + 15 - 1000 + 15, get_full_balance(self.nodes[3]))

        self.generate(2*6)

        assert_equal(30, get_full_balance(self.nodes[3]))

        for zn in range(self.num_znodes):
            assert_equal(1000 + 8*15, get_full_balance(self.nodes[zn]))

if __name__ == '__main__':
    ZnodeCheckPayments().main()

#