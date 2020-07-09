#!/usr/bin/env python3
import time
from decimal import *

from test_framework.test_framework import ZnodeTestFramework
from test_framework.util import *

class ZnodeCheckPayments(ZnodeTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.num_znodes = 2
        self.setup_clean_chain = True

    def run_test(self):
        self.collateral = dict()
        for zn in range(self.num_znodes):
            self.generate_znode_collateral()
            self.collateral[zn] = self.send_mature_znode_collateral(zn)

            self.generate_znode_privkey(zn)
            self.write_master_znode_conf(zn, self.collateral[zn])

        for zn in range(self.num_znodes):
            self.restart_as_znode(zn)
            self.znode_start(zn)

        self.wait_znode_enabled(self.num_znodes)

        znode_list = self.nodes[self.num_nodes - 1].znodelist()
        for zno, status in znode_list.items():
            if self.collateral[1].tx_id in zno:
                assert_equal(status, "ENABLED")

        generator_address = self.nodes[self.num_nodes - 1].getaccountaddress("")
        znode_output = self.nodes[1].listlockunspent()
        self.nodes[1].lockunspent(True, znode_output)
        self.nodes[1].sendtoaddress(generator_address, 1000, "", "", True)

        self.generate(12)

        znode_list = self.nodes[self.num_nodes - 1].znodelist()
        for zno, status in znode_list.items():
            if self.collateral[1].tx_id in zno:
                assert_equal(status, "OUTPOINT_SPENT")

        self.nodes[0].stop()
        bitcoind_processes[0].wait()

        for bl in range(6):
            self.nodes[self.num_nodes - 1].generate(1)
            sync_blocks(self.nodes[1:])
            time.sleep(10)

        znode_list = self.nodes[self.num_nodes - 1].znodelist()
        for zno, status in znode_list.items():
            if self.collateral[0].tx_id in zno:
                assert_equal(status, "NEW_START_REQUIRED")

        self.nodes[0] = start_node(0,self.options.tmpdir)
        
if __name__ == '__main__':
    ZnodeCheckPayments().main()
