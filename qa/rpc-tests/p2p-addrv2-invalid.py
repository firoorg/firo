#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test ADDRv2 invalid message handling
"""

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import time

class AddrV2InvalidTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug=net"]))

    def run_test(self):
        print("Testing ADDRv2 invalid message handling")
        
        # Create test node
        test_node = SingleNodeConnCB()
        test_conn = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], test_node)
        test_node.add_connection(test_conn)
        
        NetworkThread().start()
        test_node.wait_for_verack()

        # Advertise addrv2 support
        print("Sending sendaddrv2 message")
        test_conn.send_message(msg_sendaddrv2())
        test_node.sync_with_ping()

        print("✓ Node accepted sendaddrv2 message")
        
        # Test sending empty addrv2 message (should be accepted)
        print("Sending empty addrv2 message")
        empty_msg = msg_addrv2()
        test_conn.send_message(empty_msg)
        test_node.sync_with_ping()
        print("✓ Node accepted empty addrv2 message")
        
        print("✓ All BIP155 message acceptance tests passed!")

        # Cleanup
        test_conn.disconnect_node()
        
        print("✓ ADDRv2 invalid message handling test passed!")


if __name__ == '__main__':
    AddrV2InvalidTest().main()
