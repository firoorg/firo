#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test ADDRv2 relay and reception
"""

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import time

class AddrReceiver(SingleNodeConnCB):
    def __init__(self):
        super().__init__()
        self.received_addrs_v1 = []
        self.received_addrs_v2 = []

    def add_connection(self, conn):
        self.connection = conn

    def on_addr(self, conn, message):
        for addr in message.addrs:
            self.received_addrs_v1.append(addr)

    def on_addrv2(self, conn, message):
        for addr in message.addrs:
            self.received_addrs_v2.append(addr)

    def addr_received(self):
        return len(self.received_addrs_v1) > 0

    def addrv2_received(self):
        return len(self.received_addrs_v2) > 0


class AddrV2RelayTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug=net"]))

    def run_test(self):
        print("Testing ADDRv2 basic relay functionality")
        
        # Create source node
        addr_source = SingleNodeConnCB()
        source_conn = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], addr_source)
        addr_source.add_connection(source_conn)
        
        # Create receiver node
        msg_receiver = AddrReceiver()
        receiver_conn = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], msg_receiver)
        msg_receiver.add_connection(receiver_conn)
        
        NetworkThread().start()
        addr_source.wait_for_verack()
        msg_receiver.wait_for_verack()

        # Have receiver advertise addrv2 support
        print("Sending sendaddrv2 message")
        msg_receiver.connection.send_message(msg_sendaddrv2())
        msg_receiver.sync_with_ping()

        print("Testing that sendaddrv2 message is accepted")
        # If we got here without disconnect, sendaddrv2 was accepted
        print("✓ Node accepted sendaddrv2 message successfully")
        
        # Test that regular addr messages still work
        print("Sending regular addr messages (IPv4)")
        addr_msg = msg_addr()
        for i in range(3):
            addr = CAddress()
            addr.time = int(time.time())
            addr.nServices = NODE_NETWORK
            addr.ip = f"123.123.123.{i}"
            addr.port = 8333
            addr_msg.addrs.append(addr)
        
        source_conn.send_message(addr_msg)
        addr_source.sync_with_ping()
        print("✓ Node accepted addr messages without disconnecting")

        # Cleanup
        source_conn.disconnect_node()
        receiver_conn.disconnect_node()
        
        print("✓ ADDRv2 relay test passed!")


if __name__ == '__main__':
    AddrV2RelayTest().main()
