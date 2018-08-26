#!/usr/bin/env python3
# Copyright (c) 2018 Bradley Denby
# Distributed under the MIT software license. See the accompanying file COPYING
# or http://www.opensource.org/licenses/mit-license.php.
"""Test transaction behaviors under the Dandelion spreading policy

Tests:
1. Resistance to active probing:
   Stem:  0 --> 1 --> 2 --> 0 where each node has argument "-dandelion=1"
   Probe: TestNode --> 0
   Node 0 generates a Dandelion transaction "tx": 1.0 BTC from Node 0 to Node 2
   TestNode immediately sends getdata for tx to Node 0
   Assert that Node 0 does not reply with tx

2. Loop behavior:
   Stem:  0 --> 1 --> 2 --> 0 where each node has argument "-dandelion=1"
   Probe: TestNode --> 0
   Wait ~5 seconds after Test 1, then TestNode sends getdata for tx to Node 0
   Assert that Node 0 does not reply with tx

3. Resistance to black holes:
   Stem:  0 --> 1 --> 2 --> 0 where each node has argument "-dandelion=1"
   Probe: TestNode --> 0
   Wait ~45 seconds after Test 2, then TestNode sends getdata for tx to Node 0
   Assert that Node 0 replies with tx
"""

from collections import defaultdict
from test_framework.mininode import *                          # NodeConnCB
from test_framework.test_framework import BitcoinTestFramework # BitcoinTestFramework
from test_framework.util import *                              # other stuff
import time                                                    # sleep

class TestP2PConn(NodeConnCB):
    def __init__(self):
        NodeConnCB.__init__(self)
        self.connection = None

        # Track number of messages of each type received and the most recent
        # message of each type
        self.message_count = defaultdict(int)
        self.last_message = {}

        self.ping_counter = 1
        self.last_pong = msg_pong()
        self.block_receive_map = {}

    def add_connection(self, conn):
        self.connection = conn
        self.peer_disconnected = False

    def on_inv(self, conn, message):
        """Receive message and dispatch message to appropriate callback.

        We keep a count of how many of each message type has been received
        and the most recent message of each type."""
        with mininode_lock:
            try:
                command = message.command.decode('ascii')
                self.message_count[command] += 1
                self.last_message[command] = message
                getattr(self, 'on_' + command)(message)
            except:
                print("ERROR delivering %s (%s)" % (repr(message), sys.exc_info()[0]))
                raise


    # Track the last getdata message we receive (used in the test)
    def on_getdata(self, conn, message):
        self.last_getdata = message

    def on_block(self, conn, message):
        message.block.calc_sha256()
        try:
            self.block_receive_map[message.block.sha256] += 1
        except KeyError as e:
            self.block_receive_map[message.block.sha256] = 1

    # Spin until verack message is received from the node.
    # We use this to signal that our test can begin. This
    # is called from the testing thread, so it needs to acquire
    # the global lock.
    def wait_for_verack(self):
        def veracked():
            return self.verack_received
        return wait_until(veracked, timeout=10)

    def wait_for_disconnect(self):
        def disconnected():
            return self.peer_disconnected
        return wait_until(disconnected, timeout=10)

    # Wrapper for the NodeConn's send_message function
    def send_message(self, message):
        self.connection.send_message(message)

    def on_pong(self, conn, message):
        self.last_pong = message

    def on_close(self, conn):
        self.peer_disconnected = True

    # Sync up with the node after delivery of a block
    def sync_with_ping(self, timeout=30):
        def received_pong():
            return (self.last_pong.nonce == self.ping_counter)
        self.connection.send_message(msg_ping(nonce=self.ping_counter))
        success = wait_until(received_pong, timeout=timeout)
        self.ping_counter += 1
        return success

    def send_dandeliontx_getdata(self, dandeliontx_hash):
        msg = msg_getdata([CInv(5,dandeliontx_hash)]) # 5: "DandelionTx"
        self.send_message(msg)


class DandelionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 8
        self.extra_args = []
        for i in range(self.num_nodes):
            self.extra_args.append(["-dandelion=1"]) # ,"-debug=dandelion","-printtoconsole=1"

    def setup_nodes(self):
        print("setup_nodes");
        return start_nodes(
            self.num_nodes, self.options.tmpdir, 
            extra_args=[['-debug', '-whitelist=127.0.0.1']] * self.num_nodes)

    def setup_network(self):
        print("Setting up network for dandelion.")
        self.nodes = self.setup_nodes()
        # Tests 1,2,3: 0 --> 1 --> 2 --> 0
        connect_nodes(self.nodes[0],1)
        connect_nodes(self.nodes[1],2)
        connect_nodes(self.nodes[2],0)
        self.is_network_split = True
        self.sync_all()
        print("Finished setting up network for dandelion.")

    def run_test(self):
        # Convenience variables
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        node2 = self.nodes[2]

        # Setup TestP2PConns
        test_node0 = TestP2PConn()

        # NOTE: In next line p2p_port(0) was replaced by rpc_port(0).
        test_node0.add_connection(NodeConn('127.0.0.1', rpc_port(0), node0, test_node0))

        # Start networking thread
        NetworkThread().start()
        test_node0.wait_for_verack()

        # Get out of Initial Block Download (IBD)
        for node in self.nodes:
          node.generate(1)
        # Generate funds for node0
        node0.generate(101)

        # Tests 1,2,3
        # There is a low probability that one of these tests will fail even if
        # the implementation is correct. Thus, these tests are repeated upon
        # failure. A true bug will result in repeated failures.
        print('Starting tests...')
        test_1_passed = False
        test_2_passed = False
        test_3_passed = False
        tries_left = 5
        while(not (test_1_passed and test_2_passed and test_3_passed) and tries_left > 0):
            tries_left -= 1
            # Test 1: Resistance to active probing
            test_node0.message_count['notfound'] = 0
            node0_txid = node0.sendtoaddress(node2.getnewaddress(),1.0)
            node0_tx = FromHex(CTransaction(),node0.gettransaction(node0_txid)['hex'])
            test_node0.send_dandeliontx_getdata(node0_tx.calc_sha256(True))
            time.sleep(1)
            try:
              assert(test_node0.message_count['notfound']==1)
              if not test_1_passed:
                test_1_passed = True
                self.log.info('Success: resistance to active probing')
            except AssertionError:
              if not test_1_passed and tries_left == 0:
                self.log.info('Failed: resistance to active probing')
            # Test 2: Loop behavior
            test_node0.message_count['notfound'] = 0
            time.sleep(3)
            test_node0.send_dandeliontx_getdata(node0_tx.calc_sha256(True))
            time.sleep(1)
            try:
              assert(test_node0.message_count['notfound']==1)
              if not test_2_passed:
                test_2_passed = True
                self.log.info('Success: loop behavior')
            except AssertionError:
              if not test_2_passed and tries_left == 0:
                self.log.info('Failed: loop behavior')
            # Test 3: Resistance to black holes
            test_node0.message_count['tx'] = 0
            time.sleep(44)
            test_node0.send_dandeliontx_getdata(node0_tx.calc_sha256(True))
            time.sleep(1)
            try:
              assert(test_node0.message_count['tx']==1)
              if not test_3_passed:
                test_3_passed = True
                self.log.info('Success: resistance to black holes')
            except AssertionError:
              if not test_3_passed and tries_left == 0:
                self.log.info('Failed: resistance to black holes')

        print("Running dandelion test 7")
        all_tests_passed = test_1_passed and test_2_passed and test_3_passed
        assert(all_tests_passed)

if __name__ == '__main__':
    DandelionTest().main()
