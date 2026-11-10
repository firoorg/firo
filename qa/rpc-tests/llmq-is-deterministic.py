#!/usr/bin/env python3
# Copyright (c) 2026 The Firo developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import os

from test_framework import mininode
from test_framework.mininode import *
from test_framework.test_framework import EvoZnodeTestFramework
from test_framework.util import *
from time import *

'''
llmq-is-deterministic.py

Checks the switch from legacy InstantSend locks ("islock") to deterministic ones ("isdlock", DIP22), which name the
quorum that signed them through the cycleHash.

'''

ISDLOCK_HEIGHT = 800
ISDLOCK_PROTO_VERSION = 90032
MSG_ISLOCK = 30
MSG_ISDLOCK = 31
LLMQ_5_60 = 100
DKG_INTERVAL = 24
# both formats are accepted for one DKG interval before and after the switch
GRACE = DKG_INTERVAL

class TestNode(SingleNodeConnCB):
    def __init__(self):
        SingleNodeConnCB.__init__(self)
        self.to_send = {}
        self.requested = set()  # lock hashes the node asked us for
        self.invs = {}          # lock hash -> inv type
        self.islocks = {}       # txid -> msg_islock
        self.isdlocks = {}      # txid -> msg_isdlock

    def send_lock(self, lock, inv_type):
        hash = uint256_from_str(hash256(lock.serialize()))
        self.to_send[hash] = lock
        self.send_message(msg_inv([CInv(inv_type, hash)]))
        return hash

    def on_getdata(self, conn, message):
        for inv in message.inv:
            if inv.hash in self.to_send:
                self.requested.add(inv.hash)
                self.send_message(self.to_send[inv.hash])

    def on_inv(self, conn, message):
        for inv in message.inv:
            if inv.type in (MSG_ISLOCK, MSG_ISDLOCK):
                self.invs[inv.hash] = inv.type
        SingleNodeConnCB.on_inv(self, conn, message)

    def on_islock(self, conn, message):
        self.islocks[message.txid] = message

    def on_isdlock(self, conn, message):
        self.isdlocks[message.txid] = message

    def on_notfound(self, conn, message):
        pass


class LLMQ_IS_Deterministic(EvoZnodeTestFramework):
    def __init__(self):
        # node 0 is the faucet, node 1 a simple node and the others are masternodes
        super().__init__(7, 5, extra_args=[['-debug=instantsend', '-isdlockheight=%d' % ISDLOCK_HEIGHT]] * 7)

    def connect_test_node(self, node_num=0):
        test_node = TestNode()
        test_node.add_connection(NodeConn('127.0.0.1', p2p_port(node_num), self.nodes[node_num], test_node))
        return test_node

    def restart_simple_node(self, connect=True):
        stop_node(self.nodes[1], 1)
        self.nodes[1] = start_node(1, self.options.tmpdir, self.extra_args[1])
        if connect:
            connect_nodes(self.nodes[1], 0)
        wait_to_sync(self.nodes[1], True)

    def run_test(self):
        # A node only evaluates whether InstantSend is enabled when it starts, and the simple node started without a
        # chain. Restart it so that it processes locks.
        self.restart_simple_node()

        # isdlock inventory is only announced to peers that understand it
        mininode.MY_VERSION = ISDLOCK_PROTO_VERSION
        self.sender = self.connect_test_node()
        self.listener = self.connect_test_node()
        NetworkThread().start()
        self.sender.wait_for_verack()
        self.listener.wait_for_verack()

        self.quorum_a = self.mine_quorum()
        self.quorum_b = self.mine_quorum()
        assert(self.nodes[0].getblockcount() < ISDLOCK_HEIGHT - GRACE)
        self.wait_for_chainlocked_block_all_nodes(self.nodes[0].getbestblockhash())

        self.test_long_before_activation()
        self.mine_to(ISDLOCK_HEIGHT - 1)
        self.test_last_block_before_activation()
        self.mine_to(ISDLOCK_HEIGHT)
        self.test_activation_block()
        self.mine_to(ISDLOCK_HEIGHT + GRACE)
        self.test_long_after_activation()
        self.test_full_verification()
        lock, rawtx = self.test_quorum_must_be_responsible()
        self.test_lock_survives_restart(lock, rawtx)

    def mine_to(self, height):
        self.nodes[0].generate(height - self.nodes[0].getblockcount())
        self.sync_all()
        self.wait_for_chainlocked_block_all_nodes(self.nodes[0].getbestblockhash())
        assert_equal(self.nodes[0].getblockcount(), height)

    def quorum_hashes(self):
        return self.nodes[0].quorum('list')['llmq_5_60']

    def relayed(self, hash, listener=None, timeout=10):
        listener = listener or self.listener
        return wait_until(lambda: hash in listener.invs, timeout=timeout)

    def log_count(self, node_num, text):
        with open(os.path.join(self.options.tmpdir, "node%d" % node_num, "regtest", "debug.log"), errors='replace') as f:
            return f.read().count(text)

    # Let the node lock a TX and return the lock that it announced
    def node_creates_lock(self, deterministic):
        txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 1)
        assert(self.wait_for_instantlock(txid, self.nodes[0], do_assert=True))
        txid = int(txid, 16)
        expected, unexpected = (self.listener.isdlocks, self.listener.islocks) if deterministic else (self.listener.islocks, self.listener.isdlocks)
        assert(wait_until(lambda: txid in expected, timeout=10))
        assert(txid not in unexpected)
        return expected[txid]

    # Sign a lock for a new TX that the nodes don't know yet
    def new_signed_lock(self):
        rawtx = self.create_raw_tx(self.nodes[0], self.nodes[0], 1, 1, 100)['hex']
        return (rawtx,) + self.sign_lock(rawtx)

    def assert_accepted(self, lock, inv_type, sender=None, listener=None):
        hash = (sender or self.sender).send_lock(lock, inv_type)
        assert(self.relayed(hash, listener))
        assert_equal((listener or self.listener).invs[hash], inv_type)
        return hash

    def assert_refused(self, lock, inv_type, requested, sender=None, listener=None):
        sender = sender or self.sender
        hash = sender.send_lock(lock, inv_type)
        if requested:
            assert(wait_until(lambda: hash in sender.requested, timeout=10))
        assert(not self.relayed(hash, listener, timeout=5))
        assert_equal(hash in sender.requested, requested)

    def test_long_before_activation(self):
        self.node_creates_lock(False)

        # deterministic locks are not even requested, so nobody can replace a legacy lock by its deterministic form
        rawtx, inputs, txid, quorum_hash, sig = self.new_signed_lock()
        self.assert_refused(msg_isdlock(inputs, txid, int(quorum_hash, 16), sig), MSG_ISDLOCK, False)
        self.assert_accepted(msg_islock(inputs, txid, sig), MSG_ISLOCK)
        self.nodes[0].sendrawtransaction(rawtx)

    def test_last_block_before_activation(self):
        self.node_creates_lock(False)

        # Other nodes might be a block ahead, so both formats are accepted already
        rawtx, inputs, txid, quorum_hash, sig = self.new_signed_lock()
        self.assert_accepted(msg_isdlock(inputs, txid, int(quorum_hash, 16), sig), MSG_ISDLOCK)
        # ...but a TX only needs one lock
        self.assert_refused(msg_islock(inputs, txid, sig), MSG_ISLOCK, True)
        self.nodes[0].sendrawtransaction(rawtx)

    def test_activation_block(self):
        isdlock = self.node_creates_lock(True)
        assert_equal(isdlock.version, 1)
        cycle_hash = "%064x" % isdlock.cycleHash
        assert(cycle_hash in self.quorum_hashes())
        assert_equal(self.nodes[0].getblockheader(cycle_hash)['height'] % DKG_INTERVAL, 0)

        # Other nodes might be a block behind, so legacy locks are still accepted
        rawtx, inputs, txid, quorum_hash, sig = self.new_signed_lock()
        self.assert_accepted(msg_islock(inputs, txid, sig), MSG_ISLOCK)
        self.nodes[0].sendrawtransaction(rawtx)

    def test_long_after_activation(self):
        self.node_creates_lock(True)

        rawtx, inputs, txid, quorum_hash, sig = self.new_signed_lock()
        other_quorum_hash = [h for h in self.quorum_hashes() if h != quorum_hash][0]

        # legacy locks are not requested anymore
        self.assert_refused(msg_islock(inputs, txid, sig), MSG_ISLOCK, False)

        # the lock must name the quorum that signed it
        invalid_sigs = self.log_count(0, "invalid sig in islock")
        self.assert_refused(msg_isdlock(inputs, txid, int(other_quorum_hash, 16), sig), MSG_ISDLOCK, True)
        assert_equal(self.log_count(0, "invalid sig in islock"), invalid_sigs + 1)

        # an unknown version is ignored
        self.assert_refused(msg_isdlock(inputs, txid, int(quorum_hash, 16), sig, version=2), MSG_ISDLOCK, True)

        # The cycleHash must be the first block of a DKG cycle. The peer gets disconnected for this one.
        sender = self.connect_test_node()
        sender.wait_for_verack()
        not_a_cycle_start = self.nodes[0].getblockhash(self.nodes[0].getblockheader(quorum_hash)['height'] + 1)
        self.assert_refused(msg_isdlock(inputs, txid, int(not_a_cycle_start, 16), sig), MSG_ISDLOCK, True, sender=sender)
        assert(wait_until(lambda: sender.connection.state == "closed", timeout=10))

        # the correct lock is accepted and relayed with the new inventory type, even without the TX
        isdlock = msg_isdlock(inputs, txid, int(quorum_hash, 16), sig)
        self.assert_accepted(isdlock, MSG_ISDLOCK)
        assert(wait_until(lambda: txid in self.listener.isdlocks, timeout=10))
        assert_equal(self.listener.isdlocks[txid].serialize(), isdlock.serialize())

        # and it locks the TX once it arrives
        txid_hex = self.nodes[0].sendrawtransaction(rawtx)
        assert(self.wait_for_instantlock(txid_hex, self.nodes[0], do_assert=True))

    def test_full_verification(self):
        # A node that has the recovered signature of a lock does not verify the signature again. Keep the simple node
        # away from the signing session, so that it has to.
        isolate_node(self.nodes[1])
        rawtx, inputs, txid, quorum_hash, sig = self.new_signed_lock()
        other_quorum_hash = [h for h in self.quorum_hashes() if h != quorum_hash][0]
        reconnect_isolated_node(self.nodes[1], 0)

        request_id = "%064x" % uint256_from_str(hash256(ser_string(b"islock") + ser_vector(inputs)))
        assert(not self.nodes[1].quorum('hasrecsig', LLMQ_5_60, request_id, "%064x" % txid))

        sender = self.connect_test_node(1)
        listener = self.connect_test_node(1)
        sender.wait_for_verack()
        listener.wait_for_verack()

        self.assert_refused(msg_isdlock(inputs, txid, int(other_quorum_hash, 16), sig), MSG_ISDLOCK, True, sender, listener)
        reconstructed = self.log_count(1, "passing reconstructed recSig to signing mgr")
        self.assert_accepted(msg_isdlock(inputs, txid, int(quorum_hash, 16), sig), MSG_ISDLOCK, sender, listener)
        assert_equal(self.log_count(1, "passing reconstructed recSig to signing mgr"), reconstructed + 1)

        txid_hex = self.nodes[1].sendrawtransaction(rawtx)
        assert(self.wait_for_instantlock(txid_hex, self.nodes[1], do_assert=True))

    def quorum_score(self, quorum_hash, request_id):
        # see CSigningManager::SelectQuorumForSigning, the lowest score wins and uint256 compares like memcmp
        return hash256(bytes([LLMQ_5_60]) + ser_uint256(int(quorum_hash, 16)) + ser_uint256(request_id))

    def test_quorum_must_be_responsible(self):
        # A valid signature is not enough, one of the active sets that the quorum was part of must have selected it
        # for the request. Build a request that quorum B only wins against the next quorum C, and show it to a node
        # that doesn't know C yet. For this node B never won, as A beats it.
        stop_node(self.nodes[1], 1)
        all_nodes = self.nodes
        self.nodes = [node for i, node in enumerate(all_nodes) if i != 1]
        quorum_c = self.mine_quorum()
        self.nodes = all_nodes
        assert_equal(self.quorum_hashes(), [quorum_c, self.quorum_b])

        utxo = None
        for candidate in self.nodes[0].listunspent():
            if not candidate.get('spendable', True) or float(candidate['amount']) < 0.01:
                continue
            outpoint = COutPoint(int(candidate['txid'], 16), candidate['vout'])
            request_id = uint256_from_str(hash256(ser_string(b"islock") + ser_vector([outpoint])))
            if self.quorum_score(self.quorum_a, request_id) < self.quorum_score(self.quorum_b, request_id) < self.quorum_score(quorum_c, request_id):
                utxo = candidate
                break
        assert(utxo is not None)
        rawtx = self.nodes[0].createrawtransaction([{"txid": utxo['txid'], "vout": utxo['vout']}], {self.nodes[0].getnewaddress(): satoshi_round(float(utxo['amount']) - 0.001)})
        rawtx = self.nodes[0].signrawtransaction(rawtx)['hex']
        inputs, txid, quorum_hash, sig = self.sign_lock(rawtx)
        assert_equal(quorum_hash, self.quorum_b)
        lock = msg_isdlock(inputs, txid, int(quorum_hash, 16), sig)

        self.nodes[1] = start_node(1, self.options.tmpdir, self.extra_args[1])
        wait_to_sync(self.nodes[1], True)
        assert_equal(self.nodes[1].quorum('list')['llmq_5_60'], [self.quorum_b, self.quorum_a])
        sender = self.connect_test_node(1)
        listener = self.connect_test_node(1)
        sender.wait_for_verack()
        listener.wait_for_verack()
        self.assert_refused(lock, MSG_ISDLOCK, True, sender, listener)
        assert_equal(self.log_count(1, "is not responsible for this islock"), 1)

        # once the node knows quorum C it accepts the same lock
        connect_nodes(self.nodes[1], 0)
        sync_blocks([self.nodes[0], self.nodes[1]])
        sender = self.connect_test_node(1)
        sender.wait_for_verack()
        hash = sender.send_lock(lock, MSG_ISDLOCK)
        assert(self.relayed(hash, listener, timeout=60))
        assert_equal(self.log_count(1, "is not responsible for this islock"), 1)
        return lock, rawtx

    def test_lock_survives_restart(self, lock, rawtx):
        txid_hex = self.nodes[1].sendrawtransaction(rawtx)
        assert(self.wait_for_instantlock(txid_hex, self.nodes[1], do_assert=True))
        hash = uint256_from_str(hash256(lock.serialize()))

        self.restart_simple_node(connect=False)
        peer = self.connect_test_node(1)
        peer.wait_for_verack()
        assert(self.nodes[1].getrawtransaction(txid_hex, True)['instantlock'])

        # a lock is only served in its own format
        peer.send_message(msg_getdata([CInv(MSG_ISLOCK, hash)]))
        peer.send_message(msg_getdata([CInv(MSG_ISDLOCK, hash)]))
        assert(wait_until(lambda: lock.txid in peer.isdlocks, timeout=10))
        assert_equal(peer.isdlocks[lock.txid].serialize(), lock.serialize())
        assert(lock.txid not in peer.islocks)
        connect_nodes(self.nodes[1], 0)

    def sign_lock(self, hextx):
        tx = FromHex(CTransaction(), hextx)
        tx.rehash()

        request_id_buf = ser_string(b"islock") + ser_compact_size(len(tx.vin))
        inputs = []
        for txin in tx.vin:
            request_id_buf += txin.prevout.serialize()
            inputs.append(txin.prevout)
        request_id = "%064x" % uint256_from_str(hash256(request_id_buf))
        message_hash = "%064x" % tx.sha256

        for mn in self.mninfo:
            mn.node.quorum('sign', LLMQ_5_60, request_id, message_hash)

        recSig = None
        t = time()
        while time() - t < 10:
            try:
                recSig = self.nodes[0].quorum('getrecsig', LLMQ_5_60, request_id, message_hash)
                break
            except:
                sleep(0.1)
        assert(recSig is not None)

        return inputs, tx.sha256, recSig['quorumHash'], hex_str_to_bytes(recSig['sig'])

if __name__ == '__main__':
    LLMQ_IS_Deterministic().main()
