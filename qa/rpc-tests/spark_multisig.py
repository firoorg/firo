#!/usr/bin/env python3
# Copyright (c) 2026 The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Spark threshold multisig: 2-of-3 on nodes 0-2, node 3 is an outsider."""

import os
import time
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

COIN = 10**8
GROUP = [0, 1, 2]


class SparkMultisigTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 5  # node 4 tests a competing setup without changing the spend group
        self.setup_clean_chain = False

    def setup_network(self, split=False):
        super().setup_network(split)
        connect_nodes_bi(self.nodes, 3, 4)
        self.sync_all()

    # ---- helpers

    def restart(self, i, extra_args=None):
        self.nodes[i] = start_node(i, self.options.tmpdir, extra_args)

    def reconnect(self):
        for a, b in ((0, 1), (1, 2), (2, 3), (3, 4)):
            connect_nodes_bi(self.nodes, a, b)

    def fails(self, fun, *args):
        try:
            fun(*args)
        except JSONRPCException as e:
            return e.error['message']
        raise AssertionError("expected a JSON-RPC error from %s" % fun)

    def balances(self, expected=None):
        """Wait until all participants report the same (and, if given, the expected) spark balance."""
        deadline = time.time() + 60
        while True:
            vals = [self.nodes[i].getsparkbalance() for i in GROUP]
            if all(v == vals[0] for v in vals) and (expected is None or vals[0]['availableBalance'] == expected):
                return vals[0]['availableBalance']
            if time.time() > deadline:
                raise AssertionError("balances did not settle: %s (expected %s)" % (vals, expected))
            time.sleep(0.5)

    def mine(self, n=1):
        self.nodes[3].generate(n)
        self.sync_all()

    def new_spend(self, recipients=None):
        if recipients is None:
            recipients = {self.spark3: {"amount": 1, "memo": "x", "subtractFee": False}}
        return self.nodes[0].createsparkmultisigspend(recipients)['hex']

    # ---- scenarios

    def competing_setup(self):
        """One RPC batch cannot finalize two different groups for the same wallet."""
        n = self.nodes
        shared = n[4].validateaddress(n[4].getnewaddress())['pubkey']
        rounds = []
        for other in (0, 1):
            remote = n[other].validateaddress(n[other].getnewaddress())['pubkey']
            keys = [shared, remote]
            first = [n[i].addsparkmultisigaddress(2, keys)['hex'] for i in (4, other)]
            remote_second = n[other].addsparkmultisigaddress(2, keys, [first[0]])['hex']
            rounds.append((keys, remote_second))
        calls = [dict(method='addsparkmultisigaddress', params=[2, keys, [data]], id=i)
                 for i, (keys, data) in enumerate(rounds)]
        replies = n[4].auth_service_proxy_instance._batch(calls)
        assert replies[0]['error'] is None and replies[0]['result']['complete'] is True
        assert 'already completed' in replies[1]['error']['message']
        group_address = replies[0]['result']['address']
        self.competing_keys = rounds[0][0]
        wait_node(4)
        self.restart(4)
        self.reconnect()
        assert_equal(n[4].getsparkdefaultaddress()[0], group_address)

        # Key-only salvage must keep the group even though it drops the cached view key.
        stop_node(n[4], 4)
        self.restart(4, ['-salvagewallet'])
        self.reconnect()
        assert_equal(n[4].getsparkdefaultaddress()[0], group_address)
        assert n[4].addsparkmultisigaddress(2, self.competing_keys)['complete'] is True

    def funded_setup_is_rejected(self):
        """A pending incoming mint must be seen before replacing the wallet's keys."""
        n = self.nodes
        own = n[3].validateaddress(n[3].getnewaddress())['pubkey']
        remote = n[0].validateaddress(n[0].getnewaddress())['pubkey']
        keys = [own, remote]
        first = [n[i].addsparkmultisigaddress(2, keys)['hex'] for i in (3, 0)]
        remote_second = n[0].addsparkmultisigaddress(2, keys, [first[0]])['hex']

        n[2].mintspark({self.spark3: {"amount": 5, "memo": ""}})
        sync_mempools(n)
        assert "holds Spark coins" in self.fails(n[3].addsparkmultisigaddress, 2, keys, [remote_second])
        self.mine(1)
        deadline = time.time() + 60
        while n[3].getsparkbalance()['availableBalance'] != 5 * COIN and time.time() < deadline:
            time.sleep(0.5)
        assert_equal(n[3].getsparkbalance()['availableBalance'], 5 * COIN)

    def setup_group(self):
        self.addrs = [self.nodes[i].getnewaddress() for i in GROUP]
        keys = [self.nodes[i].validateaddress(self.addrs[i])['pubkey'] for i in GROUP]
        self.keys = keys
        n = self.nodes

        # pass 1 is stateless and independent of key order
        r1 = [n[i].addsparkmultisigaddress(2, keys) for i in GROUP]
        for i in GROUP:
            assert r1[i]['complete'] is False and 'address' not in r1[i]
            assert_equal(n[i].addsparkmultisigaddress(2, keys), r1[i])
            assert_equal(n[i].addsparkmultisigaddress(2, keys[::-1]), r1[i])
        d1 = [r['hex'] for r in r1]

        # error cases
        assert_raises_jsonrpc(-8, "nrequired", n[0].addsparkmultisigaddress, 0, keys)
        assert_raises_jsonrpc(-8, "nrequired", n[0].addsparkmultisigaddress, 4, keys)
        assert_raises_jsonrpc(-5, "Exactly one", n[3].addsparkmultisigaddress, 2, keys)
        second = n[0].validateaddress(n[0].getnewaddress())['pubkey']
        assert_raises_jsonrpc(-5, "Exactly one", n[0].addsparkmultisigaddress, 2, [keys[0], second, keys[1]])
        self.fails(n[0].addsparkmultisigaddress, 2, keys, [d1[1]])  # data from only one other participant
        self.fails(n[0].addsparkmultisigaddress, 2, keys, ["zz", d1[2]])
        self.fails(n[0].addsparkmultisigaddress, 2, keys, ["00ff", "00ff"])

        # pass 2
        d2 = []
        for i in GROUP:
            r = n[i].addsparkmultisigaddress(2, keys, [d1[j] for j in GROUP if j != i])
            assert r['complete'] is False
            d2.append(r['hex'])

        # pass 3 stops each node
        addrs = []
        for i in GROUP:
            r = n[i].addsparkmultisigaddress(2, keys, [d2[j] for j in GROUP if j != i])
            assert r['complete'] is True
            addrs.append(r['address'])
        assert addrs[0] == addrs[1] == addrs[2]
        self.group_addr = addrs[0]
        for i in GROUP:
            wait_node(i)
        for i in GROUP:
            self.restart(i)
        self.reconnect()

        n = self.nodes
        for i in GROUP:
            assert_equal(n[i].getsparkdefaultaddress()[0], self.group_addr)
            r = n[i].addsparkmultisigaddress(2, keys)
            assert r['complete'] is True and r['address'] == self.group_addr
            n[i].getblockcount()  # still running
        assert_raises_jsonrpc(-4, "other parameters", n[0].addsparkmultisigaddress, 1, keys)
        self.sync_all()

    def fund(self):
        for _ in range(4):
            self.nodes[3].mintspark({self.group_addr: {"amount": 5, "memo": ""}})
        self.mine(211)  # well past the Chaum V2 activation height of 700
        assert self.nodes[0].getblockcount() >= 710
        self.total = self.balances()
        assert_equal(self.total, 20 * COIN)
        # the wallet no longer spends or signs with its Spark addresses on its own
        for spend in (self.nodes[0].spendspark, self.nodes[0].spendsparksplit):
            msg = self.fails(spend, {self.spark3: {"amount": 1, "subtractFee": False}})
            assert "createsparkmultisigspend" in msg, msg
        self.fails(self.nodes[0].signmessagewithsparkaddress, self.group_addr, "message")

    def finish(self, hexstr):
        """Broadcast a complete spend from the outsider, mine it, return nothing."""
        self.nodes[3].sendrawtransaction(hexstr)
        sync_mempools(self.nodes)
        self.mine(1)

    def spend_a(self):
        n = self.nodes
        t_addr = n[3].getnewaddress()
        spark3_before = n[3].getsparkbalance()['availableBalance']
        hexstr = self.new_spend({
            self.spark3: {"amount": 1, "memo": "hi", "subtractFee": False},
            t_addr: {"amount": 2, "subtractFee": False},
        })
        dec = n[1].decodesparkmultisigspend(hexstr)
        assert_equal(dec['nrequired'], 2)
        assert_equal(dec['signers'], [])
        assert_equal(len(dec['inputs']), 1)
        assert_equal(len(dec['transparent_outputs']), 1)
        assert_equal(dec['transparent_outputs'][0]['address'], t_addr)
        assert_equal(dec['transparent_outputs'][0]['amount'], Decimal(2))
        pay = [o for o in dec['outputs'] if o['address'] == self.spark3]
        assert len(pay) == 1 and pay[0]['amount'] == Decimal(1) and pay[0]['memo'] == "hi" and not pay[0]['ismine']
        change = [o for o in dec['outputs'] if o['ismine']]
        assert len(change) == 1 and change[0]['amount'] > 0
        fee = int(dec['fee'] * COIN)
        assert fee > 0

        r = n[0].signsparkmultisigspend(hexstr)
        assert r['complete'] is False
        assert_equal(len(n[1].decodesparkmultisigspend(r['hex'])['signers']), 1)
        r = n[1].signsparkmultisigspend(r['hex'])
        assert r['complete'] is False
        r = n[0].signsparkmultisigspend(r['hex'])
        assert r['complete'] is True
        self.finish(r['hex'])

        assert_equal(n[3].getreceivedbyaddress(t_addr), Decimal(2))
        deadline = time.time() + 60
        while n[3].getsparkbalance()['availableBalance'] != spark3_before + COIN and time.time() < deadline:
            time.sleep(0.5)
        assert_equal(n[3].getsparkbalance()['availableBalance'], spark3_before + COIN)
        self.total = self.balances(self.total - 3 * COIN - fee)  # includes node 2, who never saw the spend

    def spend_b(self):
        n = self.nodes
        spark3_before = n[3].getsparkbalance()['availableBalance']
        hexstr = self.new_spend()
        fee = int(n[2].decodesparkmultisigspend(hexstr)['fee'] * COIN)
        a1 = n[1].signsparkmultisigspend(hexstr)
        a2 = n[2].signsparkmultisigspend(hexstr)
        assert a1['complete'] is False and a2['complete'] is False
        c = n[0].combinesparkmultisigspend([a1['hex'], a2['hex']])
        assert c['complete'] is False
        assert_equal(len(n[0].decodesparkmultisigspend(c['hex'])['signers']), 2)
        b1 = n[1].signsparkmultisigspend(c['hex'])
        b2 = n[2].signsparkmultisigspend(c['hex'])
        assert b1['complete'] is False and b2['complete'] is False
        done = n[0].combinesparkmultisigspend([b1['hex'], b2['hex']])
        assert done['complete'] is True
        self.finish(done['hex'])
        deadline = time.time() + 60
        while n[3].getsparkbalance()['availableBalance'] != spark3_before + COIN and time.time() < deadline:
            time.sleep(0.5)
        assert_equal(n[3].getsparkbalance()['availableBalance'], spark3_before + COIN)
        self.total = self.balances(self.total - COIN - fee)

    def sign_chain(self, hexstr, first, second):
        """Pass a spend along two signers and back, broadcast it and return its fee."""
        n = self.nodes
        fee = int(n[first].decodesparkmultisigspend(hexstr)['fee'] * COIN)
        r = n[first].signsparkmultisigspend(hexstr)
        assert r['complete'] is False
        r = n[second].signsparkmultisigspend(r['hex'])
        assert r['complete'] is False
        r = n[first].signsparkmultisigspend(r['hex'])
        assert r['complete'] is True
        self.finish(r['hex'])
        return fee

    def spend_multi_input(self):
        """No single coin covers the amount, so every signer signs several inputs."""
        n = self.nodes
        hexstr = self.new_spend({self.spark3: {"amount": 9, "subtractFee": False}})
        assert len(n[2].decodesparkmultisigspend(hexstr)['inputs']) > 1
        fee = self.sign_chain(hexstr, 2, 1)
        self.total = self.balances(self.total - 9 * COIN - fee)

    def rejoin(self):
        """A participant that lost its wallet repeats the setup with its key and the others' data."""
        n = self.nodes
        key = dumpprivkey_otac(n[2], self.addrs[2])
        stop_node(n[2], 2)
        os.remove(os.path.join(self.options.tmpdir, "node2", "regtest", "wallet.dat"))
        self.restart(2)
        self.reconnect()
        n = self.nodes
        n[2].importprivkey(key, "", False)
        assert n[2].getsparkdefaultaddress()[0] != self.group_addr
        assert "not a Spark multisig wallet" in self.fails(n[2].createsparkmultisigspend, {self.spark3: {"amount": 1, "subtractFee": False}})

        # the others are set up already and still hand out their data
        d1 = {i: n[i].addsparkmultisigaddress(2, self.keys) for i in GROUP}
        assert d1[0]['complete'] is True and d1[1]['complete'] is True and d1[2]['complete'] is False
        d2 = {i: n[i].addsparkmultisigaddress(2, self.keys, [d1[j]['hex'] for j in GROUP if j != i]) for i in GROUP}
        r = n[2].addsparkmultisigaddress(2, self.keys, [d2[0]['hex'], d2[1]['hex']])
        assert r['complete'] is True
        assert_equal(r['address'], self.group_addr)
        wait_node(2)
        self.restart(2, ['-rescan'])
        self.reconnect()
        n = self.nodes
        n[0].getblockcount()  # the others kept running
        n[1].getblockcount()
        assert_equal(n[2].getsparkdefaultaddress()[0], self.group_addr)
        self.balances(self.total)

        # and its share signs again
        fee = self.sign_chain(self.new_spend(), 2, 0)
        self.total = self.balances(self.total - COIN - fee)

    def locked_wallet(self):
        """Only signing takes the wallet passphrase."""
        n = self.nodes
        n[1].encryptwallet("pass")
        wait_node(1)
        self.restart(1)
        self.reconnect()
        n = self.nodes
        assert_equal(n[1].getsparkdefaultaddress()[0], self.group_addr)

        hexstr = n[1].createsparkmultisigspend({self.spark3: {"amount": 1, "subtractFee": False}})['hex']
        n[1].decodesparkmultisigspend(hexstr)
        assert n[1].combinesparkmultisigspend([hexstr])['complete'] is False
        r = n[1].addsparkmultisigaddress(2, self.keys)
        assert r['complete'] is True and r['address'] == self.group_addr and 'hex' not in r
        assert_raises_jsonrpc(-13, "walletpassphrase", n[1].signsparkmultisigspend, hexstr)

        n[1].walletpassphrase("pass", 600)
        fee = self.sign_chain(hexstr, 1, 0)
        self.total = self.balances(self.total - COIN - fee)

    def misuse(self):
        n = self.nodes

        # a third signer cannot join after two committed
        s = self.new_spend()
        h0 = n[0].signsparkmultisigspend(s)['hex']
        h1 = n[1].signsparkmultisigspend(h0)['hex']  # commits and signs
        assert "already has its signers" in self.fails(n[2].signsparkmultisigspend, h1)

        # a nonce is single-use: node 0 completes, then cannot sign the same pre-signature again
        r = n[0].signsparkmultisigspend(h1)
        assert r['complete'] is True
        assert "no longer holds the nonce" in self.fails(n[0].signsparkmultisigspend, h1)
        # (r['hex'] is never broadcast)

        # a signer restarted between its two passes can no longer sign
        s = self.new_spend()
        h0 = n[0].signsparkmultisigspend(s)['hex']
        h1 = n[1].signsparkmultisigspend(h0)['hex']
        stop_node(n[0], 0)
        self.restart(0)
        self.reconnect()
        n = self.nodes
        assert "no longer holds the nonce" in self.fails(n[0].signsparkmultisigspend, h1)

        # combine of two different spends
        x = self.new_spend()
        y = self.new_spend({self.spark3: {"amount": 2, "subtractFee": False}})
        assert "not copies" in self.fails(n[0].combinesparkmultisigspend, [x, y])

        # a flipped character
        bad = x[:100] + ('0' if x[100] != '0' else '1') + x[101:]
        for fun in (n[1].decodesparkmultisigspend, n[1].signsparkmultisigspend):
            assert "group" in self.fails(fun, bad)

        # not a multisig wallet / outside the group
        for fun, arg in ((n[3].createsparkmultisigspend, {self.spark3: {"amount": 1, "subtractFee": False}}),
                         (n[3].signsparkmultisigspend, x),
                         (n[3].decodesparkmultisigspend, x),
                         (n[3].combinesparkmultisigspend, [x])):
            assert "not a Spark multisig wallet" in self.fails(fun, arg)

        assert_equal(len(n[3].getrawmempool()), 0)

    def run_test(self):
        self.nodes[3].generate(501)
        self.sync_all()
        self.spark3 = self.nodes[3].getsparkdefaultaddress()[0]
        self.competing_setup()
        self.funded_setup_is_rejected()
        self.setup_group()   # A
        self.fund()          # B
        self.spend_a()       # C
        self.spend_b()       # D
        self.spend_multi_input()
        self.misuse()        # E
        self.rejoin()
        self.locked_wallet()


if __name__ == '__main__':
    SparkMultisigTest().main()
