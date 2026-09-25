#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests for the sweepbip47addresses RPC."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class Bip47Sweep(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = False
        self.num_nodes = 1

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)

    def bip47_address(self, node):
        """The notification address of the wallet's single receiving account."""
        entries = node.listbip47addresses()
        assert_equal(len(entries), 1)
        assert_equal(entries[0]["type"], "notification")
        return entries[0]["address"]

    def unspent(self, node, address):
        """The wallet's spendable outputs on address, smallest first.

        Ordinary coin selection is free to spend these, so nothing about their number or
        value can be assumed; the expected sweep is always derived from this list.
        """
        return sorted(node.listunspent(1, 9999999, [address]), key=lambda u: u["amount"])

    def fund(self, node, address, amount):
        node.sendtoaddress(address, amount)
        node.generate(1)

    def run_test(self):
        node = self.nodes[0]
        node.generate(300)

        # A wallet with no BIP47 accounts at all has nothing to sweep.
        assert_raises_jsonrpc(-4, "This wallet has no BIP47 addresses",
                              node.sweepbip47addresses, node.getnewaddress())

        node.createrapaddress("alice")
        bip47addr = self.bip47_address(node)

        # And neither does one whose addresses have never been paid.
        assert_raises_jsonrpc(-6, "No spendable funds on BIP47 addresses",
                              node.sweepbip47addresses, node.getnewaddress())

        # A destination that is neither a transparent nor a Spark address is rejected.
        assert_raises_jsonrpc(-5, "Invalid Firo or Spark address",
                              node.sweepbip47addresses, "notanaddress")

        # ---- sweeping to a transparent address ----
        self.fund(node, bip47addr, 5)
        self.fund(node, bip47addr, 3)

        held = self.unspent(node, bip47addr)
        expected = sum(u["amount"] for u in held)
        assert(expected > 0)

        dest = node.getnewaddress()
        result = node.sweepbip47addresses(dest)

        assert_equal(result["destination"], dest)
        assert_equal(result["destinationtype"], "transparent")
        assert_equal(result["amount"], expected)
        assert_equal(result["inputs"], len(held))
        assert_equal(len(result["txids"]), 1)
        assert("skippedlocked" not in result)

        node.generate(1)
        # The whole balance moves across; the fee comes out of the swept amount.
        assert_equal(node.getreceivedbyaddress(dest), result["amount"] - result["fee"])

        # Everything is gone, so a second sweep has nothing left to do.
        assert_raises_jsonrpc(-6, "No spendable funds on BIP47 addresses",
                              node.sweepbip47addresses, node.getnewaddress())

        # ---- locked outputs ----
        # The wallet locks the output of every notification transaction it receives, so
        # locked outputs stay put unless the caller asks for them.
        self.fund(node, bip47addr, 4)
        self.fund(node, bip47addr, 6)

        held = self.unspent(node, bip47addr)
        assert(len(held) >= 2)
        to_lock = [{"txid": held[0]["txid"], "vout": held[0]["vout"]}]
        locked_amount = held[0]["amount"]
        expected = sum(u["amount"] for u in held[1:])
        assert_equal(node.lockunspent(False, to_lock), True)

        dest = node.getnewaddress()
        result = node.sweepbip47addresses(dest)
        assert_equal(result["amount"], expected)
        assert_equal(result["inputs"], len(held) - 1)
        assert_equal(result["skippedlocked"]["count"], 1)
        assert_equal(result["skippedlocked"]["amount"], locked_amount)
        # The skipped output is still locked.
        assert_equal(len(node.listlockunspent()), 1)
        node.generate(1)

        # Asking for them explicitly spends them.
        dest = node.getnewaddress()
        result = node.sweepbip47addresses(dest, True)
        assert_equal(result["amount"], locked_amount)
        assert_equal(result["inputs"], 1)
        assert("skippedlocked" not in result)
        node.generate(1)
        assert_equal(node.getreceivedbyaddress(dest), result["amount"] - result["fee"])
        assert_equal(len(node.listlockunspent()), 0)

        # ---- an amount too small to pay its own fee ----
        # The whole balance is always sent, so the fee has to come out of it. CTxOut::IsDust()
        # is disabled in Firo, so CreateTransaction will happily build an output at or below
        # zero here; the sweep has to refuse before anything is committed.
        self.fund(node, bip47addr, Decimal("0.00001"))

        held = self.unspent(node, bip47addr)
        assert_equal(len(held), 1)
        assert_equal(held[0]["amount"], Decimal("0.00001"))
        to_lock = [{"txid": held[0]["txid"], "vout": held[0]["vout"]}]
        assert_equal(node.lockunspent(False, to_lock), True)

        # include_locked lifts the lock to build the sweep; a failure must put it back.
        assert_raises_jsonrpc(-6, "too small to pay the transaction fee",
                              node.sweepbip47addresses, node.getnewaddress(), True)
        assert_equal(len(node.listlockunspent()), 1)

        assert_equal(node.lockunspent(True, to_lock), True)

        # ---- sweeping into Spark ----
        self.fund(node, bip47addr, 7)

        held = self.unspent(node, bip47addr)
        expected = sum(u["amount"] for u in held)
        spark_before = node.getsparkbalance()["fullBalance"]
        spark_addr = node.getnewsparkaddress()[0]

        result = node.sweepbip47addresses(spark_addr)
        assert_equal(result["destination"], spark_addr)
        assert_equal(result["destinationtype"], "spark")
        assert_equal(result["amount"], expected)
        assert_equal(result["inputs"], len(held))
        assert_equal(len(result["txids"]), 1)

        node.generate(2)
        minted = node.getsparkbalance()["fullBalance"] - spark_before
        assert_equal(minted, int((result["amount"] - result["fee"]) * Decimal("100000000")))

        # The BIP47 addresses are empty again.
        assert_raises_jsonrpc(-6, "No spendable funds on BIP47 addresses",
                              node.sweepbip47addresses, node.getnewaddress())


if __name__ == '__main__':
    Bip47Sweep().main()
