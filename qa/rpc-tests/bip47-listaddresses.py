#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests for the listbip47addresses RPC."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class Bip47ListAddresses(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)

    def run_test(self):
        node = self.nodes[0]

        assert_equal(node.listbip47addresses(), [])

        labels = ["alice", "bob", "carol"]
        pcodes = [node.createrapaddress(label) for label in labels]

        entries = node.listbip47addresses()
        # Without any payment channel a receiving account only exposes its notification address.
        assert_equal(len(entries), len(pcodes))

        notification_addrs = set()
        for label, pcode, entry in zip(labels, pcodes, entries):
            assert_equal(entry["purpose"], "receive")
            assert_equal(entry["type"], "notification")
            assert_equal(entry["label"], label)
            assert_equal(entry["myrapaddress"], pcode)
            assert_equal(entry["ismine"], True)
            # Notification addresses are not payment addresses and carry no channel index.
            assert("index" not in entry)
            assert("used" not in entry)
            notification_addrs.add(entry["address"])

        assert_equal(len(notification_addrs), len(pcodes))

        # The notification address is the one derived from the payment code itself.
        for pcode, entry in zip(pcodes, entries):
            assert_equal(entry["address"], node.listrapaddresses()[pcodes.index(pcode)]["NotificationAddr"])

        # Filtering by a payment code restricts the listing to that account.
        for label, pcode in zip(labels, pcodes):
            filtered = node.listbip47addresses(pcode)
            assert_equal(len(filtered), 1)
            assert_equal(filtered[0]["label"], label)
            assert_equal(filtered[0]["myrapaddress"], pcode)

        # An empty filter is the same as no filter at all.
        assert_equal(node.listbip47addresses(""), entries)

        # Notification addresses are not part of the unused lookahead window, so dropping
        # unused addresses leaves them in place.
        assert_equal(node.listbip47addresses("", False), entries)

        # A payment code this wallet does not know about yields nothing.
        unknown = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA"
        assert_equal(node.listbip47addresses(unknown), [])

        # A malformed payment code is rejected.
        assert_raises_jsonrpc(-5, "Invalid RAP address", node.listbip47addresses, "notapaymentcode")

        # The listing survives a restart, since the accounts are read back from the wallet.
        stop_node(self.nodes[0], 0)
        self.nodes[0] = start_node(0, self.options.tmpdir)
        assert_equal(self.nodes[0].listbip47addresses(), entries)


if __name__ == '__main__':
    Bip47ListAddresses().main()
