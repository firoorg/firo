#!/usr/bin/env python3
# Copyright (c) 2026 The Firo developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal

from test_framework.mininode import CTransaction, CTxOut, FromHex, ToHex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal, assert_raises_jsonrpc, bitcoind_processes,
    connect_nodes_bi, start_node, start_nodes,
)


class ConsolidationTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.node_args = ["-paytxfee=0.00001"]

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 [self.node_args, self.node_args])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        node = self.nodes[0]
        node.generate(101)
        self.sync_all()
        address = node.getnewaddress("payouts")
        other = node.getnewaddress("other funds")
        dust = node.getnewaddress("unaffordable")
        watched = self.nodes[1].getnewaddress()
        node.importaddress(watched, "watch only", False)

        # Real UTXOs: the largest 13 outputs can pay their fee, but all 50 cannot.
        coin = node.listunspent()[0]
        change = coin["amount"] - Decimal("2.00012098")
        funding = FromHex(CTransaction(), node.createrawtransaction(
            [{"txid": coin["txid"], "vout": coin["vout"]}], {other: change}))
        script = bytes.fromhex(node.validateaddress(address)["scriptPubKey"])
        funding.vout += [CTxOut(value, script) for value in [1000, 1000] + [1] * 48]
        dust_script = bytes.fromhex(node.validateaddress(dust)["scriptPubKey"])
        funding.vout += [CTxOut(1, dust_script) for _ in range(50)]
        watch_script = bytes.fromhex(node.validateaddress(watched)["scriptPubKey"])
        funding.vout += [CTxOut(100000000, watch_script) for _ in range(2)]
        signed = node.signrawtransaction(ToHex(funding))
        assert_equal(signed["complete"], True)
        funding_id = node.sendrawtransaction(signed["hex"])
        node.generate(1)
        self.sync_all()

        assert_raises_jsonrpc(-1, "consolidateaddress", node.consolidateaddress)
        assert_raises_jsonrpc(-3, None, node.consolidateaddress, 1)
        assert_raises_jsonrpc(-3, None, node.consolidateaddress, address, "false")
        assert_raises_jsonrpc(-5, "Invalid transparent address", node.consolidateaddress, "invalid")
        assert_raises_jsonrpc(-4, "fewer than two", node.consolidateaddress, other)
        assert_raises_jsonrpc(-4, "fewer than two", node.consolidateaddress, watched)
        assert_raises_jsonrpc(-4, "too small to pay the fee", node.consolidateaddress, dust)

        inputs = node.listunspent(1, 9999999, [address])
        locked = [{"txid": item["txid"], "vout": item["vout"]} for item in inputs]
        node.lockunspent(False, locked)
        assert_raises_jsonrpc(-4, "fewer than two", node.consolidateaddress, address)
        node.lockunspent(True, locked)

        # Preview must work while encrypted and locked, without consuming a key,
        # altering transaction history, marking inputs spent, or entering mempool.
        node.encryptwallet("consolidation test")
        bitcoind_processes[0].wait()
        node = self.nodes[0] = start_node(0, self.options.tmpdir, self.node_args)
        connect_nodes_bi(self.nodes, 0, 1)
        self.sync_all()
        info = node.getwalletinfo()
        unspent = node.listunspent()
        mempool = node.getrawmempool()
        preview = node.consolidateaddress(address)
        assert_equal(preview, node.consolidateaddress(address, True))
        assert_equal(preview, node.consolidateaddress(address=address, dryrun=True))
        assert_equal(preview["address"], address)
        assert_equal(preview["dryrun"], True)
        assert_equal(preview["eligible_outputs"], 50)
        assert_equal(preview["inputs"], 13)
        assert_equal(preview["size_limited"], False)
        assert_equal(preview["amount"] + preview["fee"], Decimal("0.00002011"))
        assert_equal(node.getwalletinfo(), info)
        assert_equal(node.listunspent(), unspent)
        assert_equal(node.getrawmempool(), mempool)
        assert_raises_jsonrpc(-13, "walletpassphrase", node.consolidateaddress, address, False)

        node.walletpassphrase("consolidation test", 600)
        result = node.consolidateaddress(address, False)
        assert_equal(result["dryrun"], False)
        assert_equal(result["eligible_outputs"], preview["eligible_outputs"])
        assert_equal(result["inputs"], preview["inputs"])
        assert_equal(result["size"], preview["size"])
        assert_equal(result["size_limited"], preview["size_limited"])
        assert_equal(result["fee"], preview["fee"])
        assert_equal(result["remaining_outputs"], 37)
        assert result["txid"] in node.getrawmempool()
        transaction = node.getrawtransaction(result["txid"], True)
        assert_equal(len(transaction["vin"]), 13)
        assert_equal(len(transaction["vout"]), 1)
        assert_equal(transaction["vout"][0]["scriptPubKey"]["addresses"], [address])
        assert_equal(transaction["vout"][0]["value"], result["amount"])
        assert transaction["size"] <= result["size"]
        eligible = {(item["txid"], item["vout"]) for item in inputs}
        assert all((item["txid"], item["vout"]) in eligible for item in transaction["vin"])
        assert_equal(len(node.listunspent(1, 9999999, [other])), 1)
        assert_raises_jsonrpc(-4, "too small to pay the fee", node.consolidateaddress, address)

        node.generate(1)
        self.sync_all()
        assert result["txid"] not in node.getrawmempool()
        assert_equal(node.gettransaction(result["txid"])["confirmations"], 1)
        confirmed = node.listunspent(1, 9999999, [address])
        assert_equal(len(confirmed), 38)
        assert any(item["txid"] == result["txid"] for item in confirmed)
        assert all(item["txid"] in (funding_id, result["txid"]) for item in confirmed)
        assert_equal(len(node.listunspent(1, 9999999, [other])), 1)


if __name__ == '__main__':
    ConsolidationTest().main()
