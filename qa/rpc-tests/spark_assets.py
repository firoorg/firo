#!/usr/bin/env python3
# Copyright (c) 2026 The Firo developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Functional coverage for Spark asset RPCs on regtest.

SPATS activates at height 1100. Fungible assets are registered at precisions
0, 2, and 8. An NFT is registered, minted once, and transferred.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    JSONRPCException,
    assert_equal,
    assert_raises_message,
    connect_nodes_bi,
    sync_blocks,
    sync_mempools,
)


SPATS_START = 1100


class SparkAssetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        self.nodes = self.setup_nodes()
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        sync_blocks(self.nodes)
        sync_mempools(self.nodes)

    def mine(self, blocks=1):
        self.nodes[0].generate(blocks)
        sync_blocks(self.nodes)
        sync_mempools(self.nodes)

    def sent_category(self, txid, node=0):
        categories = []
        for entry in self.nodes[node].listtransactions("*", 40):
            if entry.get("txid") == txid and "fee" in entry:
                categories.append(entry["category"])
        assert categories, "no sent listtransactions row for %s" % txid
        assert_equal(len(set(categories)), 1)
        return categories[0]

    def asset(self, symbol, node=0):
        return self.nodes[node].getsparkasset(symbol)

    def register(self, symbol, name, precision, max_supply, nft=False, identifier=None):
        payload = {
            "symbol": symbol,
            "name": name,
            "precision": precision,
            "maxSupply": max_supply,
        }
        if nft:
            payload["isNFT"] = True
            payload["identifier"] = identifier
        txid = self.nodes[0].createsparkasset(payload)
        assert_equal(self.sent_category(txid), "spatsregister")
        return txid

    def mint(self, symbol, amount, iota=0):
        info = self.asset(symbol)
        txid = self.nodes[0].mintspats(self.owner, {
            "amount": amount,
            "a": int(info["assetType"]),
            "iota": iota,
            "memo": symbol,
        })
        return txid

    def assert_not_in_mempool(self, txid):
        assert txid not in self.nodes[0].getrawmempool()

    def run_test(self):
        # Spark is active at 100. SPATS is not active until 1100.
        self.mine(400)
        assert self.nodes[0].getblockcount() < SPATS_START

        assert_raises_message(
            JSONRPCException, "not yet active",
            self.nodes[0].createsparkasset,
            {"symbol": "EARLYA", "name": "Early", "maxSupply": 10, "precision": 0})
        assert_raises_message(
            JSONRPCException, "Spats is not activated yet",
            self.nodes[0].mintspats,
            "addr", {"amount": "1", "a": 1, "iota": 0})

        self.owner = self.nodes[0].getsparkdefaultaddress()[0]
        self.peer = self.nodes[1].getnewsparkaddress()[0]
        self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 40)
        self.mine(1)
        for _ in range(18):
            self.nodes[0].mintspark({self.owner: {"amount": 10, "memo": "fee"}})
        for _ in range(2):
            self.nodes[1].mintspark({self.peer: {"amount": 10, "memo": "fee"}})
        sync_mempools(self.nodes)
        self.mine(SPATS_START - self.nodes[0].getblockcount())
        assert self.nodes[0].getblockcount() >= SPATS_START
        assert_equal(self.nodes[0].listsparkassets(), [])

        assert_raises_message(
            JSONRPCException, "precision could be up to 8",
            self.nodes[0].createsparkasset,
            {"symbol": "PRECHI", "name": "Too fine", "maxSupply": 10, "precision": 9})
        assert_raises_message(
            JSONRPCException, "identifier is needed only for NFTs",
            self.nodes[0].createsparkasset,
            {"symbol": "BADIDF", "name": "Bad", "maxSupply": 10, "precision": 0, "identifier": 1})
        assert_raises_message(
            JSONRPCException, "non-zero",
            self.nodes[0].createsparkasset,
            {"symbol": "NFTBAD", "name": "Bad", "maxSupply": 1, "precision": 0,
             "isNFT": True, "identifier": 0})
        assert_raises_message(
            JSONRPCException, "Asset is not registered",
            self.nodes[0].getsparkasset, "NOSUCH")

        self.register("WHOLEU", "Whole units", 0, 1000000000)
        self.register("CENTS2", "Two decimals", 2, 100000)
        self.register("FINE08", "Eight decimals", 8, 100000000)
        self.register("NFTITM", "One item", 0, 1, nft=True, identifier=7)
        self.mine(1)

        listed = self.nodes[0].listsparkassets()
        assert_equal(len(listed), 4)
        by_symbol = {entry["symbol"]: entry for entry in listed}
        assert_equal(by_symbol["WHOLEU"]["kind"], "fungible")
        assert_equal(by_symbol["WHOLEU"]["precision"], 0)
        assert_equal(by_symbol["WHOLEU"]["identifier"], 0)
        assert_equal(by_symbol["WHOLEU"]["maxSupply"], "1000000000")
        assert_equal(by_symbol["WHOLEU"]["balance"], "0")
        assert_equal(by_symbol["WHOLEU"]["isAdmin"], True)
        assert_equal(by_symbol["CENTS2"]["precision"], 2)
        assert_equal(by_symbol["CENTS2"]["maxSupply"], "1000.00")
        assert_equal(by_symbol["CENTS2"]["balance"], "0.00")
        assert_equal(by_symbol["FINE08"]["precision"], 8)
        assert_equal(by_symbol["FINE08"]["maxSupply"], "1.00000000")
        assert_equal(by_symbol["FINE08"]["circulatingSupply"], "0.00000000")
        assert_equal(by_symbol["NFTITM"]["kind"], "nft")
        assert_equal(by_symbol["NFTITM"]["identifier"], 7)
        assert_equal(by_symbol["NFTITM"]["precision"], 0)
        assert_equal(by_symbol["NFTITM"]["maxSupply"], "1")
        assert_equal(self.asset("CENTS2")["name"], "Two decimals")
        assert_equal(self.asset("WHOLEU", node=1)["isAdmin"], False)
        types = [int(by_symbol[name]["assetType"]) for name in ("WHOLEU", "CENTS2", "FINE08", "NFTITM")]
        assert_equal(len(set(types)), 4)

        assert_raises_message(
            JSONRPCException, "Unable to register",
            self.nodes[0].createsparkasset,
            {"symbol": "CENTS2", "name": "Again", "maxSupply": 10, "precision": 2})

        whole_type = int(self.asset("WHOLEU")["assetType"])
        cents_type = int(self.asset("CENTS2")["assetType"])
        fine_type = int(self.asset("FINE08")["assetType"])
        nft_type = int(self.asset("NFTITM")["assetType"])
        assert_equal(self.nodes[0].listunspentspatsmints(cents_type, 0), [])

        assert_raises_message(
            JSONRPCException, "Invalid asset amount",
            self.nodes[0].mintspats, self.owner,
            {"amount": "12.5", "a": whole_type, "iota": 0})
        assert_raises_message(
            JSONRPCException, "Invalid asset amount",
            self.nodes[0].mintspats, self.owner,
            {"amount": "1.555", "a": cents_type, "iota": 0})
        assert_raises_message(
            JSONRPCException, "Invalid asset amount",
            self.nodes[0].mintspats, self.owner,
            {"amount": "0", "a": cents_type, "iota": 0})
        assert_raises_message(
            JSONRPCException, "Invalid asset amount",
            self.nodes[0].mintspats, self.owner,
            {"amount": "0.000000001", "a": fine_type, "iota": 0})
        assert_raises_message(
            JSONRPCException, "Asset is not registered",
            self.nodes[0].mintspats, self.owner,
            {"amount": "1.00", "a": cents_type + 1000000, "iota": 0})
        assert_raises_message(
            JSONRPCException, "subtractFee cannot be taken from a SPATS asset amount",
            self.nodes[0].spendspark,
            {self.peer: {"amount": "0.10", "a": cents_type, "iota": 0, "subtractFee": True}})

        firo_before = self.nodes[0].getsparkbalance()["availableBalance"]
        whole_mint = self.mint("WHOLEU", "1000000000")
        assert_equal(self.sent_category(whole_mint), "spatsmint")
        cents_mint = self.mint("CENTS2", "2.00")
        fine_mint = self.mint("FINE08", "0.00000001")
        nft_mint = self.mint("NFTITM", "1", iota=7)
        assert_equal(self.sent_category(nft_mint), "spatsmint")
        self.mine(1)
        firo_after = self.nodes[0].getsparkbalance()["availableBalance"]
        assert Decimal(firo_after) < Decimal(firo_before)

        assert_equal(self.asset("WHOLEU")["balance"], "1000000000")
        assert_equal(self.asset("WHOLEU")["circulatingSupply"], "1000000000")
        assert_equal(self.asset("CENTS2")["balance"], "2.00")
        assert_equal(self.asset("FINE08")["balance"], "0.00000001")
        assert_equal(self.asset("NFTITM")["balance"], "1")
        assert_equal(self.asset("NFTITM")["kind"], "nft")
        unspent = self.nodes[0].listunspentspatsmints(cents_type, 0)
        assert_equal(len(unspent), 1)
        assert_equal(unspent[0]["amount"], Decimal("0.00000200"))
        assert_equal(len(self.nodes[0].listunspentspatsmints(nft_type, 7)), 1)

        wrong_iota = self.mint("CENTS2", "1.00", iota=1)
        self.assert_not_in_mempool(wrong_iota)
        wrong_nft = self.mint("NFTITM", "1", iota=0)
        self.assert_not_in_mempool(wrong_nft)
        second_nft = self.mint("NFTITM", "1", iota=7)
        self.assert_not_in_mempool(second_nft)
        assert_equal(self.asset("NFTITM")["circulatingSupply"], "1")
        assert_raises_message(
            JSONRPCException, "Spark spend creation failed",
            self.nodes[0].spendspark,
            {"burn": ["1", nft_type, 7]})

        send_txid = self.nodes[0].sendspark({
            self.peer: {"amount": "0.50", "a": cents_type, "iota": 0, "memo": "pay"},
        })
        assert_equal(self.sent_category(send_txid), "spatsspend")
        self.mine(1)
        assert_equal(self.asset("CENTS2")["balance"], "1.50")
        assert_equal(self.asset("CENTS2")["circulatingSupply"], "2.00")
        assert_equal(self.asset("CENTS2", node=1)["balance"], "0.50")
        assert_equal(len(self.nodes[1].listunspentspatsmints(cents_type, 0)), 1)

        burn_txid = self.nodes[0].spendspark({"burn": ["0.25", cents_type, 0]})
        assert_equal(self.sent_category(burn_txid), "spatsburn")
        self.mine(1)
        assert_equal(self.asset("CENTS2")["balance"], "1.25")
        assert_equal(self.asset("CENTS2")["circulatingSupply"], "1.75")
        assert_equal(self.asset("CENTS2", node=1)["balance"], "0.50")
        assert_equal(self.asset("WHOLEU")["balance"], "1000000000")
        assert_equal(self.asset("FINE08")["balance"], "0.00000001")

        name_txid = self.nodes[0].modifysparkassetname({"symbol": "WHOLEU", "name": "Renamed"})
        assert_equal(self.sent_category(name_txid), "spatsmodify")
        desc_txid = self.nodes[0].modifysparkassetdescription(
            {"symbol": "WHOLEU", "description": "Updated text"})
        assert_equal(self.sent_category(desc_txid), "spatsmodify")
        meta_txid = self.nodes[0].modifysparkassetmetadata(
            {"symbol": "WHOLEU", "metadata": "{\"k\":1}"})
        assert_equal(self.sent_category(meta_txid), "spatsmodify")
        self.mine(1)
        renamed = self.asset("WHOLEU")
        assert_equal(renamed["name"], "Renamed")
        assert_equal(renamed["description"], "Updated text")
        assert_equal(renamed["metadata"], "{\"k\":1}")

        receive = self.nodes[1].sparkassetreceive("NFTITM")
        transfer_txid = self.nodes[0].sparkassettransfer({"symbol": "NFTITM", "receive": receive})
        assert_equal(self.sent_category(transfer_txid), "spatstransfer")
        self.mine(1)
        assert_equal(self.asset("NFTITM")["isAdmin"], False)
        assert_equal(self.asset("NFTITM", node=1)["isAdmin"], True)
        assert_equal(self.asset("NFTITM")["balance"], "1")
        assert_raises_message(
            JSONRPCException, "not mine",
            self.nodes[0].modifysparkassetname,
            {"symbol": "NFTITM", "name": "Stolen"})

        peer_name = self.nodes[1].modifysparkassetname({"symbol": "NFTITM", "name": "Peer item"})
        assert_equal(self.sent_category(peer_name, node=1), "spatsmodify")
        self.mine(1)
        assert_equal(self.asset("NFTITM")["name"], "Peer item")
        assert_equal(self.asset("NFTITM", node=1)["isAdmin"], True)
        assert_equal(self.asset("CENTS2")["balance"], "1.25")


if __name__ == '__main__':
    SparkAssetTest().main()
