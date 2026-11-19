#!/usr/bin/env python3
"""Spark coins with a point at infinity are not accepted to the mempool.

The point at infinity has many byte encodings that compare equal but hash
differently, so such coins must not be relayed or mined.
"""
from decimal import Decimal

from test_framework.mininode import COIN, CTransaction, FromHex, ToHex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import JSONRPCException, assert_equal, assert_raises_message

OP_SPARKMINT = 0xd1
POINT_SIZE = 34
S_OFFSET = 2  # script: OP_SPARKMINT, coin type, S, K, C, ...
K_OFFSET = S_OFFSET + POINT_SIZE
INFINITY = bytes(33) + b"\x07"  # any non-zero last byte marks infinity


class SparkMintInfinityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        node.generate(801)  # past Spark V2 activation on regtest

        # The value proof of a mint covers only C, so S and K of an honest
        # mint can be replaced without invalidating it.
        mint_txid = node.mintspark({node.getnewsparkaddress()[0]: {"amount": 1, "memo": ""}})[0]
        node.generate(1)
        mint = FromHex(CTransaction(), node.getrawtransaction(mint_txid))
        out = next(o for o in mint.vout if o.scriptPubKey[0] == OP_SPARKMINT)

        for offset in (S_OFFSET, K_OFFSET):
            script = bytearray(out.scriptPubKey)
            script[offset:offset + POINT_SIZE] = INFINITY
            assert_raises_message(JSONRPCException, "spark-coin-infinity",
                                  node.sendrawtransaction, self.mint_tx(out.nValue, bytes(script)))

        node.mintspark({node.getnewsparkaddress()[0]: {"amount": 1, "memo": ""}})
        node.generate(1)
        assert_equal(node.getrawmempool(), [])

    def mint_tx(self, value, script):
        node = self.nodes[0]
        utxo = next(u for u in node.listunspent() if u["amount"] > 2)
        change = utxo["amount"] - Decimal(value) / COIN - Decimal("0.001")
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            {node.getnewaddress(): Decimal(value) / COIN, node.getnewaddress(): change})
        tx = FromHex(CTransaction(), raw)
        next(o for o in tx.vout if o.nValue == value).scriptPubKey = script
        return node.signrawtransaction(ToHex(tx))["hex"]


if __name__ == '__main__':
    SparkMintInfinityTest().main()
