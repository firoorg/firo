#!/usr/bin/env python3
# Copyright (c) 2026 The Firo developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_jsonrpc, start_nodes


class NegativeTxVersionTest(BitcoinTestFramework):
    ACTIVATION_HEIGHT = 300

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = False

    def setup_nodes(self):
        return start_nodes(
            self.num_nodes,
            self.options.tmpdir,
            [["-rejectnegativetxversionheight={}".format(
                self.ACTIVATION_HEIGHT)]])

    def run_test(self):
        node = self.nodes[0]
        utxo = node.listunspent(100)[0]
        inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
        outputs = {
            node.getnewaddress(): utxo["amount"] - Decimal("0.001")}

        raw_tx = node.createrawtransaction(inputs, outputs)
        assert_equal(raw_tx[:8], "01000000")
        raw_negative = "00800000" + raw_tx[8:]
        signed_negative = node.signrawtransaction(raw_negative)
        assert signed_negative["complete"]
        assert_equal(signed_negative["hex"][:8], "0080ffff")
        signed_negative["hex"] = "00800000" + signed_negative["hex"][8:]

        assert_raises_jsonrpc(
            -26, "64: version", node.sendrawtransaction,
            signed_negative["hex"])

        node.generate(self.ACTIVATION_HEIGHT - 1 - node.getblockcount())
        assert_equal(node.getblockcount(), self.ACTIVATION_HEIGHT - 1)
        assert_raises_jsonrpc(
            -26, "16: bad-txns-version", node.sendrawtransaction,
            signed_negative["hex"])

        signed_positive = node.signrawtransaction(raw_tx)
        assert signed_positive["complete"]
        txid = node.sendrawtransaction(signed_positive["hex"])
        block_hash = node.generate(1)[0]
        assert_equal(node.getblockcount(), self.ACTIVATION_HEIGHT)
        assert txid in node.getblock(block_hash)["tx"]


if __name__ == "__main__":
    NegativeTxVersionTest().main()
