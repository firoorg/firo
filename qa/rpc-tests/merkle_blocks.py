#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test merkleblock fetch/validation
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class MerkleBlockTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 4

    def setup_network(self):
        self.nodes = []
        # Nodes 0/1 are "wallet" nodes
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug"]))
        # Nodes 2/3 are used for testing
        self.nodes.append(start_node(2, self.options.tmpdir, ["-debug", "-txindex=0"]))
        self.nodes.append(start_node(3, self.options.tmpdir, ["-debug", "-txindex=1"]))
        connect_nodes(self.nodes[0], 1)
        connect_nodes(self.nodes[0], 2)
        connect_nodes(self.nodes[0], 3)

        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        print("Mining blocks...")
        self.nodes[0].generate(105)
        self.sync_all()

        chain_height = self.nodes[1].getblockcount()
        assert_equal(chain_height, 105)
        assert_equal(self.nodes[1].getbalance(), 0)
        assert_equal(self.nodes[2].getbalance(), 0)
        assert_raises_message(JSONRPCException, "requires -txindex", self.nodes[2].getCVE17144amount)

        node0utxos = self.nodes[0].listunspent(1)
        txin1 = node0utxos.pop()
        tx1 = self.nodes[0].createrawtransaction([txin1], {self.nodes[1].getnewaddress(): txin1["amount"] - Decimal("0.01")})
        txid1 = self.nodes[0].sendrawtransaction(self.nodes[0].signrawtransaction(tx1)["hex"])
        txin2 = node0utxos.pop()
        tx2 = self.nodes[0].createrawtransaction([txin2], {self.nodes[1].getnewaddress(): txin2["amount"] - Decimal("0.01")})
        txid2 = self.nodes[0].sendrawtransaction(self.nodes[0].signrawtransaction(tx2)["hex"])
        assert_raises(JSONRPCException, self.nodes[0].gettxoutproof, [txid1])

        self.nodes[0].generate(1)
        blockhash = self.nodes[0].getblockhash(chain_height + 1)
        self.sync_all()

        txlist = []
        blocktxn = self.nodes[0].getblock(blockhash, True)["tx"]
        txlist.append(blocktxn[1])
        txlist.append(blocktxn[2])

        assert_raises(JSONRPCException, self.nodes[2].gettxoutproof, [txid1])
        assert_raises(JSONRPCException, self.nodes[2].gettxoutproof, [txid1, txid2])
        assert_equal(self.nodes[2].verifytxoutproof(self.nodes[2].gettxoutproof([txid1, txid2], blockhash)), txlist)
        assert_equal(self.nodes[3].verifytxoutproof(self.nodes[3].gettxoutproof([txid1, txid2])), txlist)

        txin_spent = self.nodes[1].listunspent(1).pop()
        tx3 = self.nodes[1].createrawtransaction([txin_spent], {self.nodes[0].getnewaddress(): txin_spent["amount"] - Decimal("0.01")})
        self.nodes[0].sendrawtransaction(self.nodes[1].signrawtransaction(tx3)["hex"])
        self.nodes[0].generate(1)
        self.sync_all()

        txid_spent = txin_spent["txid"]
        txid_unspent = txid1 if txin_spent["txid"] != txid1 else txid2

        # Without -txindex, the block hash is required for spent and unspent transactions.
        assert_raises(JSONRPCException, self.nodes[2].gettxoutproof, [txid_spent])
        assert_raises(JSONRPCException, self.nodes[2].gettxoutproof, [txid_unspent])
        assert_equal(self.nodes[2].verifytxoutproof(self.nodes[2].gettxoutproof([txid_spent], blockhash)), [txid_spent])
        # With -txindex, the block is found for a fully-spent transaction.
        assert_equal(self.nodes[3].verifytxoutproof(self.nodes[3].gettxoutproof([txid_spent])), [txid_spent])

if __name__ == '__main__':
    MerkleBlockTest().main()
