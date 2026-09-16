#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import os
import urllib.parse

class AbandonConflictTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = False

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug","-logtimemicros","-minrelaytxfee=0.00001"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug","-logtimemicros"]))
        connect_nodes(self.nodes[0], 1)

    def run_test(self):
        self.nodes[1].generate(100)
        sync_blocks(self.nodes)
        balance = self.nodes[0].getbalance()
        txA = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), Decimal("10"))
        txB = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), Decimal("10"))
        txC = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), Decimal("10"))
        sync_mempools(self.nodes)
        self.nodes[1].generate(1)

        sync_blocks(self.nodes)
        newbalance = self.nodes[0].getbalance()
        assert(balance - newbalance < Decimal("0.001")) #no more than fees lost
        balance = newbalance

        url = urllib.parse.urlparse(self.nodes[1].url)
        self.nodes[0].disconnectnode(url.hostname+":"+str(p2p_port(1)))

        # Identify the 10btc outputs
        nA = next(i for i, vout in enumerate(self.nodes[0].getrawtransaction(txA, 1)["vout"]) if vout["value"] == Decimal("10"))
        nB = next(i for i, vout in enumerate(self.nodes[0].getrawtransaction(txB, 1)["vout"]) if vout["value"] == Decimal("10"))
        nC = next(i for i, vout in enumerate(self.nodes[0].getrawtransaction(txC, 1)["vout"]) if vout["value"] == Decimal("10"))

        inputs =[]
        # spend 10btc outputs from txA and txB
        inputs.append({"txid":txA, "vout":nA})
        inputs.append({"txid":txB, "vout":nB})
        outputs = {}

        outputs[self.nodes[0].getnewaddress()] = Decimal("14.99998")
        outputs[self.nodes[1].getnewaddress()] = Decimal("5")
        signed = self.nodes[0].signrawtransaction(self.nodes[0].createrawtransaction(inputs, outputs))
        txAB1 = self.nodes[0].sendrawtransaction(signed["hex"])

        # Identify the 14.99998btc output
        nAB = next(i for i, vout in enumerate(self.nodes[0].getrawtransaction(txAB1, 1)["vout"]) if vout["value"] == Decimal("14.99998"))

        #Create a child tx spending AB1 and C
        inputs = []
        inputs.append({"txid":txAB1, "vout":nAB})
        inputs.append({"txid":txC, "vout":nC})
        outputs = {}
        outputs[self.nodes[0].getnewaddress()] = Decimal("24.9996")
        signed2 = self.nodes[0].signrawtransaction(self.nodes[0].createrawtransaction(inputs, outputs))
        txABC2 = self.nodes[0].sendrawtransaction(signed2["hex"])

        # In mempool txs from self should increase balance from change
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance - Decimal("30") + Decimal("24.9996"))
        balance = newbalance

        # Discard the persisted mempool and disable wallet reacceptance.
        stop_node(self.nodes[0],0)
        os.remove(log_filename(self.options.tmpdir, 0, "mempool.dat"))
        self.nodes[0]=start_node(0, self.options.tmpdir, ["-debug","-logtimemicros","-walletbroadcast=0"])

        # Verify txs no longer in mempool
        assert_equal(len(self.nodes[0].getrawmempool()), 0)

        # Not in mempool txs from self should only reduce balance
        # inputs are still spent, but change not received
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance - Decimal("24.9996"))
        # Unconfirmed received funds that are not in mempool, also shouldn't show
        # up in unconfirmed balance
        unconfbalance = self.nodes[0].getunconfirmedbalance() + self.nodes[0].getbalance()
        assert_equal(unconfbalance, newbalance)
        # Also shouldn't show up in listunspent
        assert(not txABC2 in [utxo["txid"] for utxo in self.nodes[0].listunspent(0)])
        balance = newbalance

        # Abandon original transaction and verify inputs are available again
        # including that the child tx was also abandoned
        self.nodes[0].abandontransaction(txAB1)
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance + Decimal("30"))
        balance = newbalance

        # Verify that even with a low min relay fee, the tx is not reaccepted from wallet on startup once abandoned
        stop_node(self.nodes[0],0)
        self.nodes[0]=start_node(0, self.options.tmpdir, ["-debug","-logtimemicros","-minrelaytxfee=0.00001"])
        assert_equal(len(self.nodes[0].getrawmempool()), 0)
        assert_equal(self.nodes[0].getbalance(), balance)

        # But if its received again then it is unabandoned
        # And since now in mempool, the change is available
        # But its child tx remains abandoned
        self.nodes[0].sendrawtransaction(signed["hex"])
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance - Decimal("20") + Decimal("14.99998"))
        balance = newbalance

        # Send child tx again so its unabandoned
        self.nodes[0].sendrawtransaction(signed2["hex"])
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance - Decimal("10") - Decimal("14.99998") + Decimal("24.9996"))
        balance = newbalance

        # Remove from the mempool the same way again.
        stop_node(self.nodes[0],0)
        os.remove(log_filename(self.options.tmpdir, 0, "mempool.dat"))
        self.nodes[0]=start_node(0, self.options.tmpdir, ["-debug","-logtimemicros","-walletbroadcast=0"])
        assert_equal(len(self.nodes[0].getrawmempool()), 0)
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance - Decimal("24.9996"))
        balance = newbalance

        # Create a double spend of AB1 by spending again from only A's 10 output
        # Mine double spend from node 1
        inputs =[]
        inputs.append({"txid":txA, "vout":nA})
        outputs = {}
        outputs[self.nodes[1].getnewaddress()] = Decimal("9.9999")
        tx = self.nodes[0].createrawtransaction(inputs, outputs)
        signed = self.nodes[0].signrawtransaction(tx)
        self.nodes[1].sendrawtransaction(signed["hex"])
        self.nodes[1].generate(1)

        connect_nodes(self.nodes[0], 1)
        sync_blocks(self.nodes)

        # Verify that B and C's 10 BTC outputs are available for spending again because AB1 is now conflicted
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance + Decimal("20"))
        balance = newbalance

        # Invalidate the block with the double spend. AB1 and its child are no longer
        # conflicted, so B's and C's 10 BTC outputs are spent by them again.
        conflict_block = self.nodes[0].getbestblockhash()
        self.nodes[0].invalidateblock(conflict_block)
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance - Decimal("20"))

        # Reconnecting the same conflict must release both outputs again.
        self.nodes[0].reconsiderblock(conflict_block)
        assert_equal(self.nodes[0].getbalance(), balance)

if __name__ == '__main__':
    AbandonConflictTest().main()
