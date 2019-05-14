#!/usr/bin/env python3


from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


class MempoolDoubleSpendOneBlock(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = False

    def setup_network(self):
        # Just need one node for this test
        args = ["-checkmempool", "-debug=mempool"]
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, args))
        self.is_network_split = False

    def run_test(self):
        node0_address = self.nodes[0].getnewaddress()
        self.nodes[0].generate(200)
        b_count = self.nodes[0].getblockcount()
        b1 = self.nodes[0].getblockhash(b_count - 100)
        coinbase_txids1 = self.nodes[0].getblock(b1)['tx'][0]
        spends1_raw = create_tx(self.nodes[0], coinbase_txids1, node0_address, 1)
        spend1_id = self.nodes[0].sendrawtransaction(spends1_raw)
        spend2_id = self.nodes[0].sendrawtransaction(spends1_raw)
        assert_equal(len(self.nodes[0].getrawmempool()), 1)
        blocks = []
        blocks.extend(self.nodes[0].generate(1))
        # mempool should not be empty, one txn should be unconfirmed
        assert_equal(len(self.nodes[0].getrawmempool()), 0)


        print('check double regular spend in multiple spend')
        b = self.nodes[0].getblockhash(b_count-101)
        coinbase_txids2 = self.nodes[0].getblock(b)['tx'][0]
        spends2_raw = try_create_tx_with_two_coinbase(self.nodes[0], coinbase_txids1, coinbase_txids2,  node0_address, node0_address, 1, 1)
        spends2_id = self.nodes[0].sendrawtransaction(spends2_raw)
        assert_equal(len(self.nodes[0].getrawmempool()), 0)
        blocks.extend(self.nodes[0].generate(1))
        # mempool should not be empty, one txn should be unconfirmed
        assert_equal(len(self.nodes[0].getrawmempool()), 0)




if __name__ == '__main__':
    MempoolDoubleSpendOneBlock().main()
