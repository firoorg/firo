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
        b = [self.nodes[0].getblockhash(n) for n in range(b_count-1, b_count)]
        coinbase_txids = [self.nodes[0].getblock(h)['tx'][0] for h in b]
        spends1_raw = [create_tx(self.nodes[0], txid, node0_address, 1) for txid in coinbase_txids]
        spends1_id = [self.nodes[0].sendrawtransaction(tx) for tx in spends1_raw]
        spends2_id = [self.nodes[0].sendrawtransaction(tx) for tx in spends1_raw]

        blocks = []
        blocks.extend(self.nodes[0].generate(1))

        # mempool should not be empty, one txn should be unconfirmed
        assert_equal(len(self.nodes[0].getrawmempool()), 1)


if __name__ == '__main__':
    MempoolDoubleSpendOneBlock().main()
