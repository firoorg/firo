#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_message, JSONRPCException

class LelantusMintTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False
        self.args = ["-dandelion=0"]

    def run_test(self):
        activation_block = 1000

        self.nodes[0].generate(200)
        assert_raises_message(
            JSONRPCException,
            "Lelantus is not activated yet",
            self.nodes[0].mintlelantus, 1)

        self.nodes[0].generate(activation_block - self.nodes[0].getblockcount())

        mints = [1, 1.0, 2, 10]
        for m in mints:
            self.nodes[0].mintlelantus(m)

        # self.sync_all()
        self.nodes[0].generate(10)
        # self.sync_all()

        utxos = self.nodes[0].listunspentlelantusmints()
        retrieved_amounts = list(map(lambda u: int(u['amount']), utxos))
        retrieved_amounts.sort()

        assert_equal(mints, retrieved_amounts)

if __name__ == '__main__':
    LelantusMintTest().main()