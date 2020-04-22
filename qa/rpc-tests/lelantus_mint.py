#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_message, JSONRPCException

class LelantusMintTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = False

    def run_test(self):
        activation_block = 1000

        self.nodes[0].generate(200)
        assert_raises_message(
            JSONRPCException,
            "Lelantus is not activated yet",
            self.nodes[0].mintlelantus, 1)

        self.nodes[0].generate(activation_block - self.nodes[0].getblockcount())

        amounts = [1, 1.1, 2, 10]
        for m in amounts:
            self.nodes[0].mintlelantus(m)

        self.nodes[0].generate(10)

        # get all mints and utxos
        mints = self.verify_listlelantusmints(amounts)
        self.verify_listunspentlelantusmints(amounts)
        assert_equal([False, False, False, False], list(map(lambda m : m["isUsed"], mints)))

        # state modification test
        # mark two coins as used
        self.nodes[0].setlelantusmintstatus(mints[2]["serialNumber"], True)
        self.nodes[0].setlelantusmintstatus(mints[3]["serialNumber"], True)

        mints = self.verify_listlelantusmints(amounts)
        self.verify_listunspentlelantusmints([1, 1.1])
        assert_equal([False, False, True, True], list(map(lambda m : m["isUsed"], mints)))

        # set a coin as unused
        self.nodes[0].setlelantusmintstatus(mints[3]["serialNumber"], False)
        mints = self.verify_listlelantusmints(amounts)
        self.verify_listunspentlelantusmints([1, 1.1, 10])
        assert_equal([False, False, True, False], list(map(lambda m : m["isUsed"], mints)))

        # reset coins state
        self.nodes[0].resetlelantusmint()
        mints = self.verify_listlelantusmints(amounts)
        self.verify_listunspentlelantusmints(amounts)
        assert_equal([False, False, False, False], list(map(lambda m : m["isUsed"], mints)))

    def verify_listlelantusmints(self, expected_amounts, *args):
        mints = self.nodes[0].listlelantusmints(*args)
        mints = sorted(mints, key = lambda u: u['amount'])

        assert_equal(
            sorted(expected_amounts),
            list(map(lambda u: u['amount'] / 1e8, mints)))

        return mints

    def verify_listunspentlelantusmints(self, expected_amounts, *args):
        utxos = self.nodes[0].listunspentlelantusmints(*args)
        utxos = sorted(utxos, key = lambda u: float(u['amount']))

        assert_equal(
            sorted(expected_amounts),
            list(map(lambda u: float(u['amount']), utxos)))

        return utxos

if __name__ == '__main__':
    LelantusMintTest().main()