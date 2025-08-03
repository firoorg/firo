#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_message, JSONRPCException

class LelantusMintTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = False

    def run_test(self):
        # generate coins
        amounts = [1, 1.1, 2, 10]

        # 10 confirmations
        self.nodes[0].mintlelantus(amounts[0])
        self.nodes[0].mintlelantus(amounts[1])
        self.nodes[0].generate(5)

        # 5 confirmations
        self.nodes[0].mintlelantus(amounts[2])
        self.nodes[0].mintlelantus(amounts[3])
        self.nodes[0].generate(5)

        # get all mints and utxos
        mints = self.verify_listlelantusmints(amounts)
        self.verify_listunspentlelantusmints(amounts)
        self.verify_listunspentlelantusmints([], 1000) # [1000, 9999999]
        self.verify_listunspentlelantusmints([2, 10], 1, 5) # [1, 5]
        self.verify_listunspentlelantusmints([1, 1.1], 6, 10)
        self.verify_listunspentlelantusmints([1, 1.1, 2, 10], 5, 10)
        assert_equal([False, False, False, False], list(map(lambda m : m["isUsed"], mints)))

        # state modification test
        # mark two coins as used
        self.nodes[0].setlelantusmintstatus(mints[2]["serialNumber"], True)
        self.nodes[0].setlelantusmintstatus(mints[3]["serialNumber"], True)

        mints = self.verify_listlelantusmints(amounts)
        self.verify_listunspentlelantusmints([1, 1.1])
        self.verify_listunspentlelantusmints([], 1000)
        self.verify_listunspentlelantusmints([], 1, 5)
        self.verify_listunspentlelantusmints([1, 1.1], 6, 10)
        self.verify_listunspentlelantusmints([1, 1.1], 5, 10)
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