#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_message, JSONRPCException

class SparkMintTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = False

    def run_test(self):
        assert_raises_message(
            JSONRPCException,
            "Spark is not activated yet",
            self.nodes[0].mintspark, 1)

        self.nodes[0].generate(1001)

        # generate coins
        amounts = [1, 1.1, 2, 10]

        # 10 confirmations
        address = self.nodes[0].getnewsparkaddress()[0]
        self.nodes[0].mintspark({address: {"amount": amounts[0], "memo":"Test memo"}})
        self.nodes[0].mintspark({address: {"amount": amounts[1], "memo": "Test memo"}})
        self.nodes[0].generate(5)

        # 5 confirmations
        self.nodes[0].mintspark({address: {"amount": amounts[2], "memo": "Test memo"}})
        self.nodes[0].mintspark({address: {"amount": amounts[3], "memo": "Test memo"}})
        self.nodes[0].generate(5)

        # get all mints and utxos
        mints = self.verify_listsparkmints(amounts)
        self.verify_listunspentsparkmints(amounts)
        assert_equal([False, False, False, False], list(map(lambda m : m["isUsed"], mints)))

        # state modification test
        # mark two coins as used
        self.nodes[0].setsparkmintstatus(mints[2]["lTagHash"], True)
        self.nodes[0].setsparkmintstatus(mints[3]["lTagHash"], True)

        mints = self.verify_listsparkmints(amounts)
        self.verify_listunspentsparkmints([1, 1.1])
        assert_equal([False, False, True, True], list(map(lambda m : m["isUsed"], mints)))

        # set a coin as unused
        self.nodes[0].setsparkmintstatus(mints[3]["lTagHash"], False)
        mints = self.verify_listsparkmints(amounts)
        self.verify_listunspentsparkmints([1, 1.1, 10])
        assert_equal([False, False, True, False], list(map(lambda m : m["isUsed"], mints)))

        self.nodes[0].setsparkmintstatus(mints[0]["lTagHash"], False)
        self.nodes[0].setsparkmintstatus(mints[1]["lTagHash"], False)
        self.nodes[0].setsparkmintstatus(mints[2]["lTagHash"], False)
        self.nodes[0].setsparkmintstatus(mints[3]["lTagHash"], False)

        mints = self.verify_listsparkmints(amounts)
        self.verify_listunspentsparkmints(amounts)
        assert_equal([False, False, False, False], list(map(lambda m : m["isUsed"], mints)))

    def verify_listsparkmints(self, expected_amounts):
        mints = self.nodes[0].listsparkmints()
        mints = sorted(mints, key = lambda u: u['amount'])

        assert_equal(
            sorted(expected_amounts),
            list(map(lambda u: float(u['amount']), mints)))

        return mints

    def verify_listunspentsparkmints(self, expected_amounts):
        mints = self.nodes[0].listunspentsparkmints()
        mints = sorted(mints, key = lambda u: float(u['amount']))

        assert_equal(
            sorted(expected_amounts),
            list(map(lambda u: float(u['amount']), mints)))

        return mints

if __name__ == '__main__':
    SparkMintTest().main()
