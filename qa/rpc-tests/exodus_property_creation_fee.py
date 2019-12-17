#!/usr/bin/env python3
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import ExodusTestFramework
from test_framework.util import assert_raises_message

class ExodusPropertyCreationFeeTest(ExodusTestFramework):

    def get_new_address(self, default_balance = 0):
        addr = self.nodes[0].getnewaddress()

        if default_balance > 0:
            self.nodes[0].sendtoaddress(addr, default_balance)
            self.nodes[0].generate(1)
            self.sync_all()

        return addr

    def test(self, balance = 1, ecosystem = 1, amount = None, expected_error = None):
        addr = self.get_new_address(balance)

        operator = self.nodes[0].exodus_sendissuancemanaged
        options = [addr, ecosystem, 1, 0, "", "", "Foo", "", ""]

        if amount is not None:
            operator = self.nodes[0].exodus_sendissuancefixed
            options.append(amount)

        if expected_error is None:
            operator(*options)
            self.nodes[0].generate(1)
            self.sync_all()
        else:
            assert_raises_message(
                JSONRPCException,
                expected_error,
                operator,
                *options)

    def test_insufficient(self, balance = 1, ecosystem = 1, amount = None):
        self.test(balance, ecosystem, amount, 'fees may not be sufficient')

    def run_test(self):
        super().run_test()

        creation_fee_start_block = 500

        # before creation fee is activated, all properies type should be able to create with low fee.
        self.test(ecosystem = 1)
        self.test(ecosystem = 1, amount = "10000")
        self.test(ecosystem = 2)
        self.test(ecosystem = 2, amount = "10000")

        # make sure, property creation fee is activated
        self.nodes[0].generate(creation_fee_start_block - self.nodes[0].getblockcount())

        # after the activation, 100 XZC is required for creating main ecosystem property
        self.test_insufficient(ecosystem = 1)
        self.test_insufficient(ecosystem = 1, amount = "10000")

        # test ecosystem should be able to create with low fee
        self.test(ecosystem = 2)
        self.test(ecosystem = 2, amount = "10000")

        # creating main ecosystem property with 100 XZC fee, should success
        self.test(balance = 101, ecosystem = 1)
        self.test(balance = 101, ecosystem = 1, amount = "10000")

if __name__ == '__main__':
    ExodusPropertyCreationFeeTest().main()