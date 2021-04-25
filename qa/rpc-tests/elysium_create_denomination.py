#!/usr/bin/env python3
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import ElysiumTestFramework
from test_framework.util import assert_equal, assert_raises_message

class ElysiumCreateDenominationTest(ElysiumTestFramework):
    def run_test(self):
        super().run_test()

        # create non-sigma token
        self.nodes[0].elysium_sendissuancefixed(self.addrs[0], 1, 1, 0, '', '', 'Normal Token', '', '', '1000000')
        self.nodes[0].generate(1)
        self.sync_all()

        # create sigma token
        self.nodes[0].elysium_sendissuancefixed(self.addrs[0], 1, 2, 0, '', '', 'Sigma Token', '', '', '1000000', 1)
        self.nodes[0].generate(1)

        self.sync_all()

        # test parameter value validation
        assert_raises_message(
            JSONRPCException,
            'Invalid address',
            self.nodes[0].elysium_sendcreatedenomination, 'abc', 4, '1'
        )

        assert_raises_message(
            JSONRPCException,
            'Property identifier is out of range',
            self.nodes[0].elysium_sendcreatedenomination, self.addrs[0], -1, '1'
        )

        assert_raises_message(
            JSONRPCException,
            'Property identifier is out of range',
            self.nodes[0].elysium_sendcreatedenomination, self.addrs[0], 0, '1'
        )

        assert_raises_message(
            JSONRPCException,
            'Property identifier is out of range',
            self.nodes[0].elysium_sendcreatedenomination, self.addrs[0], 4294967296, '1'
        )

        assert_raises_message(
            JSONRPCException,
            'Invalid amount',
            self.nodes[0].elysium_sendcreatedenomination, self.addrs[0], 3, '0.1' # fixed property will discard all fractional, so it will become 0
        )

        assert_raises_message(
            JSONRPCException,
            'Invalid amount',
            self.nodes[0].elysium_sendcreatedenomination, self.addrs[0], 4, '0'
        )

        assert_raises_message(
            JSONRPCException,
            'Invalid amount',
            self.nodes[0].elysium_sendcreatedenomination, self.addrs[0], 4, '-1'
        )

        # test parameter validation
        assert_raises_message(
            JSONRPCException,
            'Property identifier does not exist',
            self.nodes[0].elysium_sendcreatedenomination, self.addrs[0], 5, '1'
        )

        assert_raises_message(
            JSONRPCException,
            'Sender is not authorized to manage the property',
            self.nodes[0].elysium_sendcreatedenomination, self.addrs[1], 4, '1'
        )

        assert_raises_message(
            JSONRPCException,
            'Property has not enabled Sigma',
            self.nodes[0].elysium_sendcreatedenomination, self.addrs[0], 3, '1'
        )

        # test valid denomination creation
        self.nodes[0].elysium_sendcreatedenomination(self.addrs[0], 4, '0.5')
        self.nodes[0].generate(1)
        self.nodes[0].elysium_sendcreatedenomination(self.addrs[0], 4, '1')
        self.nodes[0].generate(1)

        self.sync_all()

        info = self.nodes[1].elysium_getproperty(4)

        assert_equal(info['denominations'][0]['id'], 0)
        assert_equal(info['denominations'][0]['value'], '0.50000000')
        assert_equal(info['denominations'][1]['id'], 1)
        assert_equal(info['denominations'][1]['value'], '1.00000000')

        # test duplicate denomination check
        assert_raises_message(
            JSONRPCException,
            'Denomination with value 0.50000000 already exists',
            self.nodes[0].elysium_sendcreatedenomination, self.addrs[0], 4, '0.5'
        )

        # test full denominations check
        for i in range(255 - 2):
            self.nodes[0].elysium_sendcreatedenomination(self.addrs[0], 4, str(i + 2))
            self.nodes[0].generate(1) # we need to mine here otherwise the input chaining will be too long

        assert_raises_message(
            JSONRPCException,
            'No more room for new denomination',
            self.nodes[0].elysium_sendcreatedenomination, self.addrs[0], 4, '1000'
        )

if __name__ == '__main__':
    ElysiumCreateDenominationTest().main()
