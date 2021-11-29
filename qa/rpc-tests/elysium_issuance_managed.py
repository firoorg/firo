#!/usr/bin/env python3
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import ElysiumTestFramework
from test_framework.util import assert_equal, assert_raises_message

class ElysiumIssuanceManagedTest(ElysiumTestFramework):
    def run_test(self):
        super().run_test()

        # check parameter value validation
        assert_raises_message(
            JSONRPCException,
            'Invalid address',
            self.nodes[0].elysium_sendissuancemanaged, 'abc', 1, 1, 0, 'category1', 'subcategory1', 'token1', 'http://foo.com', 'data1'
        )

        assert_raises_message(
            JSONRPCException,
            'Invalid ecosystem (1 = main, 2 = test only)',
            self.nodes[0].elysium_sendissuancemanaged, self.addrs[0], 0, 1, 0, 'category1', 'subcategory1', 'token1', 'http://foo.com', 'data1'
        )

        assert_raises_message(
            JSONRPCException,
            'Invalid ecosystem (1 = main, 2 = test only)',
            self.nodes[0].elysium_sendissuancemanaged, self.addrs[0], 3, 1, 0, 'category1', 'subcategory1', 'token1', 'http://foo.com', 'data1'
        )

        assert_raises_message(
            JSONRPCException,
            'Invalid property type (1 = indivisible, 2 = divisible only)',
            self.nodes[0].elysium_sendissuancemanaged, self.addrs[0], 1, 0, 0, 'category1', 'subcategory1', 'token1', 'http://foo.com', 'data1'
        )

        assert_raises_message(
            JSONRPCException,
            'Invalid property type (1 = indivisible, 2 = divisible only)',
            self.nodes[0].elysium_sendissuancemanaged, self.addrs[0], 1, 3, 0, 'category1', 'subcategory1', 'token1', 'http://foo.com', 'data1'
        )

        assert_raises_message(
            JSONRPCException,
            'Property appends/replaces are not yet supported',
            self.nodes[0].elysium_sendissuancemanaged, self.addrs[0], 1, 1, 1, 'category1', 'subcategory1', 'token1', 'http://foo.com', 'data1'
        )

        assert_raises_message(
            JSONRPCException,
            'Text must not be longer than 255 characters',
            self.nodes[0].elysium_sendissuancemanaged, self.addrs[0], 1, 1, 0, 'c' * 256, 'subcategory1', 'token1', 'http://foo.com', 'data1'
        )

        assert_raises_message(
            JSONRPCException,
            'Text must not be longer than 255 characters',
            self.nodes[0].elysium_sendissuancemanaged, self.addrs[0], 1, 1, 0, 'category1', 's' * 256, 'token1', 'http://foo.com', 'data1'
        )

        assert_raises_message(
            JSONRPCException,
            'Text must not be longer than 255 characters',
            self.nodes[0].elysium_sendissuancemanaged, self.addrs[0], 1, 1, 0, 'category1', 'subcategory1', 't' * 256, 'http://foo.com', 'data1'
        )

        assert_raises_message(
            JSONRPCException,
            'Text must not be longer than 255 characters',
            self.nodes[0].elysium_sendissuancemanaged, self.addrs[0], 1, 1, 0, 'category1', 'subcategory1', 'token1', 'h' * 256, 'data1'
        )

        assert_raises_message(
            JSONRPCException,
            'Text must not be longer than 255 characters',
            self.nodes[0].elysium_sendissuancemanaged, self.addrs[0], 1, 1, 0, 'category1', 'subcategory1', 'token1', 'http://foo.com', 'd' * 256
        )

        assert_raises_message(
            JSONRPCException,
            'Property name must not be empty',
            self.nodes[0].elysium_sendissuancemanaged, self.addrs[0], 1, 1, 0, 'category1', 'subcategory1', '', 'http://foo.com', 'data1'
        )

        assert_raises_message(
            JSONRPCException,
            'Lelantus status is not valid',
            self.nodes[0].elysium_sendissuancemanaged, self.addrs[0], 1, 1, 0, 'category1', 'subcategory1', 'token1', 'http://foo.com', 'data1', 4
        )

        assert_raises_message(
            JSONRPCException,
            'Lelantus feature is not activated yet',
            self.nodes[0].elysium_sendissuancemanaged, self.addrs[0], 1, 1, 0, 'category1', 'subcategory1', 'token1', 'http://foo.com', 'data1', 1
        )

        lelantus_starting_block = 1000
        remaining = lelantus_starting_block - self.nodes[0].getblockcount()
        while remaining > 0:
            # Generate in blocks of 10 so we don't run into timeout issues.
            self.nodes[0].generatetoaddress(min(10, remaining), self.addrs[0])
            remaining -= 10

        self.sync_all()

        # create properties
        tx1 = self.nodes[0].elysium_sendissuancemanaged(self.addrs[0], 1, 1, 0, 'main', 'indivisible', 'token1', 'http://token1.com', 'data1')
        self.mine_tx(tx1)

        tx2 = self.nodes[1].elysium_sendissuancemanaged(self.addrs[1], 1, 2, 0, 'main', 'divisible', 'token2', 'http://token2.com', 'data2', 0)
        self.mine_tx(tx2)

        tx3 = self.nodes[2].elysium_sendissuancemanaged(self.addrs[2], 2, 1, 0, 'test', 'indivisible', 'token3', 'http://token3.com', 'data3', 1)
        self.mine_tx(tx3)

        tx4 = self.nodes[3].elysium_sendissuancemanaged(self.addrs[3], 2, 2, 0, 'test', 'divisible', 'token4', 'http://token4.com', 'data4', 2)
        self.mine_tx(tx4)

        tx5 = self.nodes[0].elysium_sendissuancemanaged(self.addrs[0], 1, 1, 0, 'main', 'indivisible', 'token5', 'http://token5.com', 'data5', 3)
        self.mine_tx(tx5)

        assert_raises_message(
            JSONRPCException,
            'Lelantus status is not valid',
            self.nodes[0].elysium_sendissuancemanaged, self.addrs[0], 1, 1, 0, 'category1', 'subcategory1', 'token1', 'http://foo.com', 'data1', 4
        )

        tx6 = self.nodes[1].elysium_sendissuancemanaged(self.addrs[1], 1, 2, 0, 'main', 'divisible', 'token6', 'http://token6.com', 'data6', 0)
        self.mine_tx(tx6)

        tx7 = self.nodes[2].elysium_sendissuancemanaged(self.addrs[2], 2, 1, 0, 'test', 'indivisible', 'token7', 'http://token7.com', 'data7', 1)
        self.mine_tx(tx7)

        tx8 = self.nodes[3].elysium_sendissuancemanaged(self.addrs[3], 2, 2, 0, 'test', 'divisible', 'token8', 'http://token8.com', 'data8', 2)
        self.mine_tx(tx8)

        tx9 = self.nodes[0].elysium_sendissuancemanaged(self.addrs[0], 1, 1, 0, 'main', 'indivisible', 'token9', 'http://token9.com', 'data9', 3)
        self.mine_tx(tx9)

        # check property creation
        props = self.nodes[0].elysium_listproperties()

        assert_equal(len(props), 2 + 9) # 2 pre-defined properties + 9 new created

        self.assert_property_summary(props[2], 3, False, 'main', 'indivisible', 'token1', 'http://token1.com', 'data1')
        self.assert_property_summary(props[3], 4, True, 'main', 'divisible', 'token2', 'http://token2.com', 'data2')
        self.assert_property_summary(props[4], 5, False, 'main', 'indivisible', 'token5', 'http://token5.com', 'data5') # main eco tokens will come first
        self.assert_property_summary(props[7], 2147483651, False, 'test', 'indivisible', 'token3', 'http://token3.com', 'data3')
        self.assert_property_summary(props[8], 2147483652, True, 'test', 'divisible', 'token4', 'http://token4.com', 'data4')
        self.assert_property_summary(props[5], 6, True, 'main', 'divisible', 'token6', 'http://token6.com', 'data6')
        self.assert_property_summary(props[6], 7, False, 'main', 'indivisible', 'token9', 'http://token9.com', 'data9') # main eco tokens will come first
        self.assert_property_summary(props[9], 2147483653, False, 'test', 'indivisible', 'token7', 'http://token7.com', 'data7')
        self.assert_property_summary(props[10], 2147483654, True, 'test', 'divisible', 'token8', 'http://token8.com', 'data8')

        self.assert_property_info(
            self.nodes[1].elysium_getproperty(3),
            3,
            False,
            self.addrs[0],
            False,
            'main',
            'indivisible',
            'token1',
            'http://token1.com',
            'data1',
            '0',
            tx1,
            [],
            'SoftDisabled')
        self.assert_property_info(
            self.nodes[2].elysium_getproperty(4),
            4,
            False,
            self.addrs[1],
            True,
            'main',
            'divisible',
            'token2',
            'http://token2.com',
            'data2',
            '0.00000000',
            tx2,
            [],
            'SoftDisabled')
        self.assert_property_info(
            self.nodes[1].elysium_getproperty(5),
            5,
            False,
            self.addrs[0],
            False,
            'main',
            'indivisible',
            'token5',
            'http://token5.com',
            'data5',
            '0',
            tx5,
            [],
            'HardEnabled')
        self.assert_property_info(
            self.nodes[3].elysium_getproperty(2147483651),
            2147483651,
            False,
            self.addrs[2],
            False,
            'test',
            'indivisible',
            'token3',
            'http://token3.com',
            'data3',
            '0',
            tx3,
            [],
            'SoftEnabled')
        self.assert_property_info(
            self.nodes[0].elysium_getproperty(2147483652),
            2147483652,
            False,
            self.addrs[3],
            True,
            'test',
            'divisible',
            'token4',
            'http://token4.com',
            'data4',
            '0.00000000',
            tx4,
            [],
            'HardDisabled')
        self.assert_property_info(
            self.nodes[2].elysium_getproperty(6),
            6,
            False,
            self.addrs[1],
            True,
            'main',
            'divisible',
            'token6',
            'http://token6.com',
            'data6',
            '0.00000000',
            tx6,
            [],
            'SoftDisabled')
        self.assert_property_info(
            self.nodes[1].elysium_getproperty(7),
            7,
            False,
            self.addrs[0],
            False,
            'main',
            'indivisible',
            'token9',
            'http://token9.com',
            'data9',
            '0',
            tx9,
            [],
            'HardEnabled')
        self.assert_property_info(
            self.nodes[3].elysium_getproperty(2147483653),
            2147483653,
            False,
            self.addrs[2],
            False,
            'test',
            'indivisible',
            'token7',
            'http://token7.com',
            'data7',
            '0',
            tx7,
            [],
            'SoftEnabled')
        self.assert_property_info(
            self.nodes[0].elysium_getproperty(2147483654),
            2147483654,
            False,
            self.addrs[3],
            True,
            'test',
            'divisible',
            'token8',
            'http://token8.com',
            'data8',
            '0.00000000',
            tx8,
            [],
            'HardDisabled')

if __name__ == '__main__':
    ElysiumIssuanceManagedTest().main()
