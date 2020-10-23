#!/usr/bin/env python3
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import ElysiumTestFramework
from test_framework.util import assert_equal, assert_raises_message

class ElysiumSendLelantusMintTest(ElysiumTestFramework):
    def run_test(self):
        super().run_test()

        lelantus_start_block = 1000

        self.nodes[0].generatetoaddress(100, self.addrs[0])
        self.nodes[0].generate(lelantus_start_block - self.nodes[0].getblockcount())

        assert_equal(lelantus_start_block, self.nodes[0].getblockcount())

        # create non-lelantus
        self.nodes[0].elysium_sendissuancefixed(
            self.addrs[0], 1, 1, 0, '', '', 'Non-lelantus', '', '', '1000000'
        )
        self.nodes[0].generate(1)
        non_lelantus_property = 3

        # create lelantus
        self.nodes[0].elysium_sendissuancefixed(
            self.addrs[0], 1, 1, 0, '', '', 'Lelantus', '', '', '1000000', 0 ,1
        )

        self.nodes[0].generate(1)
        lelantus_property = 4

        # non-lelantus
        addr = self.nodes[0].getnewaddress()
        self.nodes[0].elysium_send(self.addrs[0], addr, non_lelantus_property, "100")
        self.nodes[0].sendtoaddress(addr, 100)
        self.nodes[0].generate(10)

        assert_raises_message(
            JSONRPCException,
            'Property has not enabled Lelantus',
            self.nodes[0].elysium_sendlelantusmint, addr, non_lelantus_property, "10"
        )

        assert_equal("100", self.nodes[0].elysium_getbalance(addr, non_lelantus_property)['balance'])

        # lelantus
        # mint without xzc and token
        addr = self.nodes[0].getnewaddress()
        assert_raises_message(
            JSONRPCException,
            'Sender has insufficient balance',
            self.nodes[0].elysium_sendlelantusmint, addr, lelantus_property, "10"
        )

        # mint without xzc then fail
        addr = self.nodes[0].getnewaddress()
        self.nodes[0].elysium_send(self.addrs[0], addr, lelantus_property, "100")
        self.nodes[0].generate(10)

        assert_raises_message(
            JSONRPCException,
            'Error choosing inputs for the send transaction',
            self.nodes[0].elysium_sendlelantusmint, addr, lelantus_property, "10"
        )

        assert_equal("100", self.nodes[0].elysium_getbalance(addr, lelantus_property)['balance'])
        assert_equal(0, len(self.nodes[0].elysium_listpendinglelantusmints()))

        # mint without token then fail
        addr = self.nodes[0].getnewaddress()
        self.nodes[0].sendtoaddress(addr, 100)
        self.nodes[0].generate(10)

        assert_raises_message(
            JSONRPCException,
            'Sender has insufficient balance',
            self.nodes[0].elysium_sendlelantusmint, addr, lelantus_property, "10"
        )

        assert_equal("0", self.nodes[0].elysium_getbalance(addr, lelantus_property)['balance'])
        assert_equal(0, len(self.nodes[0].elysium_listpendinglelantusmints()))

        # success to mint should be shown on pending
        addr = self.nodes[0].getnewaddress()

        self.nodes[0].elysium_send(self.addrs[0], addr, lelantus_property, "100")
        self.nodes[0].sendtoaddress(addr, 100)
        self.nodes[0].generate(10)
        self.nodes[0].elysium_sendlelantusmint(addr, lelantus_property, "10")

        assert_equal(1, len(self.nodes[0].elysium_listpendinglelantusmints()))
        assert_equal("90", self.nodes[0].elysium_getbalance(addr, lelantus_property)['balance'])

        self.nodes[0].generate(1)
        assert_equal(0, len(self.nodes[0].elysium_listpendinglelantusmints()))
        assert_equal(1, len(self.nodes[0].elysium_listlelantusmints()))

if __name__ == '__main__':
    ElysiumSendLelantusMintTest().main()