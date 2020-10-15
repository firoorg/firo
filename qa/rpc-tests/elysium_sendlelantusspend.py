#!/usr/bin/env python3
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import ElysiumTestFramework
from test_framework.util import assert_equal, assert_raises_message
import time

class ElysiumSendSpendTest(ElysiumTestFramework):
    def run_test(self):
        super().run_test()

        lelantus_starting_block = 1000

        self.nodes[0].generatetoaddress(lelantus_starting_block - self.nodes[0].getblockcount(), self.addrs[0])
        self.sync_all()

        assert_equal(lelantus_starting_block, self.nodes[0].getblockcount())

        # # non-sigma
        # self.nodes[0].elysium_sendissuancefixed(self.addrs[0], 1, 1, 0, 'main', \
        #     'indivisible', 'non-sigma', '', '', '1000000')
        # self.nodes[0].generate(1)

        # nonSigmaProperty = 3

        # addr = self.nodes[1].getnewaddress()
        # self.nodes[0].elysium_send(self.addrs[0], addr, nonSigmaProperty, '100')
        # self.nodes[0].generate(1)

        # self.sync_all()

        # assert_raises_message(
        #     JSONRPCException,
        #     'Denomination is not valid',
        #     self.nodes[1].elysium_sendspend, self.addrs[1], nonSigmaProperty, 0
        # )

        self.nodes[0].elysium_sendissuancefixed(self.addrs[0], 1, 1, 0, 'main', \
            'indivisible', 'foo', '', '', '1000000')
        self.nodes[0].generate(1)

        lelantusProperty = 3

        addr = self.nodes[1].getnewaddress()
        self.nodes[0].elysium_send(self.addrs[0], addr, lelantusProperty, '100')

        self.nodes[0].generate(1)
        self.sync_all()

        # spend without any mint
        assert_raises_message(
            JSONRPCException,
            'Insufficient funds',
            self.nodes[1].elysium_sendlelantusspend, self.addrs[1], lelantusProperty, '100'
        )

        # have lelantus mint but have no elysium mint
        testing_node = self.nodes[1] # fresh node
        addr = testing_node.getnewaddress()
        self.nodes[0].sendtoaddress(addr, '100')
        self.nodes[0].generate(1)
        self.sync_all()

        testing_node.mintlelantus(2)
        self.nodes[0].generate(10)
        self.sync_all()

        assert_raises_message(
            JSONRPCException,
            'Insufficient funds',
            testing_node.elysium_sendlelantusspend, self.addrs[1], lelantusProperty, '100'
        )

        # have elysium mint have no lelantus mint to spend
        testing_node = self.nodes[2] # fresh node
        addr = testing_node.getnewaddress()
        self.nodes[0].sendtoaddress(addr, '100')
        self.nodes[0].elysium_send(self.addrs[0], addr, lelantusProperty, '100')
        self.nodes[0].generate(1)
        self.sync_all()

        testing_node.elysium_sendlelantusmint(addr, lelantusProperty, '10')
        testing_node.elysium_sendlelantusmint(addr, lelantusProperty, '10')
        testing_node.generate(1)
        self.sync_all()
        time.sleep(1)

        assert_raises_message(
            JSONRPCException,
            'Error no lelantus mints to pay as transaction fee',
            self.nodes[2].elysium_sendlelantusspend, self.addrs[0], lelantusProperty, '10'
        )

        # met all requirements
        testing_node.mintlelantus(2)
        testing_node.mintlelantus(2)
        testing_node.generate(10)
        self.sync_all()

        receiver = self.nodes[0].getnewaddress()

        testing_node.elysium_sendlelantusspend(receiver, lelantusProperty, '1')
        testing_node.elysium_sendlelantusspend(receiver, lelantusProperty, '1')

        testing_node.generate(1)
        self.sync_all()

        assert_equal('2', self.nodes[0].elysium_getbalance(receiver, lelantusProperty)['balance'])

if __name__ == '__main__':
    ElysiumSendSpendTest().main()
