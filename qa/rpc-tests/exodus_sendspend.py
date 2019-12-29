#!/usr/bin/env python3
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import ExodusTestFramework
from test_framework.util import assert_equal, assert_raises_message

class ExodusSendSpendTest(ExodusTestFramework):
    def run_test(self):
        super().run_test()

        sigma_starting_block = 500

        self.nodes[0].generatetoaddress(sigma_starting_block - self.nodes[0].getblockcount(), self.addrs[0])
        self.sync_all()

        assert_equal(sigma_starting_block, self.nodes[0].getblockcount())

        # non-sigma
        self.nodes[0].exodus_sendissuancefixed(self.addrs[0], 1, 1, 0, 'main', \
            'indivisible', 'non-sigma', '', '', '1000000')
        self.nodes[0].generate(1)

        nonSigmaProperty = 3

        addr = self.nodes[1].getnewaddress()
        self.nodes[0].exodus_send(self.addrs[0], addr, nonSigmaProperty, '100')
        self.nodes[0].generate(1)

        self.sync_all()

        assert_raises_message(
            JSONRPCException,
            'Denomination is not valid',
            self.nodes[1].exodus_sendspend, self.addrs[1], nonSigmaProperty, 0
        )

        # sigma
        self.nodes[0].exodus_sendissuancefixed(self.addrs[0], 1, 1, 0, 'main', \
            'indivisible', 'sigma', '', '', '1000000', 1)
        self.nodes[0].generate(1)

        sigmaProperty = 4

        addr = self.nodes[1].getnewaddress()
        self.nodes[0].exodus_send(self.addrs[0], addr, sigmaProperty, '100')

        self.nodes[0].generate(1)
        self.sync_all()

        assert_raises_message(
            JSONRPCException,
            'Denomination is not valid',
            self.nodes[1].exodus_sendspend, self.addrs[1], sigmaProperty, 0
        )

        # generate some denominations and mint
        self.nodes[0].exodus_sendcreatedenomination(self.addrs[0], sigmaProperty, '1')
        self.nodes[0].generate(1)
        self.nodes[0].exodus_sendcreatedenomination(self.addrs[0], sigmaProperty, '2')
        self.nodes[0].generate(10)
        self.sync_all()

        # spend without any mint
        assert_raises_message(
            JSONRPCException,
            'No available mint to spend',
            self.nodes[1].exodus_sendspend, self.addrs[1], sigmaProperty, 0
        )

        # have sigma mint but have no exodus mint
        testing_node = self.nodes[1] # fresh node
        addr = testing_node.getnewaddress()
        self.nodes[0].sendtoaddress(addr, '100')
        self.nodes[0].generate(1)
        self.sync_all()

        testing_node.mint(2)
        self.nodes[0].generate(10)
        self.sync_all()

        assert_raises_message(
            JSONRPCException,
            'No available mint to spend',
            testing_node.exodus_sendspend, self.addrs[1], sigmaProperty, 0
        )

        # have exodus mint have no sigma mint to spend
        testing_node = self.nodes[2] # fresh node
        addr = testing_node.getnewaddress()
        self.nodes[0].sendtoaddress(addr, '100')
        self.nodes[0].exodus_send(self.addrs[0], addr, sigmaProperty, '100')
        self.nodes[0].generate(1)
        self.sync_all()

        testing_node.exodus_sendmint(addr, sigmaProperty, {"0": 2})
        testing_node.generate(1)
        self.sync_all()

        assert_raises_message(
            JSONRPCException,
            'Error no sigma mints to pay as transaction fee',
            self.nodes[2].exodus_sendspend, self.addrs[0], sigmaProperty, 0
        )

        # met all requirements
        testing_node.mint(2)
        testing_node.generate(10)
        self.sync_all()

        receiver = self.nodes[0].getnewaddress()

        testing_node.exodus_sendspend(receiver, sigmaProperty, 0)
        testing_node.exodus_sendspend(receiver, sigmaProperty, 0)

        testing_node.generate(1)
        self.sync_all()

        assert_equal('2', self.nodes[0].exodus_getbalance(receiver, sigmaProperty)['balance'])

if __name__ == '__main__':
    ExodusSendSpendTest().main()
