#!/usr/bin/env python3
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import ExodusTestFramework
from test_framework.util import assert_equal, assert_raises_message

class ExodusSendMintTest(ExodusTestFramework):
    def run_test(self):
        super().run_test()

        sigma_start_block = 500

        self.nodes[0].generatetoaddress(100, self.addrs[0])
        self.nodes[0].generate(sigma_start_block - self.nodes[0].getblockcount())

        assert(sigma_start_block == self.nodes[0].getblockcount())

        # create non-sigma
        self.nodes[0].exodus_sendissuancefixed(
            self.addrs[0], 1, 1, 0, '', '', 'Non-Sigma', '', '', '1000000'
        )
        self.nodes[0].generate(1)
        nonSigmaProperty = 3

        # create sigma with denominations (1, 2)
        self.nodes[0].exodus_sendissuancefixed(
            self.addrs[0], 1, 1, 0, '', '', 'Sigma', '', '', '1000000', 1
        )

        self.nodes[0].generate(1)
        sigmaProperty = 4

        self.nodes[0].exodus_sendcreatedenomination(self.addrs[0], sigmaProperty, '1')
        self.nodes[0].generate(1)

        self.nodes[0].exodus_sendcreatedenomination(self.addrs[0], sigmaProperty, '2')
        self.nodes[0].generate(10)

        # non-sigma
        addr = self.nodes[0].getnewaddress()
        self.nodes[0].exodus_send(self.addrs[0], addr, nonSigmaProperty, "100")
        self.nodes[0].sendtoaddress(addr, 100)
        self.nodes[0].generate(10)

        assert_raises_message(
            JSONRPCException,
            'Property has not enabled Sigma',
            self.nodes[0].exodus_sendmint, addr, nonSigmaProperty, {"0": 1}
        )

        assert_equal("100", self.nodes[0].exodus_getbalance(addr, nonSigmaProperty)['balance'])

        # sigma
        # mint without xzc and token
        addr = self.nodes[0].getnewaddress()
        assert_raises_message(
            JSONRPCException,
            'Sender has insufficient balance',
            self.nodes[0].exodus_sendmint, addr, sigmaProperty, {"0": 1}
        )

        # mint without xzc then fail
        addr = self.nodes[0].getnewaddress()
        self.nodes[0].exodus_send(self.addrs[0], addr, sigmaProperty, "100")
        self.nodes[0].generate(10)

        assert_raises_message(
            JSONRPCException,
            'Error choosing inputs for the send transaction',
            self.nodes[0].exodus_sendmint, addr, sigmaProperty, {"0": 1}
        )

        assert_equal("100", self.nodes[0].exodus_getbalance(addr, sigmaProperty)['balance'])
        assert_equal(0, len(self.nodes[0].exodus_listpendingmints()))

        # mint without token then fail
        addr = self.nodes[0].getnewaddress()
        self.nodes[0].sendtoaddress(addr, 100)
        self.nodes[0].generate(10)

        assert_raises_message(
            JSONRPCException,
            'Sender has insufficient balance',
            self.nodes[0].exodus_sendmint, addr, sigmaProperty, {"0":1}
        )

        assert_equal("0", self.nodes[0].exodus_getbalance(addr, sigmaProperty)['balance'])
        assert_equal(0, len(self.nodes[0].exodus_listpendingmints()))

        # success to mint should be shown on pending
        addr = self.nodes[0].getnewaddress()

        self.nodes[0].exodus_send(self.addrs[0], addr, sigmaProperty, "100")
        self.nodes[0].sendtoaddress(addr, 100)
        self.nodes[0].generate(10)
        self.nodes[0].exodus_sendmint(addr, sigmaProperty, {"0":1})

        assert_equal(1, len(self.nodes[0].exodus_listpendingmints()))
        assert_equal("99", self.nodes[0].exodus_getbalance(addr, sigmaProperty)['balance'])

        self.nodes[0].generate(1)
        assert_equal(0, len(self.nodes[0].exodus_listpendingmints()))
        assert_equal(1, len(self.nodes[0].exodus_listmints()))

if __name__ == '__main__':
    ExodusSendMintTest().main()
