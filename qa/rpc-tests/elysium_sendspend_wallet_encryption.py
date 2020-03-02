#!/usr/bin/env python3
import time
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import ElysiumTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_message,
    bitcoind_processes,
    connect_nodes,
    start_node)

class ElysiumSendSpendWalletEncryptionTest(ElysiumTestFramework):
    def run_test(self):
        super().run_test()

        sigma_start_block = 550
        passphase = "1234"

        owner = self.addrs[0]

        self.nodes[0].generatetoaddress(
            sigma_start_block - self.nodes[0].getblockcount(),
            owner)
        self.sync_all()

        # create sigma
        for _ in range(0, 10):
            self.nodes[0].mint(1)

        self.nodes[0].generate(10)

        # create property
        self.nodes[0].elysium_sendissuancefixed(
            owner, 1, 1, 0, '', '', 'Sigma', '', '', '1000000', 1)

        self.nodes[0].generate(1)
        sigmaProperty = 3

        self.nodes[0].elysium_sendcreatedenomination(owner, sigmaProperty, '1')
        self.nodes[0].generate(10)

        # mint 2 coins
        self.nodes[0].elysium_sendmint(owner, sigmaProperty, {"0": 2})
        self.nodes[0].generate(10)

        # spend a coin
        self.nodes[0].elysium_sendspend(owner, sigmaProperty, 0)
        self.nodes[0].generate(1)

        blockcount = self.nodes[0].getblockcount()

        # encrypt wallet && restart node
        self.nodes[0].encryptwallet(passphase)
        bitcoind_processes[0].wait()
        self.nodes[0] = start_node(0, self.options.tmpdir, ['-elysium', '-reindex'])
        while self.nodes[0].getblockcount() < blockcount:
            time.sleep(0.1)

        connect_nodes(self.nodes[0], 1)

        # try to spend using encrypted wallet
        assert_raises_message(
            JSONRPCException,
            'wallet locked',
            self.nodes[0].elysium_sendspend, owner, sigmaProperty, 0)

        # Unlock
        self.nodes[0].walletpassphrase(passphase, 10)

        # One coin remaining
        unspends = self.nodes[0].elysium_listmints()
        assert_equal(1, len(unspends))

        # Spend another coin
        self.nodes[0].elysium_sendspend(owner, sigmaProperty, 0)

        # No remaining coin
        unspends = self.nodes[0].elysium_listmints()
        assert_equal(0, len(unspends))

if __name__ == '__main__':
    ElysiumSendSpendWalletEncryptionTest().main()