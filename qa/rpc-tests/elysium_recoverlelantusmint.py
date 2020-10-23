#!/usr/bin/env python3
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import ElysiumTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_jsonrpc,
    assert_raises_message,
    bitcoind_processes,
    start_node,
    start_nodes,
)

from time import sleep

class ElysiumRecoverLelantusMintTest(ElysiumTestFramework):
    def run_test(self):
        super().run_test()

        # testing
        # 1. encrypt wallet
        passphrase = "1234"
        self.nodes[0].encryptwallet(passphrase)
        bitcoind_processes[0].wait()
        self.nodes[0] = start_node(0, self.options.tmpdir, ['-elysium'])

        self.nodes[0].walletpassphrase(passphrase, 10)
        addr = self.nodes[0].getnewaddress()
        self.nodes[0].generatetoaddress(1000, addr)
        self.nodes[0].elysium_sendissuancefixed(
            addr, 1, 1, 0, '', '', 'Lelantus', '', '', '1000000', 0 ,1
        )
        sleep(10)

        self.nodes[0].generate(1)
        lelantus_property = 3

        # 2. generate some mints
        self.nodes[0].walletpassphrase(passphrase, 2)
        self.nodes[0].elysium_sendlelantusmint(addr, lelantus_property, "10")
        self.nodes[0].elysium_sendlelantusmint(addr, lelantus_property, "10")

        self.nodes[0].generate(10)
        sleep(2)

        # 3. spend some coins to generate a joinsplit mint
        self.nodes[0].walletpassphrase(passphrase, 2)
        self.nodes[0].mintlelantus(2)
        self.nodes[0].mintlelantus(2)
        self.nodes[0].generate(10)
        sleep(2)

        self.nodes[0].walletpassphrase(passphrase, 2)
        self.nodes[0].elysium_sendlelantusspend(addr, lelantus_property, "1")
        sleep(2)

        self.nodes[0].generate(10)

        # 4. check mint, should not show all
        mints = self.nodes[0].elysium_listlelantusmints(1)
        assert_equal(0, len(mints))

        # 5. call recoverlelantusmint
        assert_raises_message(
            JSONRPCException,
            'Error: require passphrase to unlock wallet',
            self.nodes[0].elysium_recoverlelantusmints
        )

        assert_raises_message(
            JSONRPCException,
            'Error: The wallet passphrase entered was incorrect.',
            self.nodes[0].elysium_recoverlelantusmints, 'wrong passphrase'
        )

        self.nodes[0].elysium_recoverlelantusmints(passphrase)
        mints = self.nodes[0].elysium_listlelantusmints(1)
        assert_equal(2, len(mints))
        print(mints)

        # 6. all mint should be shown
        # - backup mnemonic
        # 1. encrypt wallet before connect
        # 2. connect to other node
        # 3. call recoverlelantusmint
        # 4. check the result

if __name__ == '__main__':
    ElysiumRecoverLelantusMintTest().main()