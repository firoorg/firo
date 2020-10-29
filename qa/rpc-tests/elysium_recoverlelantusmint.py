#!/usr/bin/env python3
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_jsonrpc,
    assert_raises_message,
    bitcoind_processes,
    connect_nodes,
    connect_nodes_bi,
    start_node,
    start_nodes,
)

from time import sleep
import os
import shutil

class ElysiumRecoverLelantusMintTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        # self.mnemonic = 'robust magnet atom concert tank sing sand chimney draw obvious attract mask science volcano tattoo'

    def setup_nodes(self):
        self.args = [['-elysium'] for _ in range(self.num_nodes)]
        # self.args[0].append(f'-mnemonic=\"{self.mnemonic}\"')

        return start_nodes(self.num_nodes, self.options.tmpdir, self.args)

    def run_test(self):
        # super().run_test()

        # testing
        # 1. encrypt wallet
        passphrase = "1234"
        self.nodes[0].encryptwallet(passphrase)
        bitcoind_processes[0].wait()

        # make snapshot
        regdir = os.path.join(self.options.tmpdir, 'node0', 'regtest')
        tmpdir = os.path.join(self.options.tmpdir, 'node0', 'regtest.tmp')
        shutil.copytree(regdir, tmpdir)

        self.nodes[0] = start_node(0, self.options.tmpdir, ['-elysium'])
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)

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
        mints = self.nodes[0].elysium_listlelantusmints(lelantus_property, True)
        assert_equal(1, len(mints))

        assert_equal('10', mints[0]['value'])

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

        # 6. all mint should be shown
        mints = self.nodes[0].elysium_listlelantusmints(lelantus_property, True)
        assert_equal(2, len(mints))

        mintVals = [m['value'] for m in mints]
        mintVals.sort()

        assert_equal(['10', '9'], mintVals)

        self.sync_all()

        # clear to do fresh start
        self.nodes[0].stop()
        bitcoind_processes[0].wait()

        shutil.rmtree(regdir)
        shutil.copytree(tmpdir, regdir)

        self.nodes[0] = start_node(0, self.options.tmpdir, self.args[0])
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)

        sleep(5)
        self.sync_all()

        # wallet is locked then no mints is recover from pool
        mints = self.nodes[0].elysium_listlelantusmints(lelantus_property, True)
        assert_equal(0, len(mints))

        self.nodes[0].elysium_recoverlelantusmints(passphrase)

        # all mint should be shown
        mints = self.nodes[0].elysium_listlelantusmints(lelantus_property, True)
        assert_equal(2, len(mints))

        mintVals = [m['value'] for m in mints]
        mintVals.sort()

        assert_equal(['10', '9'], mintVals)

if __name__ == '__main__':
    ElysiumRecoverLelantusMintTest().main()