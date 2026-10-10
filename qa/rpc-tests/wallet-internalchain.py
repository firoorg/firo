#!/usr/bin/env python3
# Copyright (c) 2026 The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests that the wallet watches the bip44 internal chain, m/44'/1'/0'/1/<n>.

Firo takes both its addresses and its change off the external chain and keeps doing so, but a
seed is not only ever used here. A wallet that follows bip44 more closely leaves its change on
the internal chain, and once that seed comes back, those coins have to be seen and spendable.
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes_bi,
    start_node,
    start_nodes,
    stop_node,
    sync_blocks,
)
from test_framework.test_helper import get_dumpwallet_otp

INTERNAL = "m/44'/1'/0'/1/"
EXTERNAL = "m/44'/1'/0'/0/"
LOOKAHEAD = 20


class WalletInternalChainTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 3
        # node0 mines. node1 holds the wallet under test and comes up without a lookahead, the way
        # a wallet that predates the internal chain being watched does. node2 is restored from the
        # same seed and stands in for the other bip44 wallet the coins are received through.
        self.node_args = [
            ['-usemnemonic=1'],
            ['-usemnemonic=1', '-keypool=0'],
            ['-usemnemonic=1', '-keypool=%d' % LOOKAHEAD],
        ]

    def setup_network(self, split=False):
        # node2 is started later, once node1's seed is known.
        self.nodes = start_nodes(2, self.options.tmpdir, self.node_args[:2])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def dump_wallet(self, node, name):
        """Returns the wallet's mnemonic and a keypath -> address map of every key it holds."""
        path = os.path.join(self.options.tmpdir, name)
        try:
            self.nodes[node].dumpwallet(path)
        except Exception as ex:
            # The first dump a node is asked for answers with a code to repeat the call with
            self.nodes[node].dumpwallet(path, get_dumpwallet_otp(ex.error['message']))

        mnemonic = None
        keys = {}
        with open(path, encoding='utf8') as dump:
            for line in dump:
                if line.startswith('# mnemonic: '):
                    mnemonic = line[len('# mnemonic: '):].strip()
                    continue
                fields = [field for field in line.split() if '=' in field]
                fields = dict(field.split('=', 1) for field in fields)
                if 'hdKeypath' in fields and 'addr' in fields:
                    keys[fields['hdKeypath']] = fields['addr']
        return mnemonic, keys

    def internal_chain(self, node, name):
        """The child index -> address map of the internal chain the wallet holds."""
        _, keys = self.dump_wallet(node, name)
        return {int(path[len(INTERNAL):]): addr for path, addr in keys.items() if path.startswith(INTERNAL)}

    def run_test(self):
        self.nodes[0].generate(101)
        self.sync_all()

        mnemonic, keys = self.dump_wallet(1, 'node1.dump')
        assert mnemonic, 'the wallet under test has to hold a mnemonic'
        # No lookahead was asked for, so this wallet has no internal chain at all yet
        assert_equal([path for path in keys if path.startswith(INTERNAL)], [])

        # Bring the other wallet up on the same seed and read the internal chain off it
        self.nodes.append(start_node(2, self.options.tmpdir, self.node_args[2] + ['-mnemonic=' + mnemonic]))
        connect_nodes_bi(self.nodes, 0, 2)
        sync_blocks(self.nodes)

        internal = self.internal_chain(2, 'node2.dump')
        assert_equal(sorted(internal), list(range(LOOKAHEAD)))

        # Pay it, the way another bip44 wallet leaves change there
        self.nodes[0].sendtoaddress(internal[0], 10)
        self.nodes[0].sendtoaddress(internal[LOOKAHEAD - 1], 5)
        self.nodes[0].generate(1)
        sync_blocks(self.nodes)

        # The wallet holding those keys sees the coins, and using the last of them moves the
        # lookahead up past it, the way a used keypool key tops the keypool up
        assert_equal(self.nodes[2].getbalance(), 15)
        assert_equal(max(self.internal_chain(2, 'node2-used.dump')), 2 * LOOKAHEAD - 1)

        # The wallet under test holds no internal chain, so the same coins go unnoticed
        assert_equal(self.nodes[1].getbalance(), 0)

        # Giving it a lookahead derives the chain and has it rescan for what it missed
        stop_node(self.nodes[1], 1)
        self.nodes[1] = start_node(1, self.options.tmpdir, self.node_args[2])
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)

        assert_equal(self.nodes[1].getbalance(), 15)
        restored = self.internal_chain(1, 'node1-restored.dump')
        assert_equal(restored[0], internal[0])
        assert_equal(max(restored), 2 * LOOKAHEAD - 1)

        # Addresses are still handed out off the external chain, nothing comes off the internal one
        for _ in range(5):
            addr = self.nodes[1].getnewaddress()
            assert self.nodes[1].validateaddress(addr)['hdkeypath'].startswith(EXTERNAL)

        # What was received on the internal chain is spendable, and its change goes back to the
        # external chain, where this wallet keeps all of its own outputs
        txid = self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 14)
        self.nodes[0].generate(1)
        sync_blocks(self.nodes)

        change = [out['scriptPubKey']['addresses'][0] for out in self.nodes[1].getrawtransaction(txid, 1)['vout']]
        change = [addr for addr in change if self.nodes[1].validateaddress(addr)['ismine']]
        assert_equal(len(change), 1)
        assert self.nodes[1].validateaddress(change[0])['hdkeypath'].startswith(EXTERNAL)
        fee = self.nodes[1].gettransaction(txid)['fee']  # negative
        assert_equal(self.nodes[1].getbalance(), 15 - 14 + fee)

        # The rescan is asked for once, not on every start from here on
        stop_node(self.nodes[1], 1)
        self.nodes[1] = start_node(1, self.options.tmpdir, self.node_args[2])
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)

        log = os.path.join(self.options.tmpdir, 'node1', 'regtest', 'debug.log')
        with open(log, encoding='utf8') as debug_log:
            rescans = [line for line in debug_log if 'transactions on the bip44 internal chain' in line]
        assert_equal(len(rescans), 1)


if __name__ == '__main__':
    WalletInternalChainTest().main()
