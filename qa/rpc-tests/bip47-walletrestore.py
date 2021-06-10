#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""dip47 sending receiving RPCs QA test.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class Bip47WalletRestore(BitcoinTestFramework):
    
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)

    def run_test(self):
        backup_file = os.path.join(self.options.tmpdir, "cleanwallet.bak")
        wallet_file = os.path.join(self.options.tmpdir, "node0/regtest/wallet.dat")
        self.nodes[0].backupwallet(backup_file)
        initial_pcodes = [self.nodes[0].createpcode("pcode" + str(num)) for num in range(0,200)]
        assert(len(initial_pcodes) == 200)

        stop_node(self.nodes[0], 0)
        os.remove(wallet_file)
        shutil.copy(backup_file, wallet_file)

        self.nodes[0] = start_node(0, self.options.tmpdir)
        assert(len(self.nodes[0].listpcodes()) == 0)

        for i in range(0, 200):
            assert(initial_pcodes[i] == self.nodes[0].createpcode("pcode" + str(i)))


if __name__ == '__main__':
    Bip47WalletRestore().main()
