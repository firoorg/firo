#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""dip47 sending receiving RPCs QA test.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class Bip47SendReceive(BitcoinTestFramework):
    
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 3

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)
        self.is_network_split=False
        self.sync_all()

    def run_test(self):

        self.nodes[1].generate(1010)
        node0_pcode = self.nodes[0].createrapaddress("node0-pcode0")

        try:
            self.nodes[1].setupchannel(node0_pcode)
            raise AssertionError('Lelantus balance should be zero')
        except JSONRPCException as e:
            assert(e.error['code']==-6)
                
        self.nodes[1].mintlelantus(1)
        self.nodes[1].mintlelantus(1)
        self.nodes[1].generate(10)
        self.nodes[1].setupchannel(node0_pcode)
        self.nodes[1].generate(1)
        sync_blocks(self.nodes)
        self.nodes[1].sendtorapaddress(node0_pcode, 10)

        self.nodes[1].generate(1)
        self.sync_all()

        assert_equal(self.nodes[0].getbalance(), Decimal("10.0001"))

        self.nodes[0].sendtoaddress(self.nodes[2].getaccountaddress(""), 9.99)

        self.sync_all()
        self.nodes[1].generate(1)
        sync_blocks(self.nodes)

        assert_equal(self.nodes[2].getbalance(), Decimal("9.99"))


if __name__ == '__main__':
    Bip47SendReceive().main()
