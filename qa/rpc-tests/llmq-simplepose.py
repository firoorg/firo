#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import EvoZnodeTestFramework
from test_framework.util import *
from time import *

'''
llmq-simplepose.py

Checks simple PoSe system based on LLMQ commitments

'''

class LLMQSimplePoSeTest(EvoZnodeTestFramework):
    def __init__(self):
        super().__init__(6, 5)

    def run_test(self):

        # check if mining quorums with all nodes being online succeeds without punishment/banning
        for i in range(3):
            self.mine_quorum()
        for mn in self.mninfo:
            assert(not self.check_punished(mn) and not self.check_punished(mn))

        # Now lets kill MNs one by one and verify that punishment/banning happens
        for i in range(len(self.mninfo), len(self.mninfo) - 2, -1):
            mn = self.mninfo[len(self.mninfo) - 1]
            self.mninfo.remove(mn)
            self.stop_node(mn.nodeIdx)
            self.nodes.remove(mn.node)

            t = time()
            while (not self.check_punished(mn) or not self.check_banned(mn)) and (time() - t) < 120:
                self.mine_quorum(expected_contributions=i-1, expected_complaints=i-1, expected_commitments=i-1)

            assert(self.check_punished(mn) and self.check_banned(mn))

    def check_punished(self, mn):
        info = self.nodes[0].protx('info', mn.proTxHash)
        if info['state']['PoSePenalty'] > 0:
            return True
        return False

    def check_banned(self, mn):
        info = self.nodes[0].protx('info', mn.proTxHash)
        if info['state']['PoSeBanHeight'] != -1:
            return True
        return False

if __name__ == '__main__':
    LLMQSimplePoSeTest().main()
