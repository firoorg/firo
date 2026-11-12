#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test -reindex and -reindex-chainstate with CheckBlockIndex
#
import os

from test_framework.mininode import wait_until
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    start_nodes,
    stop_nodes,
    assert_equal,
)

class ReindexTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)

    def reindex(self, justchainstate=False, out_of_order=False):
        self.nodes[0].generate(3)
        blockcount = self.nodes[0].getblockcount()
        block_hashes = [self.nodes[0].getblockhash(height) for height in range(1, blockcount + 1)]
        utxo_hash = self.nodes[0].gettxoutsetinfo()['hash_serialized_2']
        if out_of_order:
            hashes = [self.nodes[0].getblockhash(0)] + block_hashes
            blocks = [bytes.fromhex(self.nodes[0].getblock(block_hash, 0)) for block_hash in hashes]
        stop_nodes(self.nodes)
        if out_of_order:
            block_path = os.path.join(self.options.tmpdir, 'node0', 'regtest', 'blocks', 'blk00000.dat')
            with open(block_path, 'r+b') as block_file:
                magic = block_file.read(4)
                block_file.seek(0)
                # Queue the last block before its parent, then import a duplicate
                # after it has been accepted recursively but is not connected yet.
                for block in blocks[:-2] + [blocks[-1], blocks[-2], blocks[-1]]:
                    block_file.write(magic + len(block).to_bytes(4, 'little') + block)
                block_file.truncate()
        log_path = os.path.join(self.options.tmpdir, 'node0', 'regtest', 'debug.log')
        log_offset = os.path.getsize(log_path)
        extra_args = [["-debug=validation", "-reindex-chainstate" if justchainstate else "-reindex", "-checkblockindex=1"]]
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, extra_args)
        assert_equal(wait_until(lambda: self.nodes[0].getblockcount() >= blockcount, timeout=60), True)
        assert_equal(self.nodes[0].getblockcount(), blockcount)
        assert_equal(self.nodes[0].getbestblockhash(), block_hashes[-1])
        assert_equal(self.nodes[0].gettxoutsetinfo()['hash_serialized_2'], utxo_hash)

        with open(log_path, encoding='utf-8') as log_file:
            log_file.seek(log_offset)
            log = log_file.read()
        # Imports reuse AcceptBlock's checked block; chainstate replay checks the
        # block loaded by ConnectTip. Neither should repeat these checks.
        for height, block_hash in enumerate(block_hashes, start=1):
            check = 'CheckBlock() nHeight={}, blockHash={}, isVerifyDB=0'.format(height, block_hash)
            # The known duplicate uses the disk fallback, so the last block is
            # checked again when connected after recursive acceptance.
            expected_checks = 2 if out_of_order and height == blockcount else 1
            assert_equal(log.count(check), expected_checks)
        print("Success")

    def run_test(self):
        self.reindex(False)
        self.reindex(True)
        self.reindex(False)
        self.reindex(True)
        self.reindex(out_of_order=True)

if __name__ == '__main__':
    ReindexTest().main()
