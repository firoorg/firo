#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test RPC calls related to blockchain state. Tests correspond to code in
# rpc/blockchain.cpp.
#

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import (
    assert_equal,
    assert_raises,
    assert_is_hex_string,
    assert_is_hash_string,
    start_nodes,
    connect_nodes_bi,
)


class BlockchainTest(BitcoinTestFramework):
    """
    Test blockchain-related RPC calls:

        - gettxoutsetinfo
        - verifychain

    """

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = False
        self.num_nodes = 2

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        self._test_gettxoutsetinfo()
        self._test_getblockheader()
        self._test_getblock()
        self.nodes[0].verifychain(4, 0)

    def _test_gettxoutsetinfo(self):
        node = self.nodes[0]
        res = node.gettxoutsetinfo()

        assert_equal(res['total_amount'], Decimal('8725.00000000'))
        assert_equal(res['transactions'], 200)
        assert_equal(res['height'], 200)
        assert_equal(res['txouts'], 200)
        assert_equal(res['bestblock'], node.getblockhash(200))
        size = res['disk_size']
        assert size > 6400
        assert size < 64000
        assert_equal(len(res['bestblock']), 64)
        assert_equal(len(res['hash_serialized_2']), 64)

        self.log.info("Test that gettxoutsetinfo() works for blockchain with just the genesis block")
        b1hash = node.getblockhash(1)
        node.invalidateblock(b1hash)

        res2 = node.gettxoutsetinfo()
        assert_equal(res2['transactions'], 0)
        assert_equal(res2['total_amount'], Decimal('0'))
        assert_equal(res2['height'], 0)
        assert_equal(res2['txouts'], 0)
        assert_equal(res2['bestblock'], node.getblockhash(0))
        assert_equal(len(res2['hash_serialized_2']), 64)

        self.log.info("Test that gettxoutsetinfo() returns the same result after invalidate/reconsider block")
        node.reconsiderblock(b1hash)

        res3 = node.gettxoutsetinfo()
        assert_equal(res['total_amount'], res3['total_amount'])
        assert_equal(res['transactions'], res3['transactions'])
        assert_equal(res['height'], res3['height'])
        assert_equal(res['txouts'], res3['txouts'])
        assert_equal(res['bestblock'], res3['bestblock'])
        assert_equal(res['hash_serialized_2'], res3['hash_serialized_2'])

    def _test_getblockheader(self):
        node = self.nodes[0]

        assert_raises(
            JSONRPCException, lambda: node.getblockheader('nonsense'))

        besthash = node.getbestblockhash()
        secondbesthash = node.getblockhash(199)
        header = node.getblockheader(besthash)

        assert_equal(header['hash'], besthash)
        assert_equal(header['height'], 200)
        assert_equal(header['confirmations'], 1)
        assert_equal(header['previousblockhash'], secondbesthash)
        assert_is_hex_string(header['chainwork'])
        assert_is_hash_string(header['hash'])
        assert_is_hash_string(header['previousblockhash'])
        assert_is_hash_string(header['merkleroot'])
        assert_is_hash_string(header['bits'], length=None)
        assert isinstance(header['time'], int)
        assert isinstance(header['mediantime'], int)
        assert isinstance(header['nonce'], int)
        assert isinstance(header['version'], int)
        assert isinstance(int(header['versionHex'], 16), int)
        assert isinstance(header['difficulty'], Decimal)

    def _test_getblock(self):
        node = self.nodes[0]

        self.log.info("Test getblock with invalid block hash")
        assert_raises(
            JSONRPCException, lambda: node.getblock('nonsense'))

        besthash = node.getbestblockhash()

        # Test verbosity 0 (hex-encoded data)
        self.log.info("Test getblock verbosity 0 (hex-encoded data)")
        block_hex = node.getblock(besthash, 0)
        assert_is_hex_string(block_hex)

        # Test verbosity 1 (JSON with transaction ids - default)
        self.log.info("Test getblock verbosity 1 (JSON with tx ids)")
        block = node.getblock(besthash, 1)
        assert_equal(block['hash'], besthash)
        assert_equal(block['height'], 200)
        assert_equal(block['confirmations'], 1)
        assert 'tx' in block
        assert len(block['tx']) > 0
        # With verbosity 1, tx should be an array of txid strings
        assert isinstance(block['tx'][0], str)
        assert_is_hash_string(block['tx'][0])
        # Verify block-level chainlock is present
        assert 'chainlock' in block
        assert isinstance(block['chainlock'], bool)

        # Test default verbosity (should be same as verbosity 1)
        self.log.info("Test getblock default verbosity")
        block_default = node.getblock(besthash)
        assert_equal(block_default['hash'], besthash)
        assert isinstance(block_default['tx'][0], str)

        # Test verbosity 2 (JSON with full transaction details)
        self.log.info("Test getblock verbosity 2 (JSON with full tx details)")
        block_v2 = node.getblock(besthash, 2)
        assert_equal(block_v2['hash'], besthash)
        assert 'tx' in block_v2
        assert len(block_v2['tx']) > 0
        # With verbosity 2, tx should be an array of objects with transaction details
        tx = block_v2['tx'][0]
        assert isinstance(tx, dict)
        assert 'txid' in tx
        assert 'vin' in tx
        assert 'vout' in tx
        # Verify hex field is present (like Bitcoin's verbosity 2)
        assert 'hex' in tx
        assert_is_hex_string(tx['hex'])
        # Verify instantlock and chainlock fields are present in each transaction
        assert 'instantlock' in tx
        assert 'chainlock' in tx
        assert isinstance(tx['instantlock'], bool)
        assert isinstance(tx['chainlock'], bool)
        # Verify block-level chainlock is also present
        assert 'chainlock' in block_v2
        assert isinstance(block_v2['chainlock'], bool)

        # Test backwards compatibility with boolean (true = verbosity 1)
        self.log.info("Test getblock with boolean true (backwards compat)")
        block_true = node.getblock(besthash, True)
        assert_equal(block_true['hash'], besthash)
        assert isinstance(block_true['tx'][0], str)

        # Test backwards compatibility with boolean (false = verbosity 0)
        self.log.info("Test getblock with boolean false (backwards compat)")
        block_false = node.getblock(besthash, False)
        assert_is_hex_string(block_false)

        # Test invalid verbosity values
        self.log.info("Test getblock with invalid verbosity values")
        assert_raises(JSONRPCException, lambda: node.getblock(besthash, -1))
        assert_raises(JSONRPCException, lambda: node.getblock(besthash, 3))

if __name__ == '__main__':
    BlockchainTest().main()
