#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Base class for RPC testing

import logging
import optparse
import os
import sys
import shutil
import tempfile
import traceback
import unittest

from .util import (
    assert_equal,
    initialize_chain,
    start_nodes,
    connect_nodes_bi,
    sync_blocks,
    sync_mempools,
    stop_nodes,
    stop_node,
    enable_coverage,
    check_json_precision,
    initialize_chain_clean,
    PortSeed,
)
from .authproxy import JSONRPCException


class BitcoinTestFramework(object):

    def __init__(self):
        self.num_nodes = 4
        self.setup_clean_chain = False
        self.nodes = None
        self.set_test_params()

    # Methods to override in subclass test scripts.
    def set_test_params(self):
        """Tests must implement this method to change default values for number of nodes, topology, etc"""
        pass #raise NotImplementedError, do not raise an exception, as not all tests implement this.

    def run_test(self):
        raise NotImplementedError

    def add_options(self, parser):
        pass

    def setup_chain(self):
        print("Initializing test directory "+self.options.tmpdir)
        if self.setup_clean_chain:
            initialize_chain_clean(self.options.tmpdir, self.num_nodes)
        else:
            initialize_chain(self.options.tmpdir, self.num_nodes)

    def stop_node(self, num_node):
        stop_node(self.nodes[num_node], num_node)

    def setup_nodes(self):
        return start_nodes(self.num_nodes, self.options.tmpdir)

    def setup_network(self, split = False):
        self.nodes = self.setup_nodes()

        # Connect the nodes as a "chain".  This allows us
        # to split the network between nodes 1 and 2 to get
        # two halves that can work on competing chains.

        # If we joined network halves, connect the nodes from the joint
        # on outward.  This ensures that chains are properly reorganised.
        if not split:
            connect_nodes_bi(self.nodes, 1, 2)
            sync_blocks(self.nodes[1:3])
            sync_mempools(self.nodes[1:3])

        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 2, 3)
        self.is_network_split = split
        self.sync_all()

    def split_network(self):
        """
        Split the network of four nodes into nodes 0/1 and 2/3.
        """
        assert not self.is_network_split
        stop_nodes(self.nodes)
        self.setup_network(True)

    def sync_all(self):
        if self.is_network_split:
            sync_blocks(self.nodes[:2])
            sync_blocks(self.nodes[2:])
            sync_mempools(self.nodes[:2])
            sync_mempools(self.nodes[2:])
        else:
            sync_blocks(self.nodes)
            sync_mempools(self.nodes)

    def join_network(self):
        """
        Join the (previously split) network halves together.
        """
        assert self.is_network_split
        stop_nodes(self.nodes)
        self.setup_network(False)

    def main(self):

        parser = optparse.OptionParser(usage="%prog [options]")
        parser.add_option("--nocleanup", dest="nocleanup", default=False, action="store_true",
                          help="Leave bitcoinds and test.* datadir on exit or error")
        parser.add_option("--noshutdown", dest="noshutdown", default=False, action="store_true",
                          help="Don't stop bitcoinds after the test execution")
        parser.add_option("--srcdir", dest="srcdir", default=os.path.normpath(os.path.dirname(os.path.realpath(__file__))+"/../../../src"),
                          help="Source directory containing bitcoind/bitcoin-cli (default: %default)")
        parser.add_option("--tmpdir", dest="tmpdir", default=tempfile.mkdtemp(prefix="test"),
                          help="Root directory for datadirs")
        parser.add_option("--tracerpc", dest="trace_rpc", default=False, action="store_true",
                          help="Print out all RPC calls as they are made")
        parser.add_option("--portseed", dest="port_seed", default=os.getpid(), type='int',
                          help="The seed to use for assigning port numbers (default: current process id)")
        parser.add_option("--coveragedir", dest="coveragedir",
                          help="Write tested RPC commands into this directory")
        self.add_options(parser)
        (self.options, self.args) = parser.parse_args()

        # backup dir variable for removal at cleanup
        self.options.root, self.options.tmpdir = self.options.tmpdir, self.options.tmpdir + '/' + str(self.options.port_seed)

        if self.options.trace_rpc:
            logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

        if self.options.coveragedir:
            enable_coverage(self.options.coveragedir)

        PortSeed.n = self.options.port_seed

        os.environ['PATH'] = self.options.srcdir+":"+self.options.srcdir+"/qt:"+os.environ['PATH']

        check_json_precision()

        success = False
        try:
            os.makedirs(self.options.tmpdir, exist_ok=False)
            self.setup_chain()
            self.setup_network()
            self.run_test()
            success = True
        except JSONRPCException as e:
            print("JSONRPC error: "+e.error['message'])
            traceback.print_tb(sys.exc_info()[2])
        except AssertionError as e:
            print("Assertion failed: " + str(e))
            traceback.print_tb(sys.exc_info()[2])
        except KeyError as e:
            print("key not found: "+ str(e))
            traceback.print_tb(sys.exc_info()[2])
        except Exception as e:
            print("Unexpected exception caught during testing: " + repr(e))
            traceback.print_tb(sys.exc_info()[2])
        except KeyboardInterrupt as e:
            print("Exiting after " + repr(e))

        if not self.options.noshutdown:
            print("Stopping nodes")
            stop_nodes(self.nodes)
        else:
            print("Note: bitcoinds were not stopped and may still be running")

        if not self.options.nocleanup and not self.options.noshutdown and success:
            print("Cleaning up")
            shutil.rmtree(self.options.tmpdir)
            if not os.listdir(self.options.root):
                os.rmdir(self.options.root)
        else:
            print("Not cleaning up dir %s" % self.options.tmpdir)

        if success:
            print("Tests successful")
            sys.exit(0)
        else:
            print("Failed")
            sys.exit(1)


# Test framework for doing p2p comparison testing, which sets up some bitcoind
# binaries:
# 1 binary: test binary
# 2 binaries: 1 test binary, 1 ref binary
# n>2 binaries: 1 test binary, n-1 ref binaries

class ComparisonTestFramework(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True

    def add_options(self, parser):
        parser.add_option("--testbinary", dest="testbinary",
                          default=os.getenv("ZCOIND", "zcoind"),
                          help="bitcoind binary to test")
        parser.add_option("--refbinary", dest="refbinary",
                          default=os.getenv("ZCOIND", "zcoind"),
                          help="bitcoind binary to use for reference nodes (if any)")

    def setup_network(self):
        self.nodes = start_nodes(
            self.num_nodes, self.options.tmpdir,
            extra_args=[['-debug', '-whitelist=127.0.0.1']] * self.num_nodes,
            binary=[self.options.testbinary] +
            [self.options.refbinary]*(self.num_nodes-1))

class ElysiumTestFramework(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.addrs = []

    def run_test(self):
        for rpc in self.nodes:
            addr = rpc.getnewaddress()
            rpc.sendtoaddress(addr, 500)
            self.addrs.append(addr)

        self.nodes[0].generate(1)
        self.sync_all()

    def setup_nodes(self):
        return start_nodes(self.num_nodes, self.options.tmpdir, [['-elysium'] for _ in range(self.num_nodes)])

    def assert_property_summary(self, prop, id, divisible, cat, subcat, name, url, data):
        assert_equal(prop['propertyid'], id)
        assert_equal(prop['name'], name)
        assert_equal(prop['category'], cat)
        assert_equal(prop['subcategory'], subcat)
        assert_equal(prop['data'], data)
        assert_equal(prop['url'], url)
        assert_equal(prop['divisible'], divisible)

    def assert_property_info(self, prop, id, fixed, issuer, divisible, cat, subcat, name, url, data, tokens, sigma, createtx, denoms):
        assert_equal(prop['propertyid'], id)
        assert_equal(prop['name'], name)
        assert_equal(prop['category'], cat)
        assert_equal(prop['subcategory'], subcat)
        assert_equal(prop['data'], data)
        assert_equal(prop['url'], url)
        assert_equal(prop['divisible'], divisible)
        assert_equal(prop['issuer'], issuer)
        assert_equal(prop['creationtxid'], createtx)
        assert_equal(prop['fixedissuance'], fixed)
        assert_equal(prop['managedissuance'], not fixed)
        assert_equal(prop['totaltokens'], tokens)
        assert_equal(prop['sigmastatus'], sigma)
        assert_equal(len(prop['denominations']), len(denoms))

        for i in range(len(denoms)):
            assert_equal(prop['denominations'][i]['id'], denoms[i]['id'])
            assert_equal(prop['denominations'][i]['value'], denoms[i]['value'])

    def compare_mints(self, expected, actual):
        mint_key_extractor = lambda m : (m['propertyid'], m['denomination'], m['value'])
        expected.sort(key = mint_key_extractor)
        actual.sort(key = mint_key_extractor)

        assert_equal(expected, actual)

    def generate_until_sigma_activated(self, node):
        self.sync_all()
        required_block = 550
        current_block = self.nodes[0].getblockcount()
        if current_block >= required_block:
            return []

        return node.generate(required_block - current_block)

    def create_default_property(self, name, node, address, sigma = True, amount = None):
        sigma_status = 1 if sigma else 0

        if amount is None:
            node.elysium_sendissuancemanaged(address, 1, 1, 0, '', '', name, '', '', sigma_status)
        else:
            node.elysium_sendissuancefixed(address, 1, 1, 0, '', '', name, '', '', amount, sigma_status)

        node.generate(1)
        self.sync_all()

        # get lastest id
        properties = self.nodes[0].elysium_listproperties()
        return max(map(lambda p: p["propertyid"], properties))
