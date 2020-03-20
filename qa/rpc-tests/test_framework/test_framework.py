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
import time

from .util import (
    assert_equal,
    initialize_chain,
    start_nodes,
    connect_nodes_bi,
    sync_blocks,
    sync_mempools,
    sync_znodes,
    stop_nodes,
    stop_node,
    start_node,
    enable_coverage,
    check_json_precision,
    initialize_chain_clean,
    PortSeed,
    p2p_port,
    connect_nodes,
    wait_to_sync_znodes
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
            initialize_chain(self.options.tmpdir, self.num_nodes, self.options.cachedir)

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

        if self.num_nodes > 1:
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

    def znsync_all(self):
        if self.is_network_split:
            sync_znodes(self.nodes[:2])
            sync_znodes(self.nodes[2:])
        else:
            sync_znodes(self.nodes)

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
        parser.add_option("--cachedir", dest="cachedir", default="",
                          help="Directory for caching pregenerated datadirs")
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

        if self.options.cachedir == "":
            self.options.cachedir = self.options.tmpdir

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
            if os.getenv("PYTHON_DEBUG", ""):
                # Dump the end of the debug logs, to aid in debugging rare
                # travis failures.
                import glob
                filenames = glob.glob(self.options.tmpdir + "/node*/regtest/debug.log")
                MAX_LINES_TO_PRINT = 1000
                for f in filenames:
                    print("From" , f, ":")
                    from collections import deque
                    print("".join(deque(open(f), MAX_LINES_TO_PRINT)))
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

class ExodusTestFramework(BitcoinTestFramework):
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
        return start_nodes(self.num_nodes, self.options.tmpdir, [['-exodus'] for _ in range(self.num_nodes)])

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

#
# Znode tests support
#

ZNODE_COLLATERAL = 1000

class ZnodeCollateral(object):
    def __init__(self):
        self.tx_id = None
        self.n = -1

    def __str__(self):
        return self.tx_id + ": " + str(self.n)

    def parse_collateral_output(self, target_address, tx_text, tx_id):
        for vout in tx_text["vout"]:
            if vout["value"] == ZNODE_COLLATERAL and vout["scriptPubKey"]["addresses"] == [target_address]:
                self.tx_id = tx_id
                self.n = vout["n"]
        return self

class ZnodeTestFramework(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.znode_priv_keys = dict()
        self.num_nodes = 4
        self.num_znodes = 3

    def setup_chain(self):
        print("Initializing test directory "+self.options.tmpdir)
        self.setup_clean_chain = True
        super().setup_chain()

    def setup_network(self, split=False):
        super().setup_network(split)
        for i in range(self.num_nodes):
            for j in range(i, self.num_nodes):
                connect_nodes_bi(self.nodes, i, j)

    def write_master_znode_conf(self, znode, collateral):
        znode_service = get_znode_service(znode)
        znode_conf = " ".join(["zn"+str(znode), znode_service, self.znode_priv_keys[znode], collateral.tx_id, str(collateral.n)])

        master_node_conf_filename = os.path.join(self.options.tmpdir, "node" + str(znode), "regtest", "znode.conf")
        with open(master_node_conf_filename, "a") as master_node_conf:
            master_node_conf.write(znode_conf)
            master_node_conf.write("\n")
            master_node_conf.close()

    def generate_znode_collateral(self, generator_node=None):
        if generator_node is None:
            generator_node = self.num_nodes - 1
        curr_balance = self.nodes[generator_node].getbalance()
        while curr_balance < ZNODE_COLLATERAL:
            self.nodes[generator_node].generate(int((ZNODE_COLLATERAL - curr_balance) / 25))
            curr_balance = self.nodes[generator_node].getbalance()
        return curr_balance

    def send_znode_collateral(self, znode, collateral_provider=None):
        if collateral_provider is None:
            collateral_provider = self.num_nodes - 1
        znode_address = self.nodes[znode].getaccountaddress("Znode")
        tx_id = self.nodes[collateral_provider].sendtoaddress(znode_address, ZNODE_COLLATERAL)
        tx_text = self.nodes[collateral_provider].getrawtransaction(tx_id, 1)
        collateral = ZnodeCollateral()
        return collateral.parse_collateral_output(znode_address, tx_text, tx_id)

    def send_mature_znode_collateral(self, znode, collateral_provider=None):
        if collateral_provider is None:
            collateral_provider = self.num_nodes - 1
        result = self.send_znode_collateral(znode, collateral_provider)
        self.nodes[collateral_provider].generate(10)
        sync_blocks(self.nodes)
        time.sleep(3)
        return result

    def configure_znode(self, znode, master_znode=None):
        if master_znode is None:
            master_znode = self.num_nodes - 1
        self.znode_priv_keys[znode] = self.nodes[znode].znode("genkey")
        stop_node(self.nodes[znode], znode)
        znode_service = get_znode_service(znode)
        self.nodes[znode] = start_node(znode, self.options.tmpdir, ["-znode", "-znodeprivkey="+self.znode_priv_keys[znode], "-externalip="+znode_service, "-listen"])
        connect_nodes(self.nodes[znode], znode)
        for i in range(self.num_nodes):
            if i != znode:
                connect_nodes_bi(self.nodes, i, znode)

    def generate_znode_privkey(self, znode):
        self.znode_priv_keys[znode] = self.nodes[znode].znode("genkey")

    def restart_as_znode(self, znode):
        stop_node(self.nodes[znode], znode)
        znode_service = get_znode_service(znode)
        self.nodes[znode] = start_node(znode, self.options.tmpdir, ["-znode", "-znodeprivkey="+self.znode_priv_keys[znode], "-externalip="+znode_service, "-listen"])
        connect_nodes(self.nodes[znode], znode)
        for i in range(self.num_nodes):
            if i != znode:
                connect_nodes_bi(self.nodes, i, znode)
        for i in range(self.num_nodes):
            wait_to_sync_znodes(self.nodes[i])

    def znode_start(self, znode):
        assert_equal("Znode successfully started", self.nodes[znode].znode("start"))

    def configure_znode(self, znode, master_znode=None ):
        self.generate_znode_privkey(znode, master_znode)
        self.restart_as_znode(znode)

    def wait_znode_enabled(self, enabled_znode_number, znode_to_wait_on = None, timeout = 10):
        if znode_to_wait_on is None:
            znode_to_wait_on = self.num_nodes - 1
        wait_to_sync_znodes(self.nodes[znode_to_wait_on])
        for j in range (timeout):
            if self.nodes[znode_to_wait_on].znode("count", "enabled") == enabled_znode_number:
                return
            time.sleep(1)
        raise Exception("Cannot wait until znodes enabled")

    def generate(self, blocks, generator_node=None):
        if generator_node is None:
            generator_node = self.num_nodes - 1
        for b in range(blocks):
            self.nodes[generator_node].generate(1)
            sync_blocks(self.nodes)
            time.sleep(1)


def get_znode_service(znode):
    znode_ip_str = "127.0.1." + str(znode + 1)
    znode_port_str = str(p2p_port(znode))
    return znode_ip_str + ":" + znode_port_str

