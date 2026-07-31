#!/usr/bin/env python3
# Copyright (c) 2026 The Firo developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    bitcoind_processes,
    start_node,
    stop_node,
)


class WalletDatabaseFormatTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.start_attempt = 0

    def setup_network(self):
        self.nodes = []
        self.is_network_split = False

    def wallet_path(self, wallet_name):
        return os.path.join(
            self.options.tmpdir,
            "node0",
            "regtest",
            wallet_name)

    def debug_log_path(self):
        return os.path.join(
            self.options.tmpdir,
            "node0",
            "regtest",
            "debug.log")

    def attempt_start(self, extra_args):
        stderr_path = os.path.join(
            self.options.tmpdir,
            "node0",
            "startup-%d.stderr" % self.start_attempt)
        self.start_attempt += 1
        node = None
        failure = None
        return_code = None
        with open(stderr_path, "w", encoding="utf8") as stderr:
            try:
                node = start_node(
                    0,
                    self.options.tmpdir,
                    extra_args,
                    stderr=stderr)
            except Exception as exception:
                failure = exception
                process = bitcoind_processes.pop(0, None)
                if process is not None:
                    if process.poll() is None:
                        process.terminate()
                    return_code = process.wait(timeout=60)

        with open(stderr_path, "r", encoding="utf8") as stderr:
            output = stderr.read()

        if failure is not None:
            return False, "%s\n%s (exit status %s)" % (
                output,
                failure,
                return_code)

        self.nodes = [node]
        return True, output

    def start_wallet(self, extra_args):
        started, output = self.attempt_start(extra_args)
        if not started:
            raise AssertionError(
                "Wallet node failed to start unexpectedly:\n%s" % output)
        return self.nodes[0]

    def stop_wallet(self):
        stop_node(self.nodes[0], 0)
        self.nodes = []

    def assert_start_fails(self, extra_args, expected_error=None):
        started, output = self.attempt_start(extra_args)
        if started:
            self.stop_wallet()
            raise AssertionError("Wallet node unexpectedly started")
        if expected_error is not None and expected_error not in output:
            raise AssertionError(
                "Expected startup error was not reported:\n%s" % output)
        return output

    def assert_wallet_state(self, node, expected_format, address, account,
                            hd_master_key_id):
        wallet_info = node.getwalletinfo()
        assert_equal(wallet_info["format"], expected_format)
        assert_equal(wallet_info["hdmasterkeyid"], hd_master_key_id)
        assert address in node.getaddressesbyaccount(account)

    def sqlite_wallet_supported(self):
        started, output = self.attempt_start([
            "-wallet=sqlite-explicit-probe.dat",
            "-walletdbformat=sqlite",
        ])
        if not started:
            if "this build has SQLite wallet support disabled" in output:
                self.log.info(
                    "Skipping SQLite wallet lifecycle test in BDB-only build")
                return False
            raise AssertionError(
                "Explicit SQLite wallet creation failed:\n%s" % output)

        assert_equal(self.nodes[0].getwalletinfo()["format"], "sqlite")
        self.stop_wallet()
        return True

    def run_test(self):
        if os.name != "posix" or not self.sqlite_wallet_supported():
            return

        sqlite_wallet = "wallet-default-sqlite.dat"
        sqlite_account = "sqlite-persisted"
        node = self.start_wallet(["-wallet=" + sqlite_wallet])
        assert_equal(node.getwalletinfo()["format"], "sqlite")
        sqlite_address = node.getnewaddress(sqlite_account)
        sqlite_hd_master_key_id = node.getwalletinfo()["hdmasterkeyid"]
        self.stop_wallet()

        node = self.start_wallet([
            "-wallet=" + sqlite_wallet,
            "-walletdbformat=bdb",
        ])
        self.assert_wallet_state(
            node,
            "sqlite",
            sqlite_address,
            sqlite_account,
            sqlite_hd_master_key_id)
        self.stop_wallet()

        bdb_wallet = "wallet-explicit-bdb.dat"
        bdb_account = "bdb-persisted"
        node = self.start_wallet([
            "-wallet=" + bdb_wallet,
            "-walletdbformat=bdb",
        ])
        assert_equal(node.getwalletinfo()["format"], "bdb")
        bdb_address = node.getnewaddress(bdb_account)
        bdb_hd_master_key_id = node.getwalletinfo()["hdmasterkeyid"]
        self.stop_wallet()

        node = self.start_wallet([
            "-wallet=" + bdb_wallet,
            "-walletdbformat=sqlite",
        ])
        self.assert_wallet_state(
            node,
            "bdb",
            bdb_address,
            bdb_account,
            bdb_hd_master_key_id)
        self.stop_wallet()

        invalid_wallet = "wallet-invalid-selector.dat"
        self.assert_start_fails(
            [
                "-wallet=" + invalid_wallet,
                "-walletdbformat=invalid",
            ],
            "Invalid -walletdbformat value 'invalid'. "
            "Use 'sqlite' or 'bdb'.")
        assert not os.path.exists(self.wallet_path(invalid_wallet))

        empty_wallet = "wallet-empty-selector.dat"
        self.assert_start_fails(
            [
                "-wallet=" + empty_wallet,
                "-walletdbformat=",
            ],
            "Invalid -walletdbformat value ''. Use 'sqlite' or 'bdb'.")
        assert not os.path.exists(self.wallet_path(empty_wallet))

        failed_wallet = "wallet-failed-initialization.dat"
        self.assert_start_fails([
            "-wallet=" + failed_wallet,
            "-usemnemonic=1",
            "-mnemonicpassphrase=" + ("p" * 257),
        ])
        with open(self.debug_log_path(), "r", encoding="utf8") as debug_log:
            failed_start_log = debug_log.read()
        assert (
            "Using sqlite wallet database " + failed_wallet
            in failed_start_log)
        assert "Performing wallet upgrade" in failed_start_log
        failed_wallet_path = self.wallet_path(failed_wallet)
        assert not os.path.exists(failed_wallet_path)
        assert not os.path.exists(failed_wallet_path + "-journal")
        assert not os.path.exists(failed_wallet_path + "-wal")
        assert not os.path.exists(failed_wallet_path + "-shm")

        node = self.start_wallet(["-wallet=" + failed_wallet])
        assert_equal(node.getwalletinfo()["format"], "sqlite")
        failed_account = "failed-wallet-recreated"
        failed_address = node.getnewaddress(failed_account)
        failed_hd_master_key_id = node.getwalletinfo()["hdmasterkeyid"]
        self.stop_wallet()

        node = self.start_wallet([
            "-wallet=" + failed_wallet,
            "-walletdbformat=bdb",
        ])
        self.assert_wallet_state(
            node,
            "sqlite",
            failed_address,
            failed_account,
            failed_hd_master_key_id)
        self.stop_wallet()


if __name__ == "__main__":
    WalletDatabaseFormatTest().main()
