#!/usr/bin/env python3
# Copyright (c) 2026 The Firo developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import os
import platform
import re
import shutil
import stat

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_jsonrpc,
    bitcoind_processes,
    start_node,
    stop_node,
    wait_node,
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

    def file_sha256(self, path):
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def wallet_database_state(self, wallet_name):
        path = self.wallet_path(wallet_name)
        state = []
        for suffix in ("", "-journal", "-wal", "-shm"):
            entry = path + suffix
            if not os.path.lexists(entry):
                state.append(None)
                continue
            metadata = os.lstat(entry)
            state.append((
                stat.S_IFMT(metadata.st_mode),
                metadata.st_size,
                self.file_sha256(entry)
                if stat.S_ISREG(metadata.st_mode)
                else None,
            ))
        return tuple(state)

    def read_debug_log_from(self, offset):
        with open(self.debug_log_path(), "r", encoding="utf8") as debug_log:
            debug_log.seek(offset)
            return debug_log.read()

    def migration_backup_path(self, log, wallet_name):
        message = (
            "Wallet database migration succeeded for '%s'; "
            "Berkeley DB backup retained at '" % wallet_name)
        matches = re.findall(
            re.escape(message) + r"([^'\r\n]+)'\.",
            log)
        assert_equal(len(matches), 1)
        backup_path = matches[0]
        assert os.path.isabs(backup_path)
        return os.path.normpath(backup_path)

    def migration_artifacts(self):
        wallet_directory = os.path.join(
            self.options.tmpdir,
            "node0",
            "regtest")
        return sorted(
            entry
            for entry in os.listdir(wallet_directory)
            if entry.startswith(".firo-wallet-"))

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

    def create_rap_state(self, node, label):
        rap_address = node.createrapaddress(label)
        state = node.listrapaddresses(True)
        matches = [
            entry
            for entry in state
            if entry.get("MyRAPaddr") == rap_address
        ]
        assert_equal(len(matches), 1)
        assert_equal(matches[0]["Label"], label)
        assert matches[0]["NotificationAddr"]
        return state

    def sqlite_wallet_supported(self):
        started, output = self.attempt_start([
            "-wallet=sqlite-explicit-probe.dat",
            "-walletdbformat=sqlite",
        ])
        if not started:
            if "this build has SQLite wallet support disabled" in output:
                assert not os.path.exists(
                    self.wallet_path("sqlite-explicit-probe.dat"))
                self.log.info(
                    "Skipping SQLite wallet lifecycle test in BDB-only build")
                return False
            raise AssertionError(
                "Explicit SQLite wallet creation failed:\n%s" % output)

        assert_equal(self.nodes[0].getwalletinfo()["format"], "sqlite")
        self.stop_wallet()
        return True

    def exercise_backup_restore(self, wallet_format):
        wallet_name = "wallet-backup-%s.dat" % wallet_format
        restored_name = "wallet-backup-%s-restored.dat" % wallet_format
        account = "backup-%s-before" % wallet_format
        post_backup_account = "backup-%s-after" % wallet_format
        restored_account = "backup-%s-restored-write" % wallet_format
        passphrase = "backup-%s-passphrase" % wallet_format
        message = "wallet backup private-key check"
        backup_directory = os.path.join(
            self.options.tmpdir,
            "wallet-backup-%s" % wallet_format)
        backup_path = os.path.join(
            backup_directory,
            "wallet.snapshot")
        restored_path = self.wallet_path(restored_name)

        assert not os.path.lexists(backup_directory)
        os.mkdir(backup_directory, 0o700)
        for path in (backup_path, restored_path):
            for suffix in ("", "-journal", "-wal", "-shm"):
                assert not os.path.lexists(path + suffix)

        node = self.start_wallet([
            "-wallet=" + wallet_name,
            "-walletdbformat=" + wallet_format,
        ])
        assert_equal(
            node.getwalletinfo()["format"],
            wallet_format)
        address = node.getnewaddress(account)
        rap_state = self.create_rap_state(
            node,
            "backup-%s-bip47" % wallet_format)
        hd_master_key_id = node.getwalletinfo()["hdmasterkeyid"]
        node.encryptwallet(passphrase)
        wait_node(0)
        self.nodes = []

        node = self.start_wallet([
            "-wallet=" + wallet_name,
        ])
        self.assert_wallet_state(
            node,
            wallet_format,
            address,
            account,
            hd_master_key_id)
        assert_equal(
            node.listrapaddresses(True),
            rap_state)
        assert_raises_jsonrpc(
            -13,
            "Please enter the wallet passphrase with walletpassphrase first",
            node.signmessage,
            address,
            message)
        node.backupwallet(backup_path)

        backup_stat = os.lstat(backup_path)
        assert stat.S_ISREG(backup_stat.st_mode)
        backup_hash = self.file_sha256(backup_path)
        if wallet_format == "sqlite":
            assert_equal(backup_stat.st_uid, os.geteuid())
            assert_equal(backup_stat.st_nlink, 1)
            assert_equal(
                stat.S_IMODE(backup_stat.st_mode),
                0o600)
            for suffix in ("-journal", "-wal", "-shm"):
                assert not os.path.lexists(backup_path + suffix)

        node.walletpassphrase(passphrase, 120)
        signature = node.signmessage(address, message)
        assert node.verifymessage(
            address,
            signature,
            message)
        post_backup_address = node.getnewaddress(
            post_backup_account)
        node.walletlock()

        if wallet_format == "sqlite":
            entries_before_collision = set(
                os.listdir(backup_directory))
            expected_error = (
                "Failed to back up SQLite wallet '%s' to '%s': "
                "the destination path already exists. Choose a new absent "
                "destination; SQLite wallet backups never overwrite an "
                "existing path." % (wallet_name, backup_path))
            assert_raises_jsonrpc(
                -4,
                expected_error,
                node.backupwallet,
                backup_path)
            collision_stat = os.lstat(backup_path)
            assert_equal(
                collision_stat.st_dev,
                backup_stat.st_dev)
            assert_equal(
                collision_stat.st_ino,
                backup_stat.st_ino)
            assert_equal(
                collision_stat.st_nlink,
                backup_stat.st_nlink)
            assert_equal(
                stat.S_IMODE(collision_stat.st_mode),
                stat.S_IMODE(backup_stat.st_mode))
            assert_equal(
                self.file_sha256(backup_path),
                backup_hash)
            for suffix in ("-journal", "-wal", "-shm"):
                assert not os.path.lexists(backup_path + suffix)
            assert_equal(
                set(os.listdir(backup_directory)),
                entries_before_collision)
        else:
            node.backupwallet(backup_path)

        self.stop_wallet()

        shutil.copy2(backup_path, restored_path)
        copied_stat = os.lstat(restored_path)
        current_backup_stat = os.lstat(backup_path)
        assert_equal(
            stat.S_IMODE(copied_stat.st_mode),
            stat.S_IMODE(current_backup_stat.st_mode))
        if wallet_format == "sqlite":
            assert_equal(copied_stat.st_uid, os.geteuid())
            assert_equal(copied_stat.st_nlink, 1)
            assert_equal(
                stat.S_IMODE(copied_stat.st_mode),
                0o600)
        for suffix in ("-journal", "-wal", "-shm"):
            assert not os.path.lexists(restored_path + suffix)

        node = self.start_wallet([
            "-wallet=" + restored_name,
        ])
        self.assert_wallet_state(
            node,
            wallet_format,
            address,
            account,
            hd_master_key_id)
        assert_equal(
            node.listrapaddresses(True),
            rap_state)
        assert_raises_jsonrpc(
            -13,
            "Please enter the wallet passphrase with walletpassphrase first",
            node.signmessage,
            address,
            message)
        post_backup_addresses = node.getaddressesbyaccount(
            post_backup_account)
        if wallet_format == "sqlite":
            assert post_backup_address not in post_backup_addresses
        else:
            assert post_backup_address in post_backup_addresses
        node.walletpassphrase(passphrase, 120)
        restored_signature = node.signmessage(
            address,
            message)
        assert node.verifymessage(
            address,
            restored_signature,
            message)
        restored_address = node.getnewaddress(
            restored_account)
        self.stop_wallet()

        node = self.start_wallet([
            "-wallet=" + restored_name,
        ])
        self.assert_wallet_state(
            node,
            wallet_format,
            restored_address,
            restored_account,
            hd_master_key_id)
        assert_equal(
            node.listrapaddresses(True),
            rap_state)
        self.stop_wallet()

    def run_test(self):
        if (
            os.name != "posix"
            or platform.system() not in ("Linux", "Darwin")
        ):
            return

        if not self.sqlite_wallet_supported():
            self.exercise_backup_restore("bdb")
            bdb_only_wallet = "wallet-bdb-only-migration.dat"
            node = self.start_wallet([
                "-wallet=" + bdb_only_wallet,
                "-walletdbformat=bdb",
            ])
            assert_equal(node.getwalletinfo()["format"], "bdb")
            node.getnewaddress("bdb-only-preserved")
            self.stop_wallet()

            bdb_only_state = self.wallet_database_state(
                bdb_only_wallet)
            artifacts = self.migration_artifacts()
            self.assert_start_fails(
                [
                    "-wallet=" + bdb_only_wallet,
                    "-migratewalletdb",
                ],
                "this build has SQLite wallet support disabled")
            assert_equal(
                self.wallet_database_state(bdb_only_wallet),
                bdb_only_state)
            assert_equal(self.migration_artifacts(), artifacts)
            return

        self.exercise_backup_restore("sqlite")
        self.exercise_backup_restore("bdb")

        missing_wallet = "wallet-migration-missing.dat"
        missing_state = self.wallet_database_state(
            missing_wallet)
        assert all(entry is None for entry in missing_state)
        artifacts = self.migration_artifacts()
        self.assert_start_fails(
            [
                "-wallet=" + missing_wallet,
                "-migratewalletdb",
            ],
            "the BDB source does not exist")
        assert_equal(
            self.wallet_database_state(missing_wallet),
            missing_state)
        assert_equal(self.migration_artifacts(), artifacts)

        sqlite_wallet = "wallet-default-sqlite.dat"
        sqlite_account = "sqlite-persisted"
        node = self.start_wallet(["-wallet=" + sqlite_wallet])
        assert_equal(node.getwalletinfo()["format"], "sqlite")
        sqlite_address = node.getnewaddress(sqlite_account)
        sqlite_rap_state = self.create_rap_state(
            node,
            "sqlite-bip47-persisted")
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
        assert_equal(
            node.listrapaddresses(True),
            sqlite_rap_state)
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
        bdb_spark_default_address = node.getsparkdefaultaddress()[0]
        bdb_rap_state = self.create_rap_state(
            node,
            "bip47-before-migration")
        node.generate(101)
        pre_migration_txid = node.sendtoaddress(bdb_address, 1)
        node.generate(1)
        assert_equal(
            node.gettransaction(pre_migration_txid)["confirmations"],
            1)
        migration_passphrase = "bdb-migration-passphrase"
        migration_message = "migration locked-wallet check"
        node.encryptwallet(migration_passphrase)
        wait_node(0)
        self.nodes = []

        node = self.start_wallet(["-wallet=" + bdb_wallet])
        self.assert_wallet_state(
            node,
            "bdb",
            bdb_address,
            bdb_account,
            bdb_hd_master_key_id)
        assert_equal(
            node.listrapaddresses(True),
            bdb_rap_state)
        assert_raises_jsonrpc(
            -13,
            "Please enter the wallet passphrase with walletpassphrase first",
            node.signmessage,
            bdb_address,
            migration_message)
        assert node.gettransaction(pre_migration_txid)["confirmations"] >= 1
        assert_equal(
            node.getsparkdefaultaddress()[0],
            bdb_spark_default_address)
        self.stop_wallet()

        bdb_wallet_path = self.wallet_path(bdb_wallet)
        bdb_wallet_state = self.wallet_database_state(
            bdb_wallet)
        migration_conflicts = [
            (
                ["-disablewallet"],
                "-migratewalletdb cannot be used with -disablewallet."),
            (
                ["-salvagewallet"],
                "-migratewalletdb cannot be combined with -salvagewallet."),
            (
                ["-walletdbformat=bdb"],
                "-migratewalletdb cannot be combined with -walletdbformat."),
            (
                ["-zapwalletmints"],
                "-migratewalletdb cannot be combined with wallet zap options."),
            (
                ["-zapwallettxes=1"],
                "-migratewalletdb cannot be combined with wallet zap options."),
            (
                ["-upgradewallet"],
                "-migratewalletdb cannot be combined with -upgradewallet."),
        ]
        for conflict_args, expected_error in migration_conflicts:
            artifacts = self.migration_artifacts()
            self.assert_start_fails(
                [
                    "-wallet=" + bdb_wallet,
                    "-migratewalletdb",
                ] + conflict_args,
                expected_error)
            assert_equal(
                self.wallet_database_state(bdb_wallet),
                bdb_wallet_state)
            assert_equal(self.migration_artifacts(), artifacts)

        unsafe_ancestor = os.path.dirname(
            os.path.dirname(bdb_wallet_path))
        original_ancestor_mode = stat.S_IMODE(
            os.lstat(unsafe_ancestor).st_mode)
        artifacts = self.migration_artifacts()
        try:
            os.chmod(
                unsafe_ancestor,
                (original_ancestor_mode | 0o022) &
                ~stat.S_ISVTX)
            self.assert_start_fails(
                [
                    "-wallet=" + bdb_wallet,
                    "-migratewalletdb",
                ],
                "writable by group or other without trusted "
                "sticky-directory protection")
            assert_equal(
                self.wallet_database_state(bdb_wallet),
                bdb_wallet_state)
            assert_equal(self.migration_artifacts(), artifacts)
        finally:
            os.chmod(
                unsafe_ancestor,
                original_ancestor_mode)

        migration_log_offset = os.path.getsize(self.debug_log_path())
        node = self.start_wallet([
            "-wallet=" + bdb_wallet,
            "-migratewalletdb",
        ])
        self.assert_wallet_state(
            node,
            "sqlite",
            bdb_address,
            bdb_account,
            bdb_hd_master_key_id)
        assert_equal(
            node.listrapaddresses(True),
            bdb_rap_state)
        assert node.gettransaction(pre_migration_txid)["confirmations"] >= 1
        assert_equal(
            node.getsparkdefaultaddress()[0],
            bdb_spark_default_address)
        assert_raises_jsonrpc(
            -13,
            "walletpassphrase",
            node.sendtoaddress,
            bdb_address,
            1)
        node.walletpassphrase(migration_passphrase, 120)
        migrated_account = "bdb-migrated-write"
        migrated_address = node.getnewaddress(migrated_account)
        post_migration_txid = node.sendtoaddress(migrated_address, 1)
        node.generate(1)
        assert_equal(
            node.gettransaction(post_migration_txid)["confirmations"],
            1)
        self.stop_wallet()

        migration_log = self.read_debug_log_from(migration_log_offset)
        backup_path = self.migration_backup_path(
            migration_log,
            bdb_wallet)
        assert_equal(
            os.path.dirname(backup_path),
            os.path.dirname(bdb_wallet_path))
        assert not os.path.samefile(backup_path, bdb_wallet_path)
        backup_stat = os.lstat(backup_path)
        assert stat.S_ISREG(backup_stat.st_mode)
        assert_equal(stat.S_IMODE(backup_stat.st_mode), 0o600)

        node = self.start_wallet(["-wallet=" + bdb_wallet])
        self.assert_wallet_state(
            node,
            "sqlite",
            bdb_address,
            bdb_account,
            bdb_hd_master_key_id)
        self.assert_wallet_state(
            node,
            "sqlite",
            migrated_address,
            migrated_account,
            bdb_hd_master_key_id)
        assert_equal(
            node.listrapaddresses(True),
            bdb_rap_state)
        assert_raises_jsonrpc(
            -13,
            "Please enter the wallet passphrase with walletpassphrase first",
            node.signmessage,
            bdb_address,
            migration_message)
        assert node.gettransaction(pre_migration_txid)["confirmations"] >= 1
        assert node.gettransaction(post_migration_txid)["confirmations"] >= 1
        assert_equal(
            node.getsparkdefaultaddress()[0],
            bdb_spark_default_address)
        restarted_account = "bdb-restarted-write"
        restarted_address = node.getnewaddress(restarted_account)
        node.walletpassphrase(migration_passphrase, 120)
        migrated_rap_state = self.create_rap_state(
            node,
            "bip47-after-migrated-restart")
        self.stop_wallet()

        node = self.start_wallet(["-wallet=" + bdb_wallet])
        self.assert_wallet_state(
            node,
            "sqlite",
            restarted_address,
            restarted_account,
            bdb_hd_master_key_id)
        assert_equal(
            node.listrapaddresses(True),
            migrated_rap_state)
        assert_raises_jsonrpc(
            -13,
            "Please enter the wallet passphrase with walletpassphrase first",
            node.signmessage,
            bdb_address,
            migration_message)
        assert node.gettransaction(pre_migration_txid)["confirmations"] >= 1
        assert node.gettransaction(post_migration_txid)["confirmations"] >= 1
        assert_equal(
            node.getsparkdefaultaddress()[0],
            bdb_spark_default_address)
        self.stop_wallet()

        migrated_wallet_state = self.wallet_database_state(
            bdb_wallet)
        backup_hash = self.file_sha256(backup_path)
        artifacts = self.migration_artifacts()
        self.assert_start_fails(
            [
                "-wallet=" + bdb_wallet,
                "-migratewalletdb",
            ],
            "already uses SQLite; remove -migratewalletdb")
        assert_equal(
            self.wallet_database_state(bdb_wallet),
            migrated_wallet_state)
        assert_equal(self.file_sha256(backup_path), backup_hash)
        assert_equal(self.migration_artifacts(), artifacts)

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
        failed_start_offset = os.path.getsize(self.debug_log_path())
        self.assert_start_fails([
            "-wallet=" + failed_wallet,
            "-usemnemonic=1",
            "-mnemonicpassphrase=" + ("p" * 257),
        ])
        failed_start_log = self.read_debug_log_from(failed_start_offset)
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
