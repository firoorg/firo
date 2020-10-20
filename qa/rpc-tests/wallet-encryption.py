#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Copyright (c) 2020 The Zcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Wallet encryption"""

import re
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_jsonrpc,
    bitcoind_processes,
    start_nodes,
)

class WalletEncryptionTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True # lgtm [py/overwritten-inherited-attribute]
        self.num_nodes = 1 # lgtm [py/overwritten-inherited-attribute]

    def get_otp(self, address):
        # assume test on only 1 node
        try:
            self.nodes[0].dumpprivkey(address)
        except Exception as ex:
            found = re.search(
                'WARNING! Your one time authorization code is: (.+?)\n',
                ex.error['message'])
            if found:
                return found.group(1)

        raise Exception("Fail to get OTP")

    def run_test(self):
        passphrase = "WalletPassphrase"
        passphrase2 = "SecondWalletPassphrase"

        # Make sure the wallet isn't encrypted first
        address = self.nodes[0].getnewaddress()
        privkey = self.nodes[0].dumpprivkey(address, self.get_otp(address))

        assert_equal(privkey[:1], "c")
        assert_equal(len(privkey), 52)
        assert_raises_jsonrpc(-15, "Error: running with an unencrypted wallet, but walletpassphrase was called", self.nodes[0].walletpassphrase, 'ff', 1)
        assert_raises_jsonrpc(-15, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.", self.nodes[0].walletpassphrasechange, 'ff', 'ff')

        # Encrypt the wallet
        assert_raises_jsonrpc(-1, "encryptwallet <passphrase>\nEncrypts the wallet with <passphrase>.", self.nodes[0].encryptwallet, '')
        self.nodes[0].encryptwallet(passphrase)
        bitcoind_processes[0].wait()
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)

        # Test that the wallet is encrypted
        otp = self.get_otp(address)
        assert_raises_jsonrpc(-13, "Please enter the wallet passphrase with walletpassphrase first", self.nodes[0].dumpprivkey, address, otp)
        assert_raises_jsonrpc(-15, "Error: running with an encrypted wallet, but encryptwallet was called.", self.nodes[0].encryptwallet, 'ff')
        assert_raises_jsonrpc(-1, "walletpassphrase <passphrase> <timeout>\nStores the wallet decryption key in memory for <timeout> seconds.",
            self.nodes[0].walletpassphrase, '', 1)
        assert_raises_jsonrpc(-1, "walletpassphrasechange <oldpassphrase> <newpassphrase>\nChanges the wallet passphrase from <oldpassphrase> to <newpassphrase>.",
            self.nodes[0].walletpassphrasechange, '', 'ff')

        # Check that walletpassphrase works
        self.nodes[0].walletpassphrase(passphrase, 2)
        otp = self.get_otp(address)
        assert_equal(privkey, self.nodes[0].dumpprivkey(address, otp))

        # Check that the timeout is right
        time.sleep(3)
        otp = self.get_otp(address)
        assert_raises_jsonrpc(-13, "Please enter the wallet passphrase with walletpassphrase first", self.nodes[0].dumpprivkey, address, otp)

        # Test wrong passphrase
        assert_raises_jsonrpc(-14, "wallet passphrase entered was incorrect", self.nodes[0].walletpassphrase, passphrase + "wrong", 10)

        # Test walletlock
        self.nodes[0].walletpassphrase(passphrase, 84600)
        otp = self.get_otp(address)
        assert_equal(privkey, self.nodes[0].dumpprivkey(address, otp))
        self.nodes[0].walletlock()
        otp = self.get_otp(address)
        assert_raises_jsonrpc(-13, "Please enter the wallet passphrase with walletpassphrase first", self.nodes[0].dumpprivkey, address, otp)

        # Test passphrase changes
        self.nodes[0].walletpassphrasechange(passphrase, passphrase2)
        assert_raises_jsonrpc(-14, "wallet passphrase entered was incorrect", self.nodes[0].walletpassphrase, passphrase, 10)
        self.nodes[0].walletpassphrase(passphrase2, 10)
        otp = self.get_otp(address)
        assert_equal(privkey, self.nodes[0].dumpprivkey(address, otp))

if __name__ == '__main__':
    WalletEncryptionTest().main()
