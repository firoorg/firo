// Copyright (c) 2020 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "test/test_bitcoin.h"
#include "test/fixtures.h"

#include "key.h"
#include "utilstrencodings.h"
#include "bip47/paymentaddress.h"
#include "bip47/utils.h"

using namespace bip47;

// Implements the test cases here: https://gist.github.com/SamouraiDev/6aad669604c5930864bd
BOOST_FIXTURE_TEST_SUITE(bip47_basic_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(payment_codes)
{
    std::vector<std::vector<unsigned char>> bip32seeds = {
        ParseHex("64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a"),
        ParseHex("87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110")
    };

    std::vector<std::string> paymentcodes = {
        "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA",
        "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97"
    };

    for(size_t i = 0; i < bip32seeds.size(); ++i) {
        CExtKey key;
        key.SetMaster(&bip32seeds[i][0], bip32seeds[i].size());

        CExtPubKey pubkey = utils::derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT}).Neuter();

        bip47::CPaymentCode paymentCode({pubkey.pubkey.begin(), pubkey.pubkey.end()}, {pubkey.chaincode.begin(), pubkey.chaincode.end()});
        BOOST_CHECK_EQUAL(paymentCode.toString(), paymentcodes[i]);
    }
}

BOOST_AUTO_TEST_SUITE_END()