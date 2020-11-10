// Copyright (c) 2020 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// An implementation of bip47 tests here: https://gist.github.com/SamouraiDev/6aad669604c5930864bd

#include <boost/test/unit_test.hpp>

#include "test/test_bitcoin.h"
#include "test/fixtures.h"

#include "key.h"
#include "utilstrencodings.h"
#include "bip47/paymentaddress.h"
#include "bip47/utils.h"
#include "bip47/secretpoint.h"

using namespace bip47;

namespace {
namespace alice {
std::vector<unsigned char> const bip32seed = ParseHex("64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a");
std::string const paymentcode = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";
}
namespace bob {
std::vector<unsigned char> const bip32seed = ParseHex("87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110");
std::string const paymentcode = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97";
}


namespace alice {
std::vector<std::string> const ecdhparams = {
    "8d6a8ecd8ee5e0042ad0cb56e3a971c760b5145c3917a8e7beaf0ed92d7a520c",
    "0353883a146a23f988e0f381a9507cbdb3e3130cd81b3ce26daf2af088724ce683"
    };
}
namespace bob {
std::vector<std::string> const ecdhparams = {
    "04448fd1be0c9c13a5ca0b530e464b619dc091b299b98c5cab9978b32b4a1b8b",
    "024ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8",
    "6bfa917e4c44349bfdf46346d389bf73a18cec6bc544ce9f337e14721f06107b",
    "03e092e58581cf950ff9c8fc64395471733e13f97dedac0044ebd7d60ccc1eea4d",
    "46d32fbee043d8ee176fe85a18da92557ee00b189b533fce2340e4745c4b7b8c",
    "029b5f290ef2f98a0462ec691f5cc3ae939325f7577fcaf06cfc3b8fc249402156",
    "4d3037cfd9479a082d3d56605c71cbf8f38dc088ba9f7a353951317c35e6c343",
    "02094be7e0eef614056dd7c8958ffa7c6628c1dab6706f2f9f45b5cbd14811de44",
    "97b94a9d173044b23b32f5ab64d905264622ecd3eafbe74ef986b45ff273bbba",
    "031054b95b9bc5d2a62a79a58ecfe3af000595963ddc419c26dab75ee62e613842",
    "ce67e97abf4772d88385e66d9bf530ee66e07172d40219c62ee721ff1a0dca01",
    "03dac6d8f74cacc7630106a1cfd68026c095d3d572f3ea088d9a078958f8593572",
    "ef049794ed2eef833d5466b3be6fe7676512aa302afcde0f88d6fcfe8c32cc09",
    "02396351f38e5e46d9a270ad8ee221f250eb35a575e98805e94d11f45d763c4651",
    "d3ea8f780bed7ef2cd0e38c5d943639663236247c0a77c2c16d374e5a202455b",
    "039d46e873827767565141574aecde8fb3b0b4250db9668c73ac742f8b72bca0d0",
    "efb86ca2a3bad69558c2f7c2a1e2d7008bf7511acad5c2cbf909b851eb77e8f3",
    "038921acc0665fd4717eb87f81404b96f8cba66761c847ebea086703a6ae7b05bd",
    "18bcf19b0b4148e59e2bba63414d7a8ead135a7c2f500ae7811125fb6f7ce941",
    "03d51a06c6b48f067ff144d5acdfbe046efa2e83515012cf4990a89341c1440289"
    };
}

std::vector<std::string> const sharedsecrets = {
    "f5bb84706ee366052471e6139e6a9a969d586e5fe6471a9b96c3d8caefe86fef",
    "adfb9b18ee1c4460852806a8780802096d67a8c1766222598dc801076beb0b4d",
    "79e860c3eb885723bb5a1d54e5cecb7df5dc33b1d56802906762622fa3c18ee5",
    "d8339a01189872988ed4bd5954518485edebf52762bf698b75800ac38e32816d",
    "14c687bc1a01eb31e867e529fee73dd7540c51b9ff98f763adf1fc2f43f98e83",
    "725a8e3e4f74a50ee901af6444fb035cb8841e0f022da2201b65bc138c6066a2",
    "521bf140ed6fb5f1493a5164aafbd36d8a9e67696e7feb306611634f53aa9d1f",
    "5f5ecc738095a6fb1ea47acda4996f1206d3b30448f233ef6ed27baf77e81e46",
    "1e794128ac4c9837d7c3696bbc169a8ace40567dc262974206fcf581d56defb4",
    "fe36c27c62c99605d6cd7b63bf8d9fe85d753592b14744efca8be20a4d767c37"
    };

namespace alice {
std::string const notificationaddress = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW";
}
namespace bob {
std::string const notificationaddress = "1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV";
}


struct ChangeBase58Prefixes: public CChainParams
{
    ChangeBase58Prefixes(CChainParams const & params): instance((ChangeBase58Prefixes*) &params) { instance->base58Prefixes[CChainParams::PUBKEY_ADDRESS][0] = 0; }
    ~ChangeBase58Prefixes() { instance->base58Prefixes[CChainParams::PUBKEY_ADDRESS][0] = 82; }
    ChangeBase58Prefixes * instance;
};

}

BOOST_FIXTURE_TEST_SUITE(bip47_basic_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(payment_codes)
{
    {   using namespace alice;
        CExtKey key;
        key.SetMaster(bip32seed.data(), bip32seed.size());
        CExtPubKey pubkey = utils::derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT}).Neuter();
        bip47::CPaymentCode paymentCode({pubkey.pubkey.begin(), pubkey.pubkey.end()}, {pubkey.chaincode.begin(), pubkey.chaincode.end()});
        BOOST_CHECK_EQUAL(paymentCode.toString(), paymentcode);
        BOOST_CHECK(paymentCode.isValid());
    }

    {   using namespace bob;
        CExtKey key;
        key.SetMaster(bip32seed.data(), bip32seed.size());
        CExtPubKey pubkey = utils::derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT}).Neuter();
        bip47::CPaymentCode paymentCode = bip47::CPaymentCode({pubkey.pubkey.begin(), pubkey.pubkey.end()}, {pubkey.chaincode.begin(), pubkey.chaincode.end()});
        BOOST_CHECK_EQUAL(paymentCode.toString(), paymentcode);
        BOOST_CHECK(paymentCode.isValid());
    }
}


BOOST_AUTO_TEST_CASE(ecdh_parameters)
{
    { using namespace alice;
        CExtKey key;
        key.SetMaster(bip32seed.data(), bip32seed.size());

        CExtKey privkey = utils::derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0});
        CExtPubKey pubkey = privkey.Neuter();
        BOOST_CHECK_EQUAL(HexStr(privkey.key), ecdhparams[0]);
        BOOST_CHECK_EQUAL(HexStr(pubkey.pubkey), ecdhparams[1]);
    }

    { using namespace bob;
        for(size_t i = 0; i < bob::ecdhparams.size() / 2; ++i) {
            CExtKey key;
            key.SetMaster(bip32seed.data(), bip32seed.size());

            CExtKey privkey = utils::derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, uint32_t(i)});
            CExtPubKey pubkey = privkey.Neuter();
            BOOST_CHECK_EQUAL(HexStr(privkey.key), ecdhparams[i*2]);
            BOOST_CHECK_EQUAL(HexStr(pubkey.pubkey), ecdhparams[i*2+1]);
        }
    }
}


BOOST_AUTO_TEST_CASE(notification_addresses)
{
    ChangeBase58Prefixes _(Params());

    {using namespace alice;
        bip47::CPaymentCode paymentCode(paymentcode);
        CPubKey pubKey(paymentCode.getPubKey()), pubKey0;
        ChainCode chainCode(paymentCode.getChainCode()), chainCode0;
        pubKey.Derive(pubKey0, chainCode0, 0, chainCode);
        CBitcoinAddress notificationAddress(pubKey0.GetID());
        BOOST_CHECK_EQUAL(notificationAddress.ToString(), notificationaddress);
    }

    {using namespace bob;
        bip47::CPaymentCode paymentCode(paymentcode);
        CPubKey pubKey(paymentCode.getPubKey()), pubKey0;
        ChainCode chainCode(paymentCode.getChainCode()), chainCode0;
        pubKey.Derive(pubKey0, chainCode0, 0, chainCode);
        CBitcoinAddress notificationAddress(pubKey0.GetID());
        BOOST_CHECK_EQUAL(notificationAddress.ToString(), notificationaddress);
    }
}


BOOST_AUTO_TEST_CASE(shared_secrets)
{
    for(size_t i = 0; i < sharedsecrets.size(); ++i) {
        bip47::CSecretPoint s(ParseHex(alice::ecdhparams[0]), ParseHex(bob::ecdhparams[2 * i + 1]));
        BOOST_CHECK_EQUAL(HexStr(s.getEcdhSecret()), sharedsecrets[i]);
    }
    bip47::CSecretPoint s(ParseHex(bob::ecdhparams[0]), ParseHex(alice::ecdhparams[1]));
    BOOST_CHECK_EQUAL(HexStr(s.getEcdhSecret()), sharedsecrets[0]);
}

BOOST_AUTO_TEST_SUITE_END()