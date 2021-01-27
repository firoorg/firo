// Copyright (c) 2020 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// An implementation of bip47 tests provided here: https://gist.github.com/SamouraiDev/6aad669604c5930864bd

#include <boost/test/unit_test.hpp>

#include "test/test_bitcoin.h"
#include "test/fixtures.h"

#include "key.h"
#include "utilstrencodings.h"
#include "bip47/utils.h"
#include "bip47/secretpoint.h"
#include "bip47/account.h"
#include "wallet/wallet.h"

using namespace bip47;
using vchar = std::vector<unsigned char>;

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
std::vector<vchar> const ecdhparams = {
    ParseHex("8d6a8ecd8ee5e0042ad0cb56e3a971c760b5145c3917a8e7beaf0ed92d7a520c"),
    ParseHex("0353883a146a23f988e0f381a9507cbdb3e3130cd81b3ce26daf2af088724ce683")
    };
}
namespace bob {
std::vector<vchar> const ecdhparams = {
    ParseHex("04448fd1be0c9c13a5ca0b530e464b619dc091b299b98c5cab9978b32b4a1b8b"),
    ParseHex("024ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8"),
    ParseHex("6bfa917e4c44349bfdf46346d389bf73a18cec6bc544ce9f337e14721f06107b"),
    ParseHex("03e092e58581cf950ff9c8fc64395471733e13f97dedac0044ebd7d60ccc1eea4d"),
    ParseHex("46d32fbee043d8ee176fe85a18da92557ee00b189b533fce2340e4745c4b7b8c"),
    ParseHex("029b5f290ef2f98a0462ec691f5cc3ae939325f7577fcaf06cfc3b8fc249402156"),
    ParseHex("4d3037cfd9479a082d3d56605c71cbf8f38dc088ba9f7a353951317c35e6c343"),
    ParseHex("02094be7e0eef614056dd7c8958ffa7c6628c1dab6706f2f9f45b5cbd14811de44"),
    ParseHex("97b94a9d173044b23b32f5ab64d905264622ecd3eafbe74ef986b45ff273bbba"),
    ParseHex("031054b95b9bc5d2a62a79a58ecfe3af000595963ddc419c26dab75ee62e613842"),
    ParseHex("ce67e97abf4772d88385e66d9bf530ee66e07172d40219c62ee721ff1a0dca01"),
    ParseHex("03dac6d8f74cacc7630106a1cfd68026c095d3d572f3ea088d9a078958f8593572"),
    ParseHex("ef049794ed2eef833d5466b3be6fe7676512aa302afcde0f88d6fcfe8c32cc09"),
    ParseHex("02396351f38e5e46d9a270ad8ee221f250eb35a575e98805e94d11f45d763c4651"),
    ParseHex("d3ea8f780bed7ef2cd0e38c5d943639663236247c0a77c2c16d374e5a202455b"),
    ParseHex("039d46e873827767565141574aecde8fb3b0b4250db9668c73ac742f8b72bca0d0"),
    ParseHex("efb86ca2a3bad69558c2f7c2a1e2d7008bf7511acad5c2cbf909b851eb77e8f3"),
    ParseHex("038921acc0665fd4717eb87f81404b96f8cba66761c847ebea086703a6ae7b05bd"),
    ParseHex("18bcf19b0b4148e59e2bba63414d7a8ead135a7c2f500ae7811125fb6f7ce941"),
    ParseHex("03d51a06c6b48f067ff144d5acdfbe046efa2e83515012cf4990a89341c1440289")
    };
}

std::vector<vchar> const sharedsecrets = {
    ParseHex("f5bb84706ee366052471e6139e6a9a969d586e5fe6471a9b96c3d8caefe86fef"),
    ParseHex("adfb9b18ee1c4460852806a8780802096d67a8c1766222598dc801076beb0b4d"),
    ParseHex("79e860c3eb885723bb5a1d54e5cecb7df5dc33b1d56802906762622fa3c18ee5"),
    ParseHex("d8339a01189872988ed4bd5954518485edebf52762bf698b75800ac38e32816d"),
    ParseHex("14c687bc1a01eb31e867e529fee73dd7540c51b9ff98f763adf1fc2f43f98e83"),
    ParseHex("725a8e3e4f74a50ee901af6444fb035cb8841e0f022da2201b65bc138c6066a2"),
    ParseHex("521bf140ed6fb5f1493a5164aafbd36d8a9e67696e7feb306611634f53aa9d1f"),
    ParseHex("5f5ecc738095a6fb1ea47acda4996f1206d3b30448f233ef6ed27baf77e81e46"),
    ParseHex("1e794128ac4c9837d7c3696bbc169a8ace40567dc262974206fcf581d56defb4"),
    ParseHex("fe36c27c62c99605d6cd7b63bf8d9fe85d753592b14744efca8be20a4d767c37")
    };

namespace alice {
std::string const notificationaddress = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW";
}
namespace bob {
std::string const notificationaddress = "1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV";
}

namespace alice {
std::vector<std::string> sendingaddresses = {
    "141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK",
    "12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6",
    "1FsBVhT5dQutGwaPePTYMe5qvYqqjxyftc",
    "1CZAmrbKL6fJ7wUxb99aETwXhcGeG3CpeA",
    "1KQvRShk6NqPfpr4Ehd53XUhpemBXtJPTL",
    "1KsLV2F47JAe6f8RtwzfqhjVa8mZEnTM7t",
    "1DdK9TknVwvBrJe7urqFmaxEtGF2TMWxzD",
    "16DpovNuhQJH7JUSZQFLBQgQYS4QB9Wy8e",
    "17qK2RPGZMDcci2BLQ6Ry2PDGJErrNojT5",
    "1GxfdfP286uE24qLZ9YRP3EWk2urqXgC4s"
    };
}

namespace bob {
std::vector<std::string> sendingaddresses = {
    "17SSoP6pwU1yq6fTATEQ7gLMDWiycm68VT",
    "1KNFAqYPoiy29rTQF44YT3v9tvRJYi15Xf",
    "1HQkbVeZoLoDpkZi1MB6AgaCs5ZbxTBdZA",
    "14GfiZb1avg3HSiacMLaoG5xdfPjc1Unvm",
    "15yHVDiYJn146EKHuJiN79L9S2EZAjGVaK"
    };
}

namespace alice {
std::string maskedpayload = "010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b00000000000000000000000000";
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
        CExtPubKey pubkey = utils::Derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT}).Neuter();
        bip47::CPaymentCode paymentCode(pubkey.pubkey, pubkey.chaincode);
        BOOST_CHECK_EQUAL(paymentCode.toString(), paymentcode);
    }

    {   using namespace bob;
        CExtKey key;
        key.SetMaster(bip32seed.data(), bip32seed.size());
        CExtPubKey pubkey = utils::Derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT}).Neuter();
        bip47::CPaymentCode paymentCode = bip47::CPaymentCode(pubkey.pubkey, pubkey.chaincode);
        BOOST_CHECK_EQUAL(paymentCode.toString(), paymentcode);
    }
}


BOOST_AUTO_TEST_CASE(ecdh_parameters)
{
    { using namespace alice;
        CExtKey key;
        key.SetMaster(bip32seed.data(), bip32seed.size());

        CExtKey privkey = utils::Derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0});
        CExtPubKey pubkey = privkey.Neuter();
        BOOST_CHECK_EQUAL(HexStr(privkey.key), HexStr(ecdhparams[0]));
        BOOST_CHECK_EQUAL(HexStr(pubkey.pubkey), HexStr(ecdhparams[1]));
    }

    { using namespace bob;
        for(size_t i = 0; i < bob::ecdhparams.size() / 2; ++i) {
            CExtKey key;
            key.SetMaster(bip32seed.data(), bip32seed.size());

            CExtKey privkey = utils::Derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, uint32_t(i)});
            CExtPubKey pubkey = privkey.Neuter();
            BOOST_CHECK_EQUAL(HexStr(privkey.key), HexStr(ecdhparams[i*2]));
            BOOST_CHECK_EQUAL(HexStr(pubkey.pubkey), HexStr(ecdhparams[i*2+1]));
        }
    }
}


BOOST_AUTO_TEST_CASE(notification_addresses)
{
    ChangeBase58Prefixes _(Params());

    {using namespace alice;
        bip47::CPaymentCode paymentCode(paymentcode);
        BOOST_CHECK_EQUAL(paymentCode.getNotificationAddress().ToString(), notificationaddress);
    }

    {using namespace bob;
        bip47::CPaymentCode paymentCode(paymentcode);
        BOOST_CHECK_EQUAL(paymentCode.getNotificationAddress().ToString(), notificationaddress);
    }
}


BOOST_AUTO_TEST_CASE(shared_secrets)
{
    for(size_t i = 0; i < sharedsecrets.size(); ++i) {
        CKey privkey; privkey.Set(alice::ecdhparams[0].begin(), alice::ecdhparams[0].end(), false);
        CPubKey pubkey(bob::ecdhparams[2 * i + 1].begin(), bob::ecdhparams[2 * i + 1].end());
        bip47::CSecretPoint s(privkey, pubkey);
        BOOST_CHECK(s.getEcdhSecret() == sharedsecrets[i]);
    }
    CKey privkey_b; privkey_b.Set(bob::ecdhparams[0].begin(), bob::ecdhparams[0].end(), false);
    CPubKey pubkey_a(alice::ecdhparams[1].begin(), alice::ecdhparams[1].end());
    bip47::CSecretPoint const s_ba(privkey_b, pubkey_a);
    BOOST_CHECK(s_ba.getEcdhSecret() == sharedsecrets[0]);

    CKey privkey_a; privkey_a.Set(alice::ecdhparams[0].begin(), alice::ecdhparams[0].end(), false);
    CPubKey pubkey_b(bob::ecdhparams[1].begin(), bob::ecdhparams[1].end());
    bip47::CSecretPoint const s_ab(privkey_a, pubkey_b);
    BOOST_CHECK(s_ab.isShared(s_ba));
}

BOOST_AUTO_TEST_CASE(sending_addresses)
{
    ChangeBase58Prefixes _(Params());

    {using namespace alice;
        CExtKey key; key.SetMaster(bip32seed.data(), bip32seed.size());
        CExtKey privkey_alice = utils::Derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0});
        CPaymentCode const paymentCode_bob(bob::paymentcode);
        CPaymentChannel paymentChannel(paymentCode_bob, privkey_alice, CPaymentChannel::Side::sender);

        std::vector<std::string>::const_iterator iter = sendingaddresses.begin();
        for (CBitcoinAddress const & addr: paymentChannel.generateTheirSecretAddresses(0, 10)) {
            BOOST_CHECK_EQUAL(addr.ToString(), *iter++);
        }
    }

    {using namespace bob;
        CExtKey key; key.SetMaster(bip32seed.data(), bip32seed.size());
        CExtKey privkey_bob = utils::Derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0});
        CPaymentCode const paymentCode_alice(alice::paymentcode);
        CPaymentChannel paymentChannel(paymentCode_alice, privkey_bob, CPaymentChannel::Side::sender);

        std::vector<std::string>::const_iterator iter = sendingaddresses.begin();
        for (CBitcoinAddress const & addr: paymentChannel.generateTheirSecretAddresses(0, 5)) {
            BOOST_CHECK_EQUAL(addr.ToString(), *iter++);
        }
    }

    {using namespace bob;
        CExtKey key; key.SetMaster(bob::bip32seed.data(), bob::bip32seed.size());
        CExtKey privkey_bob = utils::Derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT});
        CPaymentCode const paymentCode_alice(alice::paymentcode);
        CPaymentChannel paymentChannel_bob(paymentCode_alice, privkey_bob, CPaymentChannel::Side::receiver);

        std::vector<std::string>::const_iterator iter = alice::sendingaddresses.begin();
        for(bip47::MyAddrContT::value_type const & addr: paymentChannel_bob.generateMySecretAddresses(0, 10)) {
            BOOST_CHECK_EQUAL(addr.first.ToString(), *iter++);
        }
    }
}

BOOST_AUTO_TEST_CASE(masked_paymentcode)
{
    ChangeBase58Prefixes _(Params());

    {using namespace alice;
        CPaymentCode const paymentCode_bob(bob::paymentcode);

        CExtKey key;
        key.SetMaster(bip32seed.data(), bip32seed.size());
        CExtKey key_alice = utils::Derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT});

        CPaymentChannel paymentChannel(paymentCode_bob, key_alice, CPaymentChannel::Side::sender);

        std::vector<unsigned char> const outPointSer = ParseHex("86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c01000000");
        CDataStream ds(outPointSer, SER_NETWORK, 0);
        COutPoint outpoint;
        ds >> outpoint;

        CBitcoinSecret vchSecret;
        vchSecret.SetString("Kx983SRhAZpAhj7Aac1wUXMJ6XZeyJKqCxJJ49dxEbYCT4a1ozRD");
        CKey outpointSecret = vchSecret.GetKey();

        std::vector<unsigned char> maskedPayload_alice = paymentChannel.getMaskedPayload(outpoint, outpointSecret);
        BOOST_CHECK_EQUAL(HexStr(maskedPayload_alice), maskedpayload);

        // Unmasking at bob's side
        key.SetMaster(bob::bip32seed.data(), bob::bip32seed.size());
        CExtKey key_bob = utils::Derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00});

        std::unique_ptr<CPaymentCode> pcode_unmasked = bip47::utils::PcodeFromMaskedPayload(maskedPayload_alice, outpoint, key_bob.key, outpointSecret.GetPubKey());
        BOOST_CHECK_EQUAL(pcode_unmasked->toString(), paymentcode);
    }
}

BOOST_AUTO_TEST_CASE(account_for_sending)
{
    ChangeBase58Prefixes _(Params());

    {using namespace alice;
        CExtKey key;
        key.SetMaster(bip32seed.data(), bip32seed.size());
        CExtKey key_alice = utils::Derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT});

        CPaymentCode const paymentCode_bob(bob::paymentcode);

        bip47::CAccountSender account(key_alice, 0, paymentCode_bob);

        std::vector<unsigned char> const outPointSer = ParseHex("86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c01000000");
        CDataStream ds(outPointSer, SER_NETWORK, 0);
        COutPoint outpoint;
        ds >> outpoint;

        CBitcoinSecret vchSecret;
        vchSecret.SetString("Kx983SRhAZpAhj7Aac1wUXMJ6XZeyJKqCxJJ49dxEbYCT4a1ozRD");
        CKey outpoinSecret = vchSecret.GetKey();

        BOOST_CHECK_EQUAL(HexStr(account.getMaskedPayload(outpoint, outpoinSecret)), maskedpayload);

        MyAddrContT addresses = account.getMyNextAddresses();
        BOOST_CHECK_EQUAL(addresses.size(), 1);
        CBitcoinAddress notifAddr = addresses[0].first;
        BOOST_CHECK_EQUAL(addresses[0].first.ToString(), notificationaddress);
        BOOST_CHECK(account.addressUsed(addresses[0].first));

        addresses = account.getMyNextAddresses();
        BOOST_CHECK(addresses[0].first == notifAddr);
        BOOST_CHECK(account.addressUsed(notifAddr));

        addresses = account.getMyUsedAddresses();
        BOOST_CHECK(addresses.empty());
    }
}

BOOST_AUTO_TEST_CASE(account_for_receiving)
{
    ChangeBase58Prefixes _(Params());

    {using namespace bob;
        CExtKey key;
        key.SetMaster(bip32seed.data(), bip32seed.size());
        CExtKey key_bob = utils::Derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT});

        bip47::CAccountReceiver account(key_bob, 0, "");

        BOOST_CHECK_EQUAL(account.getMyPcode().toString(), paymentcode);
        BOOST_CHECK_EQUAL(account.getMyNotificationAddress().ToString(), notificationaddress);

        std::vector<unsigned char> const outPointSer = ParseHex("86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c01000000");
        CDataStream ds(outPointSer, SER_NETWORK, 0);
        COutPoint outpoint;
        ds >> outpoint;

        CBitcoinSecret vchSecret;
        vchSecret.SetString("Kx983SRhAZpAhj7Aac1wUXMJ6XZeyJKqCxJJ49dxEbYCT4a1ozRD");
        CPubKey outpointPubkey = vchSecret.GetKey().GetPubKey();

        BOOST_CHECK(account.acceptMaskedPayload(ParseHex(alice::maskedpayload), outpoint, outpointPubkey));

        MyAddrContT addrs = account.getMyNextAddresses();
        BOOST_CHECK_EQUAL(addrs.size(), 1 + bip47::AddressLookaheadNumber);
        BOOST_CHECK_EQUAL(addrs[0].first.ToString(), notificationaddress);

        for(size_t i = 0; i < bip47::AddressLookaheadNumber; ++i) {
            BOOST_CHECK_EQUAL(addrs[i+1].first.ToString(), alice::sendingaddresses[i]);
        }

        BOOST_CHECK(account.addressUsed(addrs[0].first));

        addrs = account.getMyNextAddresses();
        BOOST_CHECK_EQUAL(addrs.size(), 1 + bip47::AddressLookaheadNumber);
        BOOST_CHECK_EQUAL(addrs[0].first.ToString(), notificationaddress);

        CBitcoinAddress someAddr = addrs[2].first;
        BOOST_CHECK(account.addressUsed(someAddr));

        addrs = account.getMyNextAddresses();
        BOOST_CHECK_EQUAL(addrs.size(), 1 + bip47::AddressLookaheadNumber);
        BOOST_CHECK_EQUAL(addrs[0].first.ToString(), notificationaddress);

        for(size_t i = 0; i < bip47::AddressLookaheadNumber - 2; ++i) {
            BOOST_CHECK_EQUAL(addrs[i+1].first.ToString(), alice::sendingaddresses[i + 2]);
        }

        addrs = account.getMyUsedAddresses();
        BOOST_CHECK_EQUAL(addrs.size(), 2);
        for(size_t i = 0; i < addrs.size(); ++i) {
            BOOST_CHECK_EQUAL(addrs[i].first.ToString(), alice::sendingaddresses[i]);
        }

        BOOST_CHECK(!account.addressUsed(someAddr));
        BOOST_CHECK_EQUAL(addrs.size(), 2);
        for(size_t i = 0; i < addrs.size(); ++i) {
            BOOST_CHECK_EQUAL(addrs[i].first.ToString(), alice::sendingaddresses[i]);
        }

        someAddr.SetString(alice::sendingaddresses[9]);
        BOOST_CHECK(account.addressUsed(someAddr));
        addrs = account.getMyUsedAddresses();
        BOOST_CHECK_EQUAL(addrs.size(), 10);
        for(size_t i = 0; i < addrs.size(); ++i) {
            BOOST_CHECK_EQUAL(addrs[i].first.ToString(), alice::sendingaddresses[i]);
        }

        addrs = account.getMyNextAddresses();
        BOOST_CHECK_EQUAL(addrs.size(), 1 + bip47::AddressLookaheadNumber);
        BOOST_CHECK_EQUAL(addrs[0].first.ToString(), notificationaddress);
        for(std::string const & bobsaddr : alice::sendingaddresses) {
            someAddr.SetString(bobsaddr);
            BOOST_CHECK(addrs.end() == std::find_if(addrs.begin(), addrs.end(), bip47::FindByAddress(someAddr)));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
        