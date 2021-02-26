// Copyright (c) 2020 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// An implementation of bip47 tests provided here: https://gist.github.com/SamouraiDev/6aad669604c5930864bd

#include <boost/test/unit_test.hpp>

#include "test/test_bitcoin.h"
#include "test/fixtures.h"

#include "key.h"
#include "utilstrencodings.h"
#include <bip47/utils.h>
#include <bip47/secretpoint.h>
#include <bip47/account.h>
#include "wallet/wallet.h"
#include "bip47_test_data.h"

using namespace bip47;

struct ChangeBase58Prefixes: public CChainParams
{
    ChangeBase58Prefixes(CChainParams const & params): instance((ChangeBase58Prefixes*) &params) { instance->base58Prefixes[CChainParams::PUBKEY_ADDRESS][0] = 0; }
    ~ChangeBase58Prefixes() { instance->base58Prefixes[CChainParams::PUBKEY_ADDRESS][0] = 82; }
    ChangeBase58Prefixes * instance;
};

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
        CExtKey privkey_alice = utils::Derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT});
        CPaymentCode const paymentCode_bob(bob::paymentcode);
        CPaymentChannel paymentChannel(paymentCode_bob, privkey_alice, CPaymentChannel::Side::sender);

        std::vector<std::string>::const_iterator iter = sendingaddresses.begin();
        for (CBitcoinAddress const & addr: paymentChannel.generateTheirSecretAddresses(0, 10)) {
            BOOST_CHECK_EQUAL(addr.ToString(), *iter++);
        }
    }

    {using namespace bob;
        CExtKey key; key.SetMaster(bip32seed.data(), bip32seed.size());
        CExtKey privkey_bob = utils::Derive(key, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT});
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

BOOST_AUTO_TEST_CASE(address_match)
{
    CExtKey keyBob; keyBob.SetMaster(bob::bip32seed.data(), bob::bip32seed.size());
    std::srand(std::time(nullptr));
    bip47::CAccountReceiver receiver(keyBob, std::rand(), "");

    CExtKey keyAlice; keyAlice.SetMaster(alice::bip32seed.data(), alice::bip32seed.size());
    bip47::CAccountSender sender(keyAlice, std::rand(), receiver.getMyPcode());

    receiver.acceptPcode(sender.getMyPcode());

    MyAddrContT receiverAddrs = receiver.getMyNextAddresses();
    BOOST_CHECK(std::find_if(receiverAddrs.begin(), receiverAddrs.end(), FindByAddress(sender.generateTheirNextSecretAddress())) != receiverAddrs.end());

    for (MyAddrContT::value_type const & addrPair: receiverAddrs) {
        BOOST_CHECK(addrPair.first == CBitcoinAddress(addrPair.second.GetPubKey().GetID()));
    }
}


BOOST_AUTO_TEST_SUITE_END()
        