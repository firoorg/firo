// Copyright (c) 2020 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "test/test_bitcoin.h"
#include "test/fixtures.h"

#include "bip47_test_data.h"
#include "wallet/wallet.h"
#include <bip47/utils.h>
#include <bip47/secretpoint.h>
#include <bip47/account.h>

using namespace bip47;

BOOST_FIXTURE_TEST_SUITE(bip47_serialization_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(payment_code)
{
    using namespace alice;
    CExtKey key; key.SetMaster(bip32seed.data(), bip32seed.size());
    CExtPubKey pubkey = key.Neuter();
    bip47::CPaymentCode paymentCode(pubkey.pubkey, pubkey.chaincode);

    CDataStream ds(SER_NETWORK, 0);
    ds << paymentCode;

    CPaymentCode paymenCode_deserialized;
    ds >> paymenCode_deserialized;

    BOOST_CHECK(paymentCode == paymenCode_deserialized);
}

BOOST_AUTO_TEST_CASE(payment_channel_receiver)
{
    using namespace alice;
    CExtKey privkey_alice; privkey_alice.SetMaster(bip32seed.data(), bip32seed.size());
    CPaymentCode const paymentCode_bob(bob::paymentcode);
    CPaymentChannel receiver(paymentCode_bob, privkey_alice, CPaymentChannel::Side::receiver);

    auto receiverMyAddrs = receiver.generateMyNextAddresses();
    receiver.markAddressUsed(receiverMyAddrs.back().first);

    receiver.generateTheirNextSecretAddress();
    receiver.generateTheirNextSecretAddress();

    CDataStream ds(SER_NETWORK, 0);
    ds << receiver;

    CPaymentChannel receiver_deserialized(deserialize, ds);

    BOOST_CHECK(receiver.getMyPcode() == receiver_deserialized.getMyPcode());
    BOOST_CHECK(receiver.getTheirPcode() == receiver_deserialized.getTheirPcode());

    BOOST_CHECK(receiver.generateTheirNextSecretAddress() == receiver_deserialized.generateTheirNextSecretAddress());
    BOOST_CHECK(receiver.generateMyNextAddresses() == receiver_deserialized.generateMyNextAddresses());
    BOOST_CHECK(receiver.generateMyUsedAddresses() == receiver_deserialized.generateMyUsedAddresses());
}

BOOST_AUTO_TEST_CASE(payment_channel_sender)
{
    using namespace alice;
    CExtKey privkey_alice; privkey_alice.SetMaster(bip32seed.data(), bip32seed.size());
    CPaymentCode const paymentCode_bob(bob::paymentcode);
    CPaymentChannel sender(paymentCode_bob, privkey_alice, CPaymentChannel::Side::sender);

    sender.generateTheirNextSecretAddress();
    sender.generateTheirNextSecretAddress();

    CDataStream ds(SER_NETWORK, 0);
    ds << sender;

    CPaymentChannel sender_deserialized(deserialize, ds);

    BOOST_CHECK(sender.getMyPcode() == sender_deserialized.getMyPcode());
    BOOST_CHECK(sender.getTheirPcode() == sender_deserialized.getTheirPcode());

    BOOST_CHECK(sender.generateTheirNextSecretAddress() == sender_deserialized.generateTheirNextSecretAddress());
    BOOST_CHECK(sender.generateMyNextAddresses() == sender_deserialized.generateMyNextAddresses());
    BOOST_CHECK(sender.generateMyUsedAddresses() == sender_deserialized.generateMyUsedAddresses());
}

BOOST_AUTO_TEST_CASE(account_receiver)
{
    CExtKey privkey_alice; privkey_alice.SetMaster(alice::bip32seed.data(), alice::bip32seed.size());
    std::srand(std::time(nullptr));
    CAccountReceiver receiver(privkey_alice, std::rand(), "Label");

    CExtKey privkey_bob; privkey_bob.SetMaster(bob::bip32seed.data(), bob::bip32seed.size());
    CPaymentChannel sender1(receiver.getMyPcode(), privkey_bob, CPaymentChannel::Side::sender);

    std::vector<unsigned char> const outPointSer = ParseHex("86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c01000000");
    CDataStream dso(outPointSer, SER_NETWORK, 0);
    COutPoint outpoint;
    dso >> outpoint;

    CBitcoinSecret vchSecret;
    vchSecret.SetString("Kx983SRhAZpAhj7Aac1wUXMJ6XZeyJKqCxJJ49dxEbYCT4a1ozRD");
    CKey outpointSecret = vchSecret.GetKey();

    Bytes maskedPcode1 = sender1.getMaskedPayload(outpoint, outpointSecret);

    BOOST_CHECK(receiver.acceptMaskedPayload(maskedPcode1, outpoint, outpointSecret.GetPubKey()));
    auto receiverMyAddrs = receiver.getMyNextAddresses();
    receiver.addressUsed(receiverMyAddrs.back().first);

    CDataStream ds1(SER_NETWORK, 0);
    ds1 << receiver;
    CAccountReceiver receiver_deserialized(deserialize, ds1);

    BOOST_CHECK(receiver.getAccountNum() == receiver_deserialized.getAccountNum());
    BOOST_CHECK(receiver.getLabel() == receiver_deserialized.getLabel());
    BOOST_CHECK(receiver.getMyPcode() == receiver_deserialized.getMyPcode());
    BOOST_CHECK(receiver.getPchannels() == receiver_deserialized.getPchannels());
    BOOST_CHECK(receiver.getMyUsedAddresses() == receiver_deserialized.getMyUsedAddresses());
    BOOST_CHECK(receiver.getMyNextAddresses() == receiver_deserialized.getMyNextAddresses());


    CPaymentChannel sender2(receiver.getMyPcode(), utils::Derive(privkey_bob, {1}), CPaymentChannel::Side::sender);
    Bytes maskedPcode2 = sender2.getMaskedPayload(outpoint, outpointSecret);

    BOOST_CHECK(receiver.acceptMaskedPayload(maskedPcode2, outpoint, outpointSecret.GetPubKey()));
    receiverMyAddrs = receiver.getMyNextAddresses();
    receiver.addressUsed(receiverMyAddrs.back().first);

    CDataStream ds2(SER_NETWORK, 0);
    ds2 << receiver;
    CAccountReceiver receiver_deserialized2(deserialize, ds2);

    BOOST_CHECK(receiver.getAccountNum() == receiver_deserialized2.getAccountNum());
    BOOST_CHECK(receiver.getLabel() == receiver_deserialized2.getLabel());
    BOOST_CHECK(receiver.getMyPcode() == receiver_deserialized2.getMyPcode());
    BOOST_CHECK(receiver.getPchannels() == receiver_deserialized2.getPchannels());
    BOOST_CHECK(receiver.getMyUsedAddresses() == receiver_deserialized2.getMyUsedAddresses());
    BOOST_CHECK(receiver.getMyNextAddresses() == receiver_deserialized2.getMyNextAddresses());
}

BOOST_AUTO_TEST_CASE(account_sender)
{
    CExtKey privkey_bob; privkey_bob.SetMaster(bob::bip32seed.data(), bob::bip32seed.size());
    std::srand(std::time(nullptr));
    CAccountReceiver receiver(privkey_bob, std::rand(), "Label1");

    CExtKey privkey_alice; privkey_alice.SetMaster(alice::bip32seed.data(), alice::bip32seed.size());;
    std::srand(std::time(nullptr));
    CAccountSender sender(privkey_alice, std::rand(), receiver.getMyPcode());

    sender.generateTheirNextSecretAddress();
    sender.generateTheirNextSecretAddress();

    CDataStream ds(SER_NETWORK, 0);
    ds << sender;

    CAccountSender sender_deserialized(deserialize, ds);

    BOOST_CHECK(sender.getAccountNum() == sender_deserialized.getAccountNum());
    BOOST_CHECK(sender.getTheirPcode() == sender_deserialized.getTheirPcode());
    BOOST_CHECK(sender.getMyPcode() == sender_deserialized.getMyPcode());
    BOOST_CHECK(sender.getMyUsedAddresses() == sender_deserialized.getMyUsedAddresses());
    BOOST_CHECK(sender.getMyNextAddresses() == sender_deserialized.getMyNextAddresses());
    BOOST_CHECK(sender.getMyNextAddresses() == sender_deserialized.getMyNextAddresses());
    BOOST_CHECK(sender.generateTheirNextSecretAddress() == sender_deserialized.generateTheirNextSecretAddress());
}

BOOST_AUTO_TEST_CASE(wallet)
{
    bip47::CWallet wallet(alice::bip32seed);
    wallet.createReceivingAccount("Label1");
    CPaymentCode paymentCode_bob(bob::paymentcode);
    wallet.provideSendingAccount(paymentCode_bob);

    CDataStream ds(SER_NETWORK, 0);
    wallet.enumerateReceivers(
        [&ds](bip47::CAccountReceiver & acc)->bool
        {
            ds << acc;
            return true;
        }
    );

    wallet.enumerateSenders(
        [&ds](bip47::CAccountSender & acc)->bool
        {
            ds << acc;
            return true;
        }
    );


    bip47::CWallet wallet_deserialize(alice::bip32seed);

    CAccountReceiver rcv(deserialize, ds);
    wallet_deserialize.readReceiver(std::move(rcv));

    CAccountSender snd(deserialize, ds);
    wallet_deserialize.readSender(std::move(snd));

    size_t receiverNum = 0, senderNum = 0;
    wallet_deserialize.enumerateReceivers(
        [&receiverNum](bip47::CAccountReceiver & acc)->bool
        {
            BOOST_CHECK(acc.getLabel() == "Label1");
            receiverNum += 1;
            return true;
        }
    );
    BOOST_CHECK_EQUAL(receiverNum, 1);

    wallet_deserialize.enumerateSenders(
        [&senderNum, &paymentCode_bob](bip47::CAccountSender & acc)->bool
        {
            BOOST_CHECK(acc.getTheirPcode() == paymentCode_bob);
            senderNum += 1;
            return true;
        }
    );
    BOOST_CHECK_EQUAL(senderNum, 1);
}

BOOST_AUTO_TEST_SUITE_END()
