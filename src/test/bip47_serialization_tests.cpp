// Copyright (c) 2020 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "test/test_bitcoin.h"
#include "test/fixtures.h"

#include "bip47_test_data.h"
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

BOOST_AUTO_TEST_CASE(payment_channel)
{
    using namespace alice;
    CExtKey privkey_alice; privkey_alice.SetMaster(bip32seed.data(), bip32seed.size());
    CPaymentCode const paymentCode_bob(bob::paymentcode);
    CPaymentChannel receiver(paymentCode_bob, privkey_alice, CPaymentChannel::Side::receiver);

    auto receiverMyAddrs = receiver.generateMyNextAddresses();
    receiver.markAddressUsed(receiverMyAddrs.back().first);

    receiver.generateTheirNextSecretAddress();
    auto receiverTheirAddr = receiver.generateTheirNextSecretAddress();

    CDataStream ds(SER_NETWORK, 0);
    ds << receiver;

    CPaymentChannel receiver_deserialized(deserialize, ds);

    BOOST_CHECK(receiver.getMyPcode() == receiver_deserialized.getMyPcode());
    BOOST_CHECK(receiver.getTheirPcode() == receiver_deserialized.getTheirPcode());
}


BOOST_AUTO_TEST_SUITE_END()
