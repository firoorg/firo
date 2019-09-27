// Copyright (c) 2019 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../sigmadb.h"
#include "../sigmawallet.h"

#include "../../wallet/test/wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>

namespace exodus {

class TestSigmaWallet : public SigmaWallet {

public:
    TestSigmaWallet(std::string const &walletFile) : SigmaWallet(walletFile)
    {
    }

public:
    bool GeneratePrivateKey(uint512 const &seed, exodus::SigmaPrivateKey &coin)
    {
        return SigmaWallet::GeneratePrivateKey(seed, coin);
    }
};

struct WalletTestingSetup : ::WalletTestingSetup
{
    WalletTestingSetup() : sigmaWallet(pwalletMain->strWalletFile)
    {
    }

    TestSigmaWallet sigmaWallet;
};

BOOST_FIXTURE_TEST_SUITE(exodus_sigmawallet_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(generate_private_key)
{
    uint512 seed;
    seed.SetHex(
        "5ead609e466f37c92b671e3725da4cd98adafdb23496369c09196f30f8d716dc9f67"
        "9026b2f94984f94a289208a2941579ef321dee63d8fd6346ef665c6f60df"
    );

    SigmaPrivateKey key;
    sigmaWallet.GeneratePrivateKey(seed, key);

    BOOST_CHECK_EQUAL(
        std::string("4d75cc284921b44e9acbf67cdabbd8a5c61057a4fa5b7aedbe01994e55e3c0b6"),
        key.serial.GetHex());

    BOOST_CHECK_EQUAL(
        std::string("d2e5b830ab1fa8235a9af7db4fd554de5757a0e594acbfc1a4526c3fb26bcbbd"),
        key.randomness.GetHex());
}

BOOST_AUTO_TEST_SUITE_END()

}