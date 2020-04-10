#include "../wallet.h"

#include "wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>

class LelantusWalletTestingSetup : public WalletTestingSetup {
public:
    LelantusWalletTestingSetup() : params(lelantus::Params::get_default()) {
    }

public:
    lelantus::Params const *params;
};

BOOST_FIXTURE_TEST_SUITE(wallet_lelantus_tests, LelantusWalletTestingSetup)

BOOST_AUTO_TEST_CASE(create_mint_recipient)
{
    lelantus::PrivateCoin coin(params, 1);
    CHDMint m;

    auto r = CWallet::CreateLelantusMintRecipient(coin, m);

    // payload is commentment and schnorr proof
    size_t expectedSize = 1 // op code
        + lelantus::PublicCoin().GetSerializeSize()
        + lelantus::SchnorrProof<Scalar, GroupElement>().memoryRequired();

    BOOST_CHECK_EQUAL(OP_LELANTUSMINT, r.scriptPubKey.front());
    BOOST_CHECK_EQUAL(expectedSize, r.scriptPubKey.size());

    // assert HDMint
    BOOST_CHECK_EQUAL(0, m.GetCount());
}

BOOST_AUTO_TEST_SUITE_END()
