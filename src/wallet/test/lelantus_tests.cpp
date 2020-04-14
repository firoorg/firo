#include "../../validation.h"

#include "../wallet.h"

#include "wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>

class LelantusWalletTestingSetup : public TestChain100Setup {
public:
    LelantusWalletTestingSetup() :
        params(lelantus::Params::get_default()) {

        CPubKey key;
        {
            LOCK(pwalletMain->cs_wallet);
            key = pwalletMain->GenerateNewKey();
        }

        script = GetScriptForDestination(key.GetID());
    }

public:
    bool GenerateBlock(const std::vector<CMutableTransaction>& txns = {}) {
        auto last = chainActive.Tip();

        CreateAndProcessBlock(txns, script);
        auto block = chainActive.Tip();

        if (block != last) {
            pwalletMain->ScanForWalletTransactions(block);
        }

        return block != last;
    }

    void GenerateBlocks(size_t blocks) {
        while (--blocks) {
            GenerateBlock();
        }
    }

public:
    lelantus::Params const *params;
    CScript script;
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

    BOOST_CHECK(r.scriptPubKey.IsLelantusMint());
    BOOST_CHECK_EQUAL(expectedSize, r.scriptPubKey.size());

    // assert HDMint
    BOOST_CHECK_EQUAL(0, m.GetCount());
}

BOOST_AUTO_TEST_CASE(mint_and_store_lelantus)
{
    GenerateBlocks(110);
    auto amount = 1 * COIN;

    lelantus::PrivateCoin coin(params, amount);
    CHDMint m;

    auto rec = CWallet::CreateLelantusMintRecipient(coin, m);

    CWalletTx wtx;
    auto result = pwalletMain->MintAndStoreLelantus(rec, coin, m, wtx);

    BOOST_CHECK_EQUAL("", result);
    auto tx = wtx.tx.get();

    BOOST_CHECK(tx->IsLelantusMint());
    BOOST_CHECK(tx->IsLelantusTransaction());

    // verify outputs
    BOOST_CHECK_EQUAL(2, tx->vout.size());

    size_t mintCount = 0;
    for (auto const &out : tx->vout) {
        if (out.scriptPubKey.IsLelantusMint()) {
            BOOST_CHECK_EQUAL(amount, out.nValue);
            mintCount++;
        }
    }

    BOOST_CHECK_EQUAL(1, mintCount);

    // verify tx
    CMutableTransaction mtx(*tx);
    BOOST_CHECK(GenerateBlock({mtx}));
}

BOOST_AUTO_TEST_SUITE_END()
