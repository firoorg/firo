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
    bool GenerateBlock(std::vector<CMutableTransaction> const &txns = {}) {
        auto last = chainActive.Tip();

        CreateAndProcessBlock(txns, script);
        auto block = chainActive.Tip();

        if (block != last) {
            pwalletMain->ScanForWalletTransactions(block, true);
        }

        return block != last;
    }

    void GenerateBlocks(size_t blocks) {
        while (--blocks) {
            GenerateBlock();
        }
    }

    std::vector<CHDMint> GenerateMints(std::vector<CAmount> const &amounts, std::vector<CMutableTransaction> &txs) {
        std::vector<CHDMint> mints;

        for (auto a : amounts) {
            lelantus::PrivateCoin coin(params, a);
            mints.emplace_back();
            auto mint = mints.back();

            auto rec = CWallet::CreateLelantusMintRecipient(coin, mint);

            CWalletTx wtx;
            auto result = pwalletMain->MintAndStoreLelantus(rec, coin, mint, wtx);
            txs.emplace_back(wtx);

            zwalletMain->GetTracker().AddLelantus(mint, true);

            if (result != "") {
                throw std::runtime_error("Fail to generate mints " + result);
            }
        }

        return mints;
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

BOOST_AUTO_TEST_CASE(list_confirmed)
{
    GenerateBlocks(120);
    std::vector<CAmount> confirmedAmounts = {1, 2 * COIN};
    std::vector<CAmount> unconfirmedAmounts = {10 * COIN};
    std::vector<CAmount> allAmounts(confirmedAmounts);
    allAmounts.insert(allAmounts.end(), unconfirmedAmounts.begin(), unconfirmedAmounts.end());

    // Generate all coins
    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints(allAmounts, txs);
    GenerateBlock(std::vector<CMutableTransaction>(txs.begin(), txs.begin() + txs.size() - 1));

    auto extractAmountsFromOutputs = [](std::vector<COutput> const &outs) -> std::vector<CAmount> {
        std::vector<CAmount> amounts;
        for (auto const &out : outs) {
            amounts.push_back(out.tx->tx->vout[out.i].nValue);
        }

        return amounts;
    };

    std::vector<COutput> confirmedCoins, allCoins;
    pwalletMain->ListAvailableLelantusMintCoins(confirmedCoins, true);
    pwalletMain->ListAvailableLelantusMintCoins(allCoins, false);
    auto confirmed = extractAmountsFromOutputs(confirmedCoins);
    auto all = extractAmountsFromOutputs(allCoins);

    BOOST_CHECK(std::is_permutation(confirmed.begin(), confirmed.end(), confirmedAmounts.begin()));
    BOOST_CHECK(std::is_permutation(all.begin(), all.end(), allAmounts.begin()));
}

BOOST_AUTO_TEST_SUITE_END()
