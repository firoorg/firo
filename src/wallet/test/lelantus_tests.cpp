#include "../../test/fixtures.h"
#include "../../validation.h"

#include "../wallet.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(wallet_lelantus_tests, LelantusTestingSetup)

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
    fRequireStandard = true; // to verify mainnet can accept lelantus mint
    pwalletMain->SetBroadcastTransactions(true);

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
    BOOST_CHECK(mempool.exists(tx->GetHash()));

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

BOOST_AUTO_TEST_CASE(get_and_list_mints)
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

    std::vector<std::pair<lelantus::PublicCoin, uint64_t>> pubCoins;
    pubCoins.reserve(mints.size() - 1);
    for (size_t i = 0; i != mints.size() - 1; i++) {
        pubCoins.emplace_back(mints[i].GetPubcoinValue(), mints[i].GetAmount());
    }

    zwalletMain->GetTracker().UpdateMintStateFromBlock(pubCoins);

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

    // get mints
    CLelantusEntry entry;
    BOOST_CHECK(pwalletMain->GetMint(mints.front().GetSerialHash(), entry));
    BOOST_CHECK(entry.value == mints.front().GetPubcoinValue());

    uint256 fakeSerial;
    std::fill(fakeSerial.begin(), fakeSerial.end(), 1);
    BOOST_CHECK(!pwalletMain->GetMint(fakeSerial, entry));
}

BOOST_AUTO_TEST_SUITE_END()
