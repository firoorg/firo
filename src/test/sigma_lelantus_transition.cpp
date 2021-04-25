
#include <stdint.h>
#include <vector>

#include "key.h"
#include "validation.h"
#include "pubkey.h"
#include "txmempool.h"
#include "sigma.h"
#include "lelantus.h"

#include "test/fixtures.h"
#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletexcept.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

BOOST_FIXTURE_TEST_SUITE(sigma_lelantus_transition, LelantusTestingSetup)

BOOST_AUTO_TEST_CASE(sigma_lelantus_transition_test)
{
    GenerateBlocks(150);

    pwalletMain->SetBroadcastTransactions(true);
    string stringError;

    string denomination;
    std::vector<string> denominations = {"0.05", "0.1", "0.5", "1", "10", "25", "100"};
    vector <CHDMint> vDMints;
    // foreach denom from denominations
    for(auto denomination : denominations)
    {
        sigma::CoinDenomination denom;
        BOOST_CHECK_MESSAGE(StringToDenomination(denomination, denom), "Unable to convert denomination string to value.");

        // Verify Mint is successful
        std::vector <sigma::PrivateCoin> privCoins;
        const auto &sigmaParams = sigma::Params::get_default();
        privCoins.push_back(sigma::PrivateCoin(sigmaParams, denom));
        privCoins.push_back(sigma::PrivateCoin(sigmaParams, denom));

        vDMints.clear();
        auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);
        CWalletTx wtx;
        stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);

        BOOST_CHECK_MESSAGE(stringError == "", "Create Mint Failed");

        // Verify Mint gets in the mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

        int previousHeight = chainActive.Height();
        GenerateBlock({CMutableTransaction(*wtx.tx)});
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
        GenerateBlocks(6);
    }

    std::list<CSigmaEntry> coins = pwalletMain->GetAvailableCoins(nullptr, false);
    BOOST_CHECK_MESSAGE(coins.size() == denominations.size() * 2, "Wrong number of available sigma coins");

    GenerateBlocks(300);

    // Generate address
    CPubKey newKey;
    BOOST_CHECK_MESSAGE(pwalletMain->GetKeyFromPool(newKey), "Fail to get new address");
    const CBitcoinAddress randomAddr(newKey.GetID());
    std::vector<CRecipient> recipients = {
        {GetScriptForDestination(randomAddr.Get()), 200 * COIN, true},
    };

    CWalletTx wtx;
    {
        BOOST_CHECK_NO_THROW(pwalletMain->JoinSplitLelantus(recipients, {}, wtx));
    }
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "JoinSplit is not added into mempool");

    int previousHeight = chainActive.Height();
    GenerateBlock({CMutableTransaction(*wtx.tx)});
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "JoinSplit is not removed from mempool");
    coins = pwalletMain->GetAvailableCoins(nullptr, false);
    BOOST_CHECK_MESSAGE(coins.size() == denominations.size() * 2 - 2, "Spent sigma coins are not set as used");

    for(auto mint : vDMints)
        pwalletMain->zwallet->GetTracker().SetPubcoinNotUsed(primitives::GetPubCoinValueHash(mint.GetPubcoinValue()));

    wtx.Init(NULL);
    BOOST_CHECK_NO_THROW(pwalletMain->JoinSplitLelantus(recipients, {}, wtx));
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not empty although mempool should reject double spend");

    //roll back mints used
    for(auto mint : vDMints)
        pwalletMain->zwallet->GetTracker().SetPubcoinUsed(primitives::GetPubCoinValueHash(mint.GetPubcoinValue()), uint256());

    std::vector<CMutableTransaction> mintTxs;
    vDMints = GenerateMints({20 * COIN, 30 * COIN}, mintTxs);

    // Verify Mint gets in the mempool
    BOOST_CHECK_MESSAGE(mempool.size() == vDMints.size(), "Mints were not added to mempool");

    previousHeight = chainActive.Height();
    GenerateBlock(mintTxs);
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mints were not removed from mempool");
    GenerateBlocks(6);
    recipients = {
        {GetScriptForDestination(randomAddr.Get()), 100 * COIN, true},
    };
    wtx.Init(NULL);
    BOOST_CHECK_NO_THROW(pwalletMain->JoinSplitLelantus(recipients, {}, wtx));
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "JoinSplit is not added into mempool");

    previousHeight = chainActive.Height();
    GenerateBlock({CMutableTransaction(*wtx.tx)});
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "JoinSplit is not removed from mempool");

    coins = pwalletMain->GetAvailableCoins(nullptr, false);
    BOOST_CHECK_MESSAGE(coins.size() == 0, "All sigma coins should be marked used, but something went wrong");

    auto lelantusCoins = pwalletMain->GetAvailableLelantusCoins(nullptr, false);
    BOOST_CHECK_MESSAGE(lelantusCoins.size() < vDMints.size(), "Some of lelantus coins should be marked used, but something went wrong");

    previousHeight = chainActive.Height();
    GenerateBlocks(6);

    auto currentLelantusCoins = pwalletMain->GetAvailableLelantusCoins(nullptr, false);
    BOOST_CHECK_MESSAGE(currentLelantusCoins.size() > lelantusCoins.size(), "Newly created jmint should be marked as spendable, but something went wrong");

    mempool.clear();
    sigma::CSigmaState::GetState()->Reset();
    lelantus::CLelantusState::GetState()->Reset();

}
BOOST_AUTO_TEST_SUITE_END()