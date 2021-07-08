#include "util.h"

#include <stdint.h>
#include <vector>

#include "chainparams.h"
#include "key.h"
#include "validation.h"
#include "pubkey.h"
#include "txdb.h"
#include "txmempool.h"
#include "sigma.h"

#include "test/fixtures.h"
#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletexcept.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

BOOST_FIXTURE_TEST_SUITE(sigma_mintspend_numinputs, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(sigma_mintspend_numinputs)
{
    vector<string> denominationsForTx;
    vector<uint256> vtxid;
    int previousHeight;
    CBlock b;
    CWalletTx wtx;
    string stringError;

    // Generate address
    CPubKey newKey;
    BOOST_CHECK_MESSAGE(pwalletMain->GetKeyFromPool(newKey), "Fail to get new address");

    const CBitcoinAddress randomAddr(newKey.GetID());

    std::vector<std::string> denominations = {"0.05", "0.1", "0.5", "1", "10", "25", "100"};

    // Test with small denominations to limit required coins.
    int denominationIndexA = 0; // 0.1
    int denominationIndexB = 1; // 0.5

    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    auto& consensus = ::Params().GetConsensus();

    pwalletMain->SetBroadcastTransactions(true);

    // attempt to create a sigma spend with more than inputs limit.
    denominationsForTx.clear();
    CAmount nAmount(0);
    for (unsigned i = 0; i < (consensus.nMaxSigmaInputPerBlock + 1) * 2; i++){
        denominationsForTx.push_back(denominations[denominationIndexA]);

        sigma::CoinDenomination denomination;
        BOOST_CHECK_MESSAGE(StringToDenomination(denominations[denominationIndexA], denomination), "Unable to convert denomination string to value.");

        CAmount intDenom;
        DenominationToInteger(denomination, intDenom);

        nAmount += intDenom;

        const auto& sigmaParams = sigma::Params::get_default();

        {
            sigma::CoinDenomination denom;
            BOOST_CHECK_MESSAGE(StringToDenomination(denominations[denominationIndexA], denom), "Unable to convert denomination string to value.");
            std::vector<sigma::PrivateCoin> privCoins;
            privCoins.push_back(sigma::PrivateCoin(sigmaParams, denom));
            vector<CHDMint> vDMints;
            auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);
            CWalletTx wtx;
            stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);
            BOOST_CHECK_MESSAGE(stringError == "", "Create Mint Failed");
        }
        {
            sigma::CoinDenomination denom;
            BOOST_CHECK_MESSAGE(StringToDenomination(denominations[denominationIndexB], denom), "Unable to convert denomination string to value.");
            std::vector<sigma::PrivateCoin> privCoins;
            privCoins.push_back(sigma::PrivateCoin(sigmaParams, denom));
            vector<CHDMint> vDMints;
            auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);
            CWalletTx wtx;
            stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);
            BOOST_CHECK_MESSAGE(stringError == "", "Create Mint Failed");
        }

        if (i <= consensus.nMaxSigmaInputPerBlock) {
            denominationsForTx.push_back(denominations[denominationIndexA]);
            nAmount += intDenom;
        }
    }

    BOOST_CHECK_MESSAGE(mempool.size() == (consensus.nMaxSigmaInputPerBlock + 1) * 4, "Num input mints not added to mempool");

    // add block
    previousHeight = chainActive.Height();
    b = CreateAndProcessBlock(scriptPubKey);
    wtx.Init(NULL);

    //Add 5 more blocks
    for (int i = 0; i < 5; i++)
    {
        b = CreateAndProcessBlock(scriptPubKey);
        wtx.Init(NULL);
    }

    BOOST_CHECK_MESSAGE(previousHeight + 6 == chainActive.Height(), "Block not added to chain");
    previousHeight = chainActive.Height();

    std::vector<CRecipient> recipients = {
            {GetScriptForDestination(randomAddr.Get()), nAmount, true},
            };

    // Check that the tx creation fails.
    BOOST_CHECK_THROW(pwalletMain->SpendSigma(recipients, wtx), std::exception);
    
    sigma::DenominationToInteger(sigma::CoinDenomination::SIGMA_DENOM_0_1, nAmount);
    recipients = {
            {GetScriptForDestination(randomAddr.Get()), nAmount * 2, true},
            };

    unsigned spendsTransactionLimit = consensus.nMaxSigmaInputPerBlock / 2;
    // Next add spendsTransactionLimit + 1 transactions with 2 inputs each, verify mempool==spendsTransactionLimit + 1. mine a block. Verify mempool still has 1 tx.
    for(unsigned i = 0; i < spendsTransactionLimit + 1; i++){
        BOOST_CHECK_NO_THROW(pwalletMain->SpendSigma(recipients, wtx));
    }

    BOOST_CHECK_MESSAGE(mempool.size() == spendsTransactionLimit + 1, "Num input spends not added to mempool");

    // add block
    b = CreateAndProcessBlock(scriptPubKey);
    wtx.Init(NULL);

    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mempool not correctly cleared: Block spend limit not enforced.");

    vtxid.clear();
    mempool.clear();
    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(spend_value_limit)
{
    // Generate addresses
    CPubKey newKey1, newKey2;
    BOOST_CHECK_MESSAGE(pwalletMain->GetKeyFromPool(newKey1), "Fail to get new address");
    BOOST_CHECK_MESSAGE(pwalletMain->GetKeyFromPool(newKey2), "Fail to get new address");

    const CBitcoinAddress randomAddr1(newKey1.GetID());
    const CBitcoinAddress randomAddr2(newKey2.GetID());

    std::string stringError;
    auto& consensus = Params().GetConsensus();

    auto testDenomination = sigma::CoinDenomination::SIGMA_DENOM_100;
    CAmount testDenominationAmount;
    sigma::DenominationToInteger(testDenomination, testDenominationAmount);

    pwalletMain->SetBroadcastTransactions(true);

    // Mint coins to ensure have coins enough to choose more than value limit.
    CAmount allMintsValue(0);
    while (allMintsValue <= consensus.nMaxValueSigmaSpendPerBlock * 2){
        const auto& sigmaParams = sigma::Params::get_default();

        std::vector<sigma::PrivateCoin> privCoins;
        privCoins.push_back(sigma::PrivateCoin(sigmaParams, testDenomination));
        vector<CHDMint> vDMints;
        auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);
        CWalletTx wtx;
        stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);
        BOOST_CHECK_MESSAGE(stringError == "", "Create Mint Failed");

        allMintsValue += testDenominationAmount;
    }

    // Ensure all mint coins be able to use.
    BOOST_CHECK_NE(mempool.size(), 0);
    CreateAndProcessBlock(scriptPubKey);
    BOOST_CHECK_EQUAL(mempool.size(), 0);
    CreateAndProcessEmptyBlocks(5, scriptPubKey);

    // Try to spend at value limit with single vout.
    std::vector<CRecipient> recipients = {
        {GetScriptForDestination(randomAddr1.Get()), testDenominationAmount * 5, false},
    };

    CWalletTx tx;

    // This should fail because we need to use spends more than limit.
    BOOST_CHECK_EXCEPTION(
        pwalletMain->SpendSigma(recipients, tx),
        std::invalid_argument,
        [](const std::invalid_argument& e){return e.what() == std::string("Required amount exceed value spend limit");});

    // Try to spend at value limit with two vout.
    recipients = {
        {GetScriptForDestination(randomAddr1.Get()), testDenominationAmount * 4, false},
        {GetScriptForDestination(randomAddr2.Get()), testDenominationAmount * 1, false},
    };
    // This should fail because we need to use spends more than limit.
    BOOST_CHECK_EXCEPTION(
        pwalletMain->SpendSigma(recipients, tx),
        std::invalid_argument,
        [](const std::invalid_argument& e){return e.what() == std::string("Required amount exceed value spend limit");});

    // Try to spend two transactions which each transaction not over limit.
    // But sum of spend in both transaction exceed limit.
    // Then both transactions should be included to mempool but never be mined together.
    recipients = {
        {GetScriptForDestination(randomAddr1.Get()), testDenominationAmount * 2, false},
        {GetScriptForDestination(randomAddr2.Get()), testDenominationAmount * 1, false},
    };

    BOOST_CHECK_NO_THROW(pwalletMain->SpendSigma(recipients, tx));
    BOOST_CHECK_EQUAL(mempool.size(), 1);

    recipients = {
            {GetScriptForDestination(randomAddr1.Get()), testDenominationAmount * 3, false},
            };

    BOOST_CHECK_NO_THROW(pwalletMain->SpendSigma(recipients, tx));
    BOOST_CHECK_EQUAL(mempool.size(), 2);

    CreateAndProcessBlock(scriptPubKey);
    BOOST_CHECK_EQUAL(mempool.size(), 1);

    mempool.clear();
}

BOOST_AUTO_TEST_SUITE_END()


