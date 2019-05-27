#include "util.h"

#include <stdint.h>
#include <vector>

#include "chainparams.h"
#include "key.h"
#include "main.h"
#include "pubkey.h"
#include "txdb.h"
#include "txmempool.h"
#include "zerocoin_v3.h"

#include "test/fixtures.h"
#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

BOOST_FIXTURE_TEST_SUITE(sigma_mintspend_numinputs, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(sigma_mintspend_numinputs)
{
    vector<string> denominationsForTx;
    vector<uint256> vtxid;
    string thirdPartyAddress;
    int previousHeight;
    CBlock b;
    CWalletTx wtx;
    string stringError;

    std::vector<std::string> denominations = {"0.1", "0.5", "1", "10", "100"};
    int denominationIndexA = rand() % 5;
    int denominationIndexB = (denominationIndexA + 5) %4; //guarantees a different number in the range

    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    auto& consensus = Params().GetConsensus();

    // Create 2000 new empty blocks to get some funds. nMaxSigmaInputPerBlock == 500, so 
    // we want to create 500 coins of each denomination. For denomination 100 we need 50.000 xzc.
    CreateAndProcessEmptyBlocks(2000, scriptPubKey);

    pwalletMain->SetBroadcastTransactions(true);

    // attempt to create a zerocoin spend with more than inputs limit.
    printf("Testing number of inputs for denomination %s", denominations[denominationIndexA].c_str());
    denominationsForTx.clear();

    for (unsigned i = 0; i < (consensus.nMaxSigmaInputPerBlock + 1) * 2; i++){
        denominationsForTx.push_back(denominations[denominationIndexA]);
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominations[denominationIndexA].c_str(), SIGMA), stringError + " - Create Mint failed");
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominations[denominationIndexB].c_str(), SIGMA), stringError + " - Create Mint failed");
        if (i <= consensus.nMaxSigmaInputPerBlock) {
            denominationsForTx.push_back(denominations[denominationIndexA]);
        }
    }

    BOOST_CHECK_MESSAGE(mempool.size() == (consensus.nMaxSigmaInputPerBlock + 1) * 4, "Num input mints not added to mempool");

    // add block
    previousHeight = chainActive.Height();
    b = CreateAndProcessBlock({}, scriptPubKey);
    wtx.Init(NULL);

    //Add 5 more blocks
    for (int i = 0; i < 5; i++)
    {
        b = CreateAndProcessBlock({}, scriptPubKey);
        wtx.Init(NULL);
    }

    BOOST_CHECK_MESSAGE(previousHeight + 6 == chainActive.Height(), "Block not added to chain");
    previousHeight = chainActive.Height();

    // Check that the tx creation fails.
    BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend succeeded even though number of inputs exceed the limits");

    unsigned spendsTransactionLimit = consensus.nMaxSigmaInputPerBlock / 2;
    // Next add spendsTransactionLimit + 1 transactions with 2 inputs each, verify mempool==spendsTransactionLimit + 1. mine a block. Verify mempool still has 1 tx.
    for(unsigned i = 0; i < spendsTransactionLimit + 1; i++){
        denominationsForTx.clear();
        denominationsForTx.push_back(denominations[denominationIndexA]);
        denominationsForTx.push_back(denominations[denominationIndexB]);
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend Failed");
    }

    BOOST_CHECK_MESSAGE(mempool.size() == spendsTransactionLimit + 1, "Num input spends not added to mempool");

    // add block
    b = CreateAndProcessBlock({}, scriptPubKey);
    wtx.Init(NULL);

    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mempool not correctly cleared: Block spend limit not enforced.");

    vtxid.clear();
    mempool.clear();
    zerocoinState->Reset();
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

    auto testDenomination = sigma::CoinDenominationV3::SIGMA_DENOM_100;
    std::string testDenominationStr = std::to_string(testDenomination);
    CAmount testDenominationAmount;
    sigma::DenominationToInteger(testDenomination, testDenominationAmount);

    // Create 400-200+1 = 201 new empty blocks. // consensus.nMintV3SigmaStartBlock = 400
    CreateAndProcessEmptyBlocks(201, scriptPubKey);

    pwalletMain->SetBroadcastTransactions(true);

    // Mint coins to ensure have coins enough to choose more than value limit.
    CAmount allMintsValue(0);
    while (allMintsValue <= consensus.nMaxValueSigmaSpendPerBlock * 2){
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, testDenominationStr, SIGMA), stringError + " - Create Mint failed");
        allMintsValue += testDenominationAmount;
    }

    // Ensure all mint coins be able to use.
    BOOST_CHECK_NE(mempool.size(), 0);
    CreateAndProcessBlock({}, scriptPubKey);
    BOOST_CHECK_EQUAL(mempool.size(), 0);
    CreateAndProcessEmptyBlocks(5, scriptPubKey);

    // Try to spend at value limit with single vout.
    std::vector<CRecipient> recipients = {
        {GetScriptForDestination(randomAddr1.Get()), testDenominationAmount * 5, false},
    };

    CWalletTx tx;

    // This should fail because we need to use spends more than limit.
    BOOST_CHECK_EXCEPTION(
        pwalletMain->SpendZerocoinV3(recipients, tx),
        std::invalid_argument,
        [](const std::invalid_argument& e){return e.what() == std::string("Required amount exceed value spend limit");});

    // Try to spend at value limit with two vout.
    recipients = {
        {GetScriptForDestination(randomAddr1.Get()), testDenominationAmount * 4, false},
        {GetScriptForDestination(randomAddr2.Get()), testDenominationAmount * 1, false},
    };
    // This should fail because we need to use spends more than limit.
    BOOST_CHECK_EXCEPTION(
        pwalletMain->SpendZerocoinV3(recipients, tx),
        std::invalid_argument,
        [](const std::invalid_argument& e){return e.what() == std::string("Required amount exceed value spend limit");});

    // Try to spend two transactions which each transaction not over limit.
    // But sum of spend in both transaction exceed limit.
    // Then both transactions should be included to mempool but never be mined together.
    recipients = {
        {GetScriptForDestination(randomAddr1.Get()), testDenominationAmount * 2, false},
        {GetScriptForDestination(randomAddr2.Get()), testDenominationAmount * 1, false},
    };

    BOOST_CHECK_NO_THROW(pwalletMain->SpendZerocoinV3(recipients, tx));
    BOOST_CHECK_EQUAL(mempool.size(), 1);

    recipients = {
        {GetScriptForDestination(randomAddr1.Get()), testDenominationAmount * 3, false},
    };

    BOOST_CHECK_NO_THROW(pwalletMain->SpendZerocoinV3(recipients, tx));
    BOOST_CHECK_EQUAL(mempool.size(), 2);

    CreateAndProcessBlock({}, scriptPubKey);
    BOOST_CHECK_EQUAL(mempool.size(), 1);

    mempool.clear();
}

BOOST_AUTO_TEST_SUITE_END()

