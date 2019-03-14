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
#include "wallet/walletexcept.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

static const CBitcoinAddress randomAddr1("TSUYFnC7KbNpYxe2LtV6J2YLYafC1sncEb");
static const CBitcoinAddress randomAddr2("TKeQs4VELXhNbUypGrp9r37FXU974SQ712");

static bool isNotEnoughCoinException(const std::runtime_error& e) {
    return strcmp(e.what(),
        std::runtime_error(_("Has to have at least two mint coins with at least 6 confirmation in order to spend a coin")).what()) == 0;
}

static bool addToMempool(const CWalletTx& tx) {
    CValidationState state;
    bool fMissingInputs;
    CAmount nMaxRawTxFee = maxTxFee;
    return AcceptToMemoryPool(mempool, state, tx, true, false, &fMissingInputs, true, false, nMaxRawTxFee);
}

BOOST_FIXTURE_TEST_SUITE(sigma_partialspend, ZerocoinTestingSetup200)

/*
* 1. Create one denomination pair and check it can't be spend till 6 conf of mint
* 2. Make one more mint of denom pair and check it can't be spend till 6 conf
* 3. Create two spend transactions using same mint
* 4. Double spend with previous spend in last block
*/
BOOST_AUTO_TEST_CASE(sigma_partialspend_test)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    string denomination;
    vector<uint256> vtxid;
    std::vector<CMutableTransaction> MinTxns;
    std::vector<string> denominations = {"0.1", "0.5", "1", "10", "100"};

    CAmount smallestDenomAmount;
    sigma::DenominationToInteger(sigma::CoinDenominationV3::SIGMA_DENOM_0_1, smallestDenomAmount);

    // foreach denom from denominations
    for (const auto& denomination : denominations) {
        sigma::CoinDenominationV3 denomId;
        CAmount denomAmount;
        sigma::StringToDenomination(denomination, denomId);
        sigma::DenominationToInteger(denomId, denomAmount);

        printf("Testing denomination %s\n", denomination.c_str());
        string stringError;
        // Make sure that transactions get to mempool
        pwalletMain->SetBroadcastTransactions(true);

        // Verify Mint is successful
        vector<pair<std::string, int>> denominationPairs = {{denomination, 1}};
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
            stringError, denominationPairs, SIGMA), stringError + " - Create Mint failed");

        // Verify Mint gets in the mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

        int previousHeight = chainActive.Height();
        CBlock b = CreateAndProcessBlock(MinTxns, scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        previousHeight = chainActive.Height();
        // Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification

		std::vector<CRecipient> recipients = {
            {GetScriptForDestination(randomAddr1.Get()), denomAmount / 2, false},
            {GetScriptForDestination(randomAddr2.Get()), denomAmount / 2 - CENT, false},
        };
        for (int i = 0; i < 5; i++) {
            CWalletTx tx;
            BOOST_CHECK_EXCEPTION(
                pwalletMain->SpendZerocoinV3(recipients, tx),
                std::runtime_error,
                [](const std::runtime_error& e) {
                    return strcmp(e.what(), InsufficientFunds().what()) == 0;
                });
            std::vector<CMutableTransaction> noTxns;
            CreateAndProcessBlock(noTxns, scriptPubKey);
        }

        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        // Need 2 coin in same denomination
        CWalletTx tx;
        BOOST_CHECK_EXCEPTION(
            pwalletMain->SpendZerocoinV3(recipients, tx),
            std::runtime_error,
            isNotEnoughCoinException);

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
            stringError, denominationPairs, SIGMA), stringError + "Create Mint failed");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

        MinTxns.clear();

        previousHeight = chainActive.Height();
        CreateAndProcessBlock(MinTxns, scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");


        previousHeight = chainActive.Height();
        // Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        for (int i = 0; i < 5; i++) {
            // CWalletTx tx;
            BOOST_CHECK_EXCEPTION(
                pwalletMain->SpendZerocoinV3(recipients, tx),
                std::runtime_error,
                isNotEnoughCoinException);
            std::vector<CMutableTransaction> noTxns;
            CreateAndProcessBlock(noTxns, scriptPubKey);
        }

        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        // Create tx to do double spend before spend
        CWalletTx dtx;
        CAmount dFee;
        std::vector<CZerocoinEntryV3> dSelected;
        std::vector<CZerocoinEntryV3> dChanges;

        // Make dtx is not identical tx
        std::vector<CRecipient> dupRecipients = {
            {GetScriptForDestination(randomAddr2.Get()), denomAmount / 2, false},
            {GetScriptForDestination(randomAddr1.Get()), denomAmount / 2 - CENT, false},
        };
        dtx = pwalletMain->CreateZerocoinSpendTransactionV3(dupRecipients, dFee, dSelected, dChanges);

        // Create two spend transactions using the same mint.
        BOOST_CHECK_NO_THROW(pwalletMain->SpendZerocoinV3(recipients, tx));

        // Try to put two in the same block and it will fail, expect 1
        // And verify spend got into mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

        vtxid.clear();
        MinTxns.clear();

        b = CreateBlock(MinTxns, scriptPubKey);
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        BOOST_CHECK_NO_THROW(pwalletMain->SpendZerocoinV3(recipients, tx));

        //Verify spend got into mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

        MinTxns.clear();

        b = CreateBlock(MinTxns, scriptPubKey);
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        // Test double spend with previous spend in last block
        BOOST_CHECK_MESSAGE(!addToMempool(dtx), "Spend created although double");
        // This confirms that double spend is blocked and cannot enter mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not empty although mempool should reject double spend");

        // Temporary disable usedCoinSerials check to force double spend in mempool
        auto tempSerials = zerocoinState->usedCoinSerials;
        zerocoinState->usedCoinSerials.clear();

        BOOST_CHECK_MESSAGE(addToMempool(dtx), "Spend created although double");
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mempool not set");
        zerocoinState->usedCoinSerials = tempSerials;

        MinTxns.clear();
        BOOST_CHECK_EXCEPTION(CreateBlock(MinTxns, scriptPubKey), std::runtime_error, no_check);
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mempool not set");
        vtxid.clear();
        mempool.queryHashes(vtxid);
        MinTxns.clear();
        MinTxns.push_back(*mempool.get(vtxid.at(0)));
        tempSerials = zerocoinState->usedCoinSerials;
        zerocoinState->usedCoinSerials.clear();
        CreateBlock(MinTxns, scriptPubKey);
        zerocoinState->usedCoinSerials = tempSerials;

        mempool.clear();
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed");
        // This test confirms that a block containing a double spend is rejected and not added in the chain
        BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Double spend - Block added to chain even though same spend in previous block");

        vtxid.clear();
        MinTxns.clear();
        mempool.clear();
        zerocoinState->Reset();
    }
}

BOOST_AUTO_TEST_CASE(sigma_remits_test) {
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    std::vector<CMutableTransaction> MinTxns;

    CAmount denomAmount1;
    CAmount denomAmount01;
    sigma::DenominationToInteger(sigma::CoinDenominationV3::SIGMA_DENOM_1, denomAmount1);
    sigma::DenominationToInteger(sigma::CoinDenominationV3::SIGMA_DENOM_0_1, denomAmount01);

    string stringError;
    // Make sure that transactions get to mempool
    pwalletMain->SetBroadcastTransactions(true);

    // Verify Mint is successful
    vector<pair<std::string, int>> denominationPairs = {{"1", 2}};
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
            stringError, denominationPairs, SIGMA), stringError + " - Create Mint failed");

    // Verify Mint gets in the mempool
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");

    int previousHeight = chainActive.Height();
    CBlock b = CreateAndProcessBlock(MinTxns, scriptPubKey);
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

    std::vector<CRecipient> recipients = {
        {GetScriptForDestination(randomAddr1.Get()), denomAmount1 , false},
        {GetScriptForDestination(randomAddr2.Get()), denomAmount1 - CENT - 2 * denomAmount01, false},
    };

    previousHeight = chainActive.Height();
    // Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification

    for (int i = 0; i < 5; i++) {
        CWalletTx tx;
        BOOST_CHECK_EXCEPTION(
            pwalletMain->SpendZerocoinV3(recipients, tx),
            std::runtime_error,
            [](const std::runtime_error& e) {
                return strcmp(e.what(), InsufficientFunds().what()) == 0;
            });
        std::vector<CMutableTransaction> noTxns;
        CreateAndProcessBlock(noTxns, scriptPubKey);
    }

    BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

    // spend all and should remints 2 coins of denomination 0.1
    CWalletTx tx;
    BOOST_CHECK_NO_THROW(pwalletMain->SpendZerocoinV3(recipients, tx));

    // Try to put two in the same block and it will fail, expect 1
    // And verify spend got into mempool
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

    previousHeight = chainActive.Height();
    CreateAndProcessBlock(MinTxns, scriptPubKey);
    BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

    recipients = {
        {GetScriptForDestination(randomAddr1.Get()), denomAmount01 , false},
        {GetScriptForDestination(randomAddr2.Get()), denomAmount01 - CENT, false},
    };

    previousHeight = chainActive.Height();
    // Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification

    for (int i = 0; i < 5; i++) {
        CWalletTx tx;
        BOOST_CHECK_EXCEPTION(
            pwalletMain->SpendZerocoinV3(recipients, tx),
            std::runtime_error,
            [](const std::runtime_error& e) {
                return strcmp(e.what(), InsufficientFunds().what()) == 0;
            });
        std::vector<CMutableTransaction> noTxns;
        CreateAndProcessBlock(noTxns, scriptPubKey);
    }

    BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

    // Use remints
    BOOST_CHECK_NO_THROW(pwalletMain->SpendZerocoinV3(recipients, tx));

    MinTxns.clear();
    mempool.clear();
    zerocoinState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
