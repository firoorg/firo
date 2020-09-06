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

BOOST_FIXTURE_TEST_SUITE(sigma_mintspend_many, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(sigma_mintspend_many)
{
    vector<string> denominationsForTx;
    vector<uint256> vtxid;
    string thirdPartyAddress;
    int previousHeight;
    CBlock b;
    CWalletTx wtx;

    std::vector<std::string> denominations = {"0.05", "0.1", "0.5", "1", "10", "25", "100"};

    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();

    //200 blocks already mined, create another 200.
    CreateAndProcessEmptyBlocks(200, scriptPubKey);

    pwalletMain->SetBroadcastTransactions(true);

    std::vector<sigma::PrivateCoin> privCoins;
    const auto& sigmaParams = sigma::Params::get_default();

    for(size_t i = 0; i < denominations.size() - 1; i++)
    {
        denominationsForTx.clear();
        denominationsForTx.push_back(denominations[i]);
        CAmount nAmount(0);
        sigma::CoinDenomination denom;
        BOOST_CHECK_MESSAGE(StringToDenomination(denominationsForTx[0], denom), "Unable to convert denomination string to value.");

        CAmount intDenom;
        DenominationToInteger(denom, intDenom);
        nAmount += intDenom;
        denominationsForTx.push_back(denominations[i+1]);
        BOOST_CHECK_MESSAGE(StringToDenomination(denominationsForTx[1], denom), "Unable to convert denomination string to value.");

        DenominationToInteger(denom, intDenom);
        nAmount += intDenom;

        string stringError;
        //Make sure that transactions get to mempool
        pwalletMain->SetBroadcastTransactions(true);
        privCoins.clear();

        //Verify Mint is successful
        for(int i = 0; i < 2; ++i) {
            sigma::CoinDenomination denomination;
            sigma::StringToDenomination(denominationsForTx[i], denomination);
            privCoins.push_back(sigma::PrivateCoin(sigmaParams, denomination));
        }

        vector<CHDMint> vDMints;
        auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);
        wtx.Init(NULL);
        stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);

        BOOST_CHECK_MESSAGE(stringError == "", "Mint Failed");

        // Verify mint tx get added in the mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint tx was not added to mempool");

        int previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        previousHeight = chainActive.Height();
        wtx.Init(NULL);

        // Generate address
        CPubKey newKey;
        BOOST_CHECK_MESSAGE(pwalletMain->GetKeyFromPool(newKey), "Fail to get new address");

        const CBitcoinAddress randomAddr(newKey.GetID());

        std::vector<CRecipient> recipients = {
                {GetScriptForDestination(randomAddr.Get()), nAmount, true},
        };
        //Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        for (int i = 0; i < 5; i++)
        {
            BOOST_CHECK_THROW(pwalletMain->SpendSigma(recipients, wtx), WalletError); //this must throw as 6 blocks have not passed yet,

            b = CreateAndProcessBlock(scriptPubKey);
            wtx.Init(NULL);
        }
        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        wtx.Init(NULL);

        BOOST_CHECK_THROW(pwalletMain->SpendSigma(recipients, wtx), WalletError); //this must throw as it has to have at least two mint coins with at least 6 confirmation

        vDMints.clear();
        vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);
        wtx.Init(NULL);
        stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);

        BOOST_CHECK_MESSAGE(stringError == "", "Mint Failed");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint tx was not added to mempool");

        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");


        previousHeight = chainActive.Height();
        //Add 5 more blocks and verify that Mint can not be spent until 6 blocks verification
        wtx.Init(NULL);
        for (int i = 0; i < 5; i++)
        {
            BOOST_CHECK_THROW(pwalletMain->SpendSigma(recipients, wtx), WalletError); //this must throw as 6 blocks have not passed yet,

            b = CreateAndProcessBlock(scriptPubKey);
            wtx.Init(NULL);
        }

        BOOST_CHECK_MESSAGE(previousHeight + 5 == chainActive.Height(), "Block not added to chain");

        // Create two spend transactions using the same mints
        std::vector<CSigmaEntry> coins;
        {
            std::vector <CHDMint> changes;
            CAmount fee;
            bool fChangeAddedToFee;
            wtx = pwalletMain->CreateSigmaSpendTransaction(recipients, fee, coins, changes, fChangeAddedToFee);
            pwalletMain->CommitSigmaTransaction(wtx, coins, changes);
        }
        BOOST_CHECK_MESSAGE(wtx.tx->vin.size() == 2, "Incorrect inputs size");
        BOOST_CHECK_MESSAGE(wtx.tx->vout.size() == 1, "Incorrect output size");
        //Set mints unused, and try to spend again
        for(auto mint : coins)
            pwalletMain->zwallet->GetTracker().SetPubcoinNotUsed(primitives::GetPubCoinValueHash(mint.value));

        wtx.Init(NULL);
        BOOST_CHECK_NO_THROW(pwalletMain->SpendSigma(recipients, wtx));

//        Try to put two in the same block and it will fail, expect 1
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spends was not added to mempool");
        wtx.Init(NULL);
        //roll back mints used
        for(auto mint : coins)
            pwalletMain->zwallet->GetTracker().SetPubcoinUsed(primitives::GetPubCoinValueHash(mint.value), uint256());
        b = CreateBlock(scriptPubKey);
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        coins.clear();
        {
            std::vector <CHDMint> changes;
            CAmount fee;
            bool fChangeAddedToFee;
            wtx = pwalletMain->CreateSigmaSpendTransaction(recipients, fee, coins, changes, fChangeAddedToFee);
            pwalletMain->CommitSigmaTransaction(wtx, coins, changes);
        }
        BOOST_CHECK_MESSAGE(wtx.tx->vin.size() == 2, "Incorrect inputs size");
        BOOST_CHECK_MESSAGE(wtx.tx->vout.size() == 1, "Incorrect output size");

        //Verify spend got into mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

        b = CreateBlock(scriptPubKey);
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed although valid spend inside");
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");
        wtx.Init(NULL);

        //Set mints unused, and try to spend again
        for(auto mint : coins)
            pwalletMain->zwallet->GetTracker().SetPubcoinNotUsed(primitives::GetPubCoinValueHash(mint.value));

        BOOST_CHECK_NO_THROW(pwalletMain->SpendSigma(recipients, wtx));
        //This confirms that double spend is blocked and cannot enter mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not empty although mempool should reject double spend");

        //Temporary disable usedCoinSerials check to force double spend in mempool
        auto tempSerials = sigmaState->GetSpends();
        sigmaState->containers.usedCoinSerials.clear();

        wtx.Init(NULL);

        for(auto mint : coins)
            pwalletMain->zwallet->GetTracker().SetPubcoinNotUsed(primitives::GetPubCoinValueHash(mint.value));
        BOOST_CHECK_NO_THROW(pwalletMain->SpendSigma(recipients, wtx));
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "mempool not set after used coin serials removed");
        sigmaState->containers.usedCoinSerials = tempSerials;

        BOOST_CHECK_EXCEPTION(CreateBlock(scriptPubKey), std::runtime_error, no_check);
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "mempool not set after block created");

        tempSerials = sigmaState->containers.usedCoinSerials;
        sigmaState->containers.usedCoinSerials.clear();
        CreateBlock(scriptPubKey);
        sigmaState->containers.usedCoinSerials = tempSerials;

        mempool.clear();
        previousHeight = chainActive.Height();
        BOOST_CHECK_MESSAGE(ProcessBlock(b), "ProcessBlock failed");
        //This test confirms that a block containing a double spend is rejected and not added in the chain
        BOOST_CHECK_MESSAGE(previousHeight == chainActive.Height(), "Double spend - Block added to chain even though same spend in previous block");

        mempool.clear();
        sigmaState->mempoolCoinSerials.clear();

        // Test: send to third party address.
        // mint two of each denom
        privCoins.clear();
        for(int i=0;i<2;i++){
            sigma::CoinDenomination denomination;
            sigma::StringToDenomination(denominationsForTx[i], denomination);
            privCoins.push_back(sigma::PrivateCoin(sigmaParams, denomination));
            privCoins.push_back(sigma::PrivateCoin(sigmaParams, denomination));

        }
        vDMints.clear();
        vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);
        wtx.Init(NULL);
        stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);

        BOOST_CHECK_MESSAGE(stringError == "", "Mint Failed");

        // verify mints got to mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "mint tx not added to mempool");

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

        //roll back mints used
        for(auto mint : coins)
            pwalletMain->zwallet->GetTracker().SetPubcoinUsed(primitives::GetPubCoinValueHash(mint.value), uint256());

        // send to third party address.
        thirdPartyAddress = "TXYb6pEWBDcxQvTxbFQ9sEV1c3rWUPGW3v";
        const CBitcoinAddress address(thirdPartyAddress);

        recipients = {
                {GetScriptForDestination(address.Get()), nAmount, true},
                };
        BOOST_CHECK_NO_THROW(pwalletMain->SpendSigma(recipients, wtx));
        BOOST_CHECK_MESSAGE(wtx.tx->vin.size() == 2, "Incorrect inputs size");
        BOOST_CHECK_MESSAGE(wtx.tx->vout.size() == 1, "Incorrect output size");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "third party spend not added to mempool");

        b = CreateAndProcessBlock(scriptPubKey);
        wtx.Init(NULL);

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "third party spend not succeeded");

        vtxid.clear();
        mempool.clear();
        sigmaState->Reset();
    }


    // create transactions using the same denomination
    for(size_t i = 0; i < denominations.size(); i++)
    {
        string stringError;

        privCoins.clear();
        sigma::CoinDenomination denomination;
        sigma::StringToDenomination(denominations[i], denomination);
        privCoins.push_back(sigma::PrivateCoin(sigmaParams, denomination));
        privCoins.push_back(sigma::PrivateCoin(sigmaParams, denomination));

        vector<CHDMint> vDMints;
        auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);
        wtx.Init(NULL);
        stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);

        BOOST_CHECK_MESSAGE(stringError == "", "Mint Failed");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Same denom mint tx not added to mempool");

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

        // Generate address
        CPubKey newKey;
        BOOST_CHECK_MESSAGE(pwalletMain->GetKeyFromPool(newKey), "Fail to get new address");

        const CBitcoinAddress randomAddr(newKey.GetID());

        sigma::CoinDenomination denom;
        BOOST_CHECK_MESSAGE(StringToDenomination(denominations[i], denom), "Unable to convert denomination string to value.");

        CAmount nAmount;
        DenominationToInteger(denom, nAmount);

        std::vector<CRecipient> recipients = {
                {GetScriptForDestination(randomAddr.Get()), nAmount * 2, true},
        };
        BOOST_CHECK_NO_THROW(pwalletMain->SpendSigma(recipients, wtx));

        BOOST_CHECK_MESSAGE(wtx.tx->vin.size() == 2, "Incorrect inputs size");
        BOOST_CHECK_MESSAGE(wtx.tx->vout.size() == 1, "Incorrect output size");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Same denom spend not added to mempool");

        b = CreateAndProcessBlock(scriptPubKey);
        wtx.Init(NULL);

        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Same denom spend not succeeded");

        vtxid.clear();
        mempool.clear();
        sigmaState->Reset();
    }
}

BOOST_AUTO_TEST_CASE(zerocoin_mintspend_usedinput)
{
    vector<string> denominationsForTx;
    vector<uint256> vtxid;
    // Generate address
    CPubKey newKey;
    BOOST_CHECK_MESSAGE(pwalletMain->GetKeyFromPool(newKey), "Fail to get new address");
    const CBitcoinAddress randomAddr(newKey.GetID());

    int previousHeight;
    CBlock b;
    CWalletTx wtx;

    std::vector<std::string> denominations = {"0.05", "0.1", "0.5", "1", "10", "25", "100"};

    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();

    // Create 400-200+1 = 201 new empty blocks. // consensus.nMintV3SigmaStartBlock = 400
    CreateAndProcessEmptyBlocks(201, scriptPubKey);

    pwalletMain->SetBroadcastTransactions(true);

    // attempt to add a mixed input spend in one block, and use of the inputs into another tx in the next block.
    denominationsForTx.clear();
    denominationsForTx.push_back(denominations[rand() % 7]);
    denominationsForTx.push_back(denominations[rand() % 7]);
    string stringError;

    std::vector<sigma::PrivateCoin> privCoins;
    const auto& sigmaParams = sigma::Params::get_default();
    CAmount nAmount(0);
    CAmount lastIntDenom(0);
    for (int i = 0; i < 2; i++){
        sigma::CoinDenomination denomination;
        sigma::StringToDenomination(denominationsForTx[i], denomination);
        privCoins.push_back(sigma::PrivateCoin(sigmaParams, denomination));
        privCoins.push_back(sigma::PrivateCoin(sigmaParams, denomination));

        DenominationToInteger(denomination, lastIntDenom);
        nAmount += lastIntDenom;
    }

    vector<CHDMint> vDMints;
    auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);
    wtx.Init(NULL);
    stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);

    BOOST_CHECK_MESSAGE(stringError == "", "Mint Failed");

    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Used input mint not added to mempool");

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

    BOOST_CHECK_NO_THROW(pwalletMain->SpendSigma(recipients, wtx));
    BOOST_CHECK_MESSAGE(wtx.tx->vin.size() == denominationsForTx.size(), "Incorrect inputs size");
    BOOST_CHECK_MESSAGE(wtx.tx->vout.size() == 1, "Incorrect output size");

    BOOST_CHECK_NO_THROW(pwalletMain->SpendSigma(recipients, wtx));
    BOOST_CHECK_MESSAGE(wtx.tx->vin.size() == denominationsForTx.size(), "Incorrect inputs size");
    BOOST_CHECK_MESSAGE(wtx.tx->vout.size() == 1, "Incorrect output size");

    BOOST_CHECK_MESSAGE(mempool.size() == 2, "Same denom spend not added to mempool");

    b = CreateAndProcessBlock(scriptPubKey);
    wtx.Init(NULL);

    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Same denom spend not succeeded");

    // Now add one of the inputs into another spend and verify it fails..
    nAmount -= lastIntDenom;
    recipients = {
        {GetScriptForDestination(randomAddr.Get()), nAmount, true},
    };
    BOOST_CHECK_THROW(pwalletMain->SpendSigma(recipients, wtx), WalletError);

    // Now mint two more of the first denomination, but don't mine the needed blocks, preventing their usage. verify transaction creation fails
    privCoins.clear();

    sigma::CoinDenomination denomination;
    sigma::StringToDenomination(denominationsForTx[0], denomination);
    privCoins.push_back(sigma::PrivateCoin(sigmaParams, denomination));
    privCoins.push_back(sigma::PrivateCoin(sigmaParams, denomination));

    vDMints.clear();
    vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);
    wtx.Init(NULL);
    stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);

    BOOST_CHECK_MESSAGE(stringError == "", "Mint Failed");

    BOOST_CHECK_THROW(pwalletMain->SpendSigma(recipients, wtx), WalletError);

    vtxid.clear();
    mempool.clear();
    sigmaState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
