
#include "clientversion.h"
#include "primitives/transaction.h"
#include "random.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h"
#include "test/test_bitcoin.h"

#include <stdint.h>
#include <vector>

#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "key.h"
#include "validation.h"
#include "miner.h"
#include "pubkey.h"
#include "random.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "rpc/server.h"
#include "rpc/register.h"
#include "zerocoin.h"
#include "sigma.h"

#include "test/fixtures.h"
#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

BOOST_FIXTURE_TEST_SUITE(zerocoin_tests2_v3, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(zerocoin_mintspend2_v3)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();

    //200 blocks already mined, create another 350. See Params::nSigmaPaddingBlock

    CreateAndProcessEmptyBlocks(350, scriptPubKey);

    const auto& sigmaParams = sigma::Params::get_default();

    std::vector<string> denominations = {"0.1", "0.5", "1"};
    for(string denomination : denominations) {
        string stringError;
        //Make sure that transactions get to mempool
        pwalletMain->SetBroadcastTransactions(true);

        sigma::CoinDenomination denom;
        sigma::StringToDenomination(denomination, denom);
        //Block 201 create 5 mints
        //Verify Mint is successful
        for(int i = 0; i < 5; i++)
        {
            std::vector<sigma::PrivateCoin> privCoins(1, sigma::PrivateCoin(sigmaParams, denom));

            CWalletTx wtx;
            vector<CHDMint> vDMints;
            auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);
            stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);

            BOOST_CHECK_MESSAGE(stringError == "", "Mint Failed");
        }

        //Put 5 in the same block
        BOOST_CHECK_MESSAGE(mempool.size() == 5, "Mints were not added to mempool");

        int previousHeight = chainActive.Height();
        CBlock b = CreateAndProcessBlock(scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        //Block 111, put 6 mints
        for(int i = 0; i < 6; i++) {
            std::vector<sigma::PrivateCoin> privCoins(1, sigma::PrivateCoin(sigmaParams, denom));

            CWalletTx wtx;
            vector<CHDMint> vDMints;
            auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);
            stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);

            BOOST_CHECK_MESSAGE(stringError == "", "Mint Failed");
        }

        //Put 6 in the same block
        BOOST_CHECK_MESSAGE(mempool.size() == 6, "Mints were not added to mempool");

        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        for (int i = 0; i < 5; i++)
        {
            CBlock b = CreateAndProcessBlock(scriptPubKey);
        }

        //Block 117, put 10 mints and one spend
        for(int i = 0; i < 10; i++) {
            std::vector<sigma::PrivateCoin> privCoins(1, sigma::PrivateCoin(sigmaParams, denom));

            CWalletTx wtx;
            vector<CHDMint> vDMints;
            auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);
            stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);

            BOOST_CHECK_MESSAGE(stringError == "", "Mint Failed");
        }


        std::vector<CRecipient> recipients;
        {
            // Generate address
            CPubKey newKey;
            BOOST_CHECK_MESSAGE(pwalletMain->GetKeyFromPool(newKey), "Fail to get new address");

            const CBitcoinAddress randomAddr(newKey.GetID());

            sigma::CoinDenomination denom;
            BOOST_CHECK_MESSAGE(StringToDenomination(denomination, denom), "Unable to convert denomination string to value.");

            CAmount nAmount;
            DenominationToInteger(denom, nAmount);

            recipients = {
                    {GetScriptForDestination(randomAddr.Get()), nAmount, true},
            };

            CWalletTx wtx;
            BOOST_CHECK_NO_THROW(pwalletMain->SpendSigma(recipients, wtx));
        }

        //Put 11 in the same block
        BOOST_CHECK_MESSAGE(mempool.size() == 11, "Mints were not added to mempool");

        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        //20 spends in 20 blocks
        for(int i = 0; i < 20; i++) {
            CWalletTx wtx;
            BOOST_CHECK_NO_THROW(pwalletMain->SpendSigma(recipients, wtx));
            BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spends were not added to mempool");
            previousHeight = chainActive.Height();
            b = CreateAndProcessBlock(scriptPubKey);
            BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
            BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");
        }

        //Put 19 mints
        for(int i = 0; i < 19; i++) {
            std::vector<sigma::PrivateCoin> privCoins(1, sigma::PrivateCoin(sigmaParams, denom));

            CWalletTx wtx;
            vector<CHDMint> vDMints;
            auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);
            stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);

            BOOST_CHECK_MESSAGE(stringError == "", "Mint Failed");
        }

        //Put 19 in the same block
        BOOST_CHECK_MESSAGE(mempool.size() == 19, "Mints were not added to mempool");

        previousHeight = chainActive.Height();
        b = CreateAndProcessBlock(scriptPubKey);
        BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");

        for (int i = 0; i < 5; i++)
        {
            CBlock b = CreateAndProcessBlock(scriptPubKey);
        }

        //19 spends in 19 blocks
        for(int i = 0; i < 19; i++) {
            CWalletTx wtx;
            BOOST_CHECK_NO_THROW(pwalletMain->SpendSigma(recipients, wtx));
            BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spends were not added to mempool");
            previousHeight = chainActive.Height();
            b = CreateAndProcessBlock(scriptPubKey);
            BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
            BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool not cleared");
        }
    }

    mempool.clear();
    sigmaState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
