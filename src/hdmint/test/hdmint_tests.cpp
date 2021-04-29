#include "util.h"

#include "clientversion.h"
#include "primitives/transaction.h"
#include "random.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h"
#include "test/test_bitcoin.h"

#include <stdint.h>
#include <vector>
#include <iostream>

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
#include "firo_params.h"

#include "test/fixtures.h"
#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

using namespace sigma;

BOOST_FIXTURE_TEST_SUITE(hdmint_tests, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(deterministic)
{
    vector<string> denominationsForTx;
    vector<uint256> vtxid;
    int previousHeight;
    CBlock b;
    CWalletTx wtx;

    int mintCount = 0;

    std::vector<std::string> denominations = {"0.05", "0.1", "0.5", "1", "10", "25", "100"};

    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();

    pwalletMain->SetBroadcastTransactions(true);

    vector<CHDMint> vDMints;
    vector<CHDMint> vDMintsBuilder;
    vector<CHDMint> vDMintsRegenerated;
    std::vector<sigma::PrivateCoin> privCoins;
    const auto& sigmaParams = sigma::Params::get_default();

    int mempoolCount = 0;

    for(int i = 0; i < denominations.size() - 1; i++)
    {
        vDMintsBuilder.clear();
        denominationsForTx.clear();
        denominationsForTx.push_back(denominations[i]);
        denominationsForTx.push_back(denominations[i+1]);

        //Make sure that transactions get to mempool
        pwalletMain->SetBroadcastTransactions(true);
        privCoins.clear();
        //Verify Mint is successful
        for(int i = 0; i < 2; ++i) {
            sigma::CoinDenomination denomination;
            sigma::StringToDenomination(denominationsForTx[i], denomination);
            privCoins.push_back(sigma::PrivateCoin(sigmaParams, denomination));
            mintCount++;
        }

        auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMintsBuilder);
        CWalletTx wtx;
        string stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMintsBuilder, wtx);

        BOOST_CHECK_MESSAGE(stringError == "", "Mint Failed");

        // Verify mint tx get added in the mempool
        BOOST_CHECK_MESSAGE(mempool.size() == ++mempoolCount, "Mint tx was not added to mempool");

        // Verify correct mint count
        BOOST_CHECK(mintCount == pwalletMain->zwallet->GetCount());

        for(auto& mint : vDMintsBuilder){
            vDMints.push_back(mint);
        }
    }

    // We now have 10 mints, each stored in vDMints.
    // reset the count
    // Clear HDMints in db and sigma state (to allow regeneration of the same mints)

    CWalletDB walletdb(pwalletMain->strWalletFile);
    pwalletMain->zwallet->SetCount(0);
    mintCount = 0;
    sigmaState->Reset();
    pwalletMain->ZapSigmaMints();

    for(int i = 0; i < denominations.size() - 1; i++)
    {
        vDMintsBuilder.clear();
        denominationsForTx.clear();
        denominationsForTx.push_back(denominations[i]);
        denominationsForTx.push_back(denominations[i+1]);
        string stringError;
        //Make sure that transactions get to mempool
        pwalletMain->SetBroadcastTransactions(true);
        privCoins.clear();
        //Verify Mint is successful
        for(int i = 0; i < 2; ++i) {
            sigma::CoinDenomination denomination;
            sigma::StringToDenomination(denominationsForTx[i], denomination);
            privCoins.push_back(sigma::PrivateCoin(sigmaParams, denomination));
            mintCount++;
        }

        auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMintsBuilder);
        CWalletTx wtx;
        stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMintsBuilder, wtx);

        BOOST_CHECK_MESSAGE(stringError == "", "Mint Failed");

        // Verify correct mint count
        BOOST_CHECK(mintCount == pwalletMain->zwallet->GetCount());

        for(auto& mint : vDMintsBuilder){
            vDMintsRegenerated.push_back(mint);
        }
    }

    BOOST_CHECK(vDMints.size() == vDMintsRegenerated.size());

    for(int i=0; i<vDMints.size();i++){
        BOOST_CHECK(vDMints[i].GetCount() == vDMintsRegenerated[i].GetCount());
        BOOST_CHECK(vDMints[i].GetSeedId() == vDMintsRegenerated[i].GetSeedId());
        BOOST_CHECK(vDMints[i].GetSerialHash() == vDMintsRegenerated[i].GetSerialHash());
        BOOST_CHECK(vDMints[i].GetPubCoinHash() == vDMintsRegenerated[i].GetPubCoinHash());
    }

}

/*
HDMint wallet count test
- test that if passed a used count, the wallet will generate the next available count.
*/
BOOST_AUTO_TEST_CASE(wallet_count)
{
    vector<string> denominationsForTx;
    vector<uint256> vtxid;
    int previousHeight;
    CBlock b;
    CWalletTx wtx;

    const int TOTAL_MINTS = 5;
    const int INITIAL_MINTS = TOTAL_MINTS-1;

    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();

    pwalletMain->SetBroadcastTransactions(true);

    for(int i=0; i<=INITIAL_MINTS;i++){
        CAmount nAmount = AmountFromValue("1");

        std::vector<sigma::CoinDenomination> denominations;
        sigma::GetAllDenoms(denominations);

        CAmount smallestDenom;
        DenominationToInteger(denominations.back(), smallestDenom);

        BOOST_CHECK_MESSAGE(nAmount % smallestDenom == 0, "Amount to mint is invalid.\n");

        std::vector<sigma::CoinDenomination> mints;

        BOOST_CHECK(CWallet::SelectMintCoinsForAmount(nAmount, denominations, mints) == nAmount);

        std::vector<sigma::PrivateCoin> privCoins;

        const auto& sigmaParams = sigma::Params::get_default();
        std::transform(mints.begin(), mints.end(), std::back_inserter(privCoins),
            [sigmaParams](const sigma::CoinDenomination& denom) -> sigma::PrivateCoin {
                return sigma::PrivateCoin(sigmaParams, denom);
            });
        vector<CHDMint> vDMints;
        auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);

        CWalletTx wtx;
        std::string strError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);

        BOOST_CHECK(strError == "");
    }

    pwalletMain->zwallet->SetCount(0); // reset count

    // create another mint
    CAmount nAmount = AmountFromValue("1");

    std::vector<sigma::CoinDenomination> denominations;
    sigma::GetAllDenoms(denominations);

    CAmount smallestDenom;
    DenominationToInteger(denominations.back(), smallestDenom);

    BOOST_CHECK_MESSAGE(nAmount % smallestDenom == 0, "Amount to mint is invalid.\n");

    std::vector<sigma::CoinDenomination> mints;
    BOOST_CHECK(CWallet::SelectMintCoinsForAmount(nAmount, denominations, mints) == nAmount);

    std::vector<sigma::PrivateCoin> privCoins;

    const auto& sigmaParams = sigma::Params::get_default();
    std::transform(mints.begin(), mints.end(), std::back_inserter(privCoins),
    [sigmaParams](const sigma::CoinDenomination& denom) -> sigma::PrivateCoin {
        return sigma::PrivateCoin(sigmaParams, denom);
    });
    vector<CHDMint> vDMints;
    auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);

    BOOST_CHECK(vDMints[0].GetCount() == TOTAL_MINTS);
    BOOST_CHECK(pwalletMain->zwallet->GetCount() == (TOTAL_MINTS+1));

}

/*
HDMint wallet blockchain restore test
- Create and add mints to chain, save mints
- Clear wallet count and HDMint db entries
- SyncWithChain - Verify mints restored are the same
*/
BOOST_AUTO_TEST_CASE(blockchain_restore)
{
    vector<string> denominationsForTx;
    vector<uint256> vtxid;
    int previousHeight;
    CBlock b;
    CWalletTx wtx;

    int mintCount = 0;

    std::vector<std::string> denominations = {"0.05", "0.1", "0.5", "1", "10", "25", "100"};

    pwalletMain->SetBroadcastTransactions(true);

    std::vector<sigma::PrivateCoin> privCoins;

    vector<CHDMint> vDMints;
    vector<CHDMint> vDMintsBuilder;
    const auto& sigmaParams = sigma::Params::get_default();

    for(int i = 0; i < denominations.size() - 1; i++)
    {
        vDMintsBuilder.clear();
        denominationsForTx.clear();
        denominationsForTx.push_back(denominations[i]);
        denominationsForTx.push_back(denominations[i+1]);
        string stringError;
        //Make sure that transactions get to mempool
        privCoins.clear();
        //Verify Mint is successful
        for(int i = 0; i < 2; ++i) {
            sigma::CoinDenomination denomination;
            sigma::StringToDenomination(denominationsForTx[i], denomination);
            privCoins.push_back(sigma::PrivateCoin(sigmaParams, denomination));
            mintCount++;
        }

        auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMintsBuilder);
        CWalletTx wtx;
        stringError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMintsBuilder, wtx);

        BOOST_CHECK_MESSAGE(stringError == "", "Mint Failed");

        // Verify mint tx get added in the mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint tx was not added to mempool");

        // Verify correct mint count
        BOOST_CHECK(mintCount == pwalletMain->zwallet->GetCount());

        for(auto& mint : vDMintsBuilder){
            vDMints.push_back(mint);
        }

        for(int i = 0; i < ZC_MINT_CONFIRMATIONS; i++){
            int previousHeight = chainActive.Height();
            b = CreateAndProcessBlock(scriptPubKey);
            BOOST_CHECK_MESSAGE(previousHeight + 1 == chainActive.Height(), "Block not added to chain");
        }
    }

    // We now have 10 mints, each stored in vDMints.
    // reset the count
    // Clear HDMints in db and sigma state (to allow regeneration of the same mints)
    // erase mint pool/ serialHash->pubcoin pairs
    CWalletDB walletdb(pwalletMain->strWalletFile);
    pwalletMain->ZapSigmaMints();

    vector<std::pair<uint256, MintPoolEntry>> listMintPool = walletdb.ListMintPool();
    std::vector<std::pair<uint256, GroupElement>> serialPubcoinPairs = walletdb.ListSerialPubcoinPairs();
    uint256 hashSerial;
    uint256 hashPubcoin;
    for (auto& mintPoolPair : listMintPool){
        hashPubcoin = mintPoolPair.first;
        pwalletMain->zwallet->GetSerialForPubcoin(serialPubcoinPairs, hashPubcoin, hashSerial);
        walletdb.EraseMintPoolPair(hashPubcoin);
        walletdb.ErasePubcoin(hashSerial);
    }

    // Start pwalletMain->zwallet from scratch
    pwalletMain->zwallet = std::make_unique<CHDMintWallet>(pwalletMain->strWalletFile, true);

    // sync mints with chain (will regenerate mintpool + sync with chain)
    pwalletMain->zwallet->SyncWithChain();

    // Pull mints from the wallet
    std::list<CHDMint> vDMintsRegeneratedList = walletdb.ListHDMints(false);
    vector<CHDMint> vDMintsRegenerated(vDMintsRegeneratedList.begin(), vDMintsRegeneratedList.end());

    BOOST_CHECK(vDMints.size() == vDMintsRegenerated.size());

    for(int i=0; i<vDMints.size();i++){
        bool found = false;
        for(int j=0; (j<vDMintsRegenerated.size())||!found;j++){
            if(vDMints[i].GetCount() == vDMintsRegenerated[j].GetCount()){
                BOOST_CHECK(vDMints[i].GetCount() == vDMintsRegenerated[j].GetCount());
                BOOST_CHECK(vDMints[i].GetSeedId() == vDMintsRegenerated[j].GetSeedId());
                BOOST_CHECK(vDMints[i].GetSerialHash() == vDMintsRegenerated[j].GetSerialHash());
                BOOST_CHECK(vDMints[i].GetPubCoinHash() == vDMintsRegenerated[j].GetPubCoinHash());
                found=true;
            }
        }
        BOOST_CHECK_MESSAGE(found, "Same mint not regenerated.");
    }

}

BOOST_AUTO_TEST_SUITE_END()
