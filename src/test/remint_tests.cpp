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

#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "key.h"
#include "main.h"
#include "miner.h"
#include "pubkey.h"
#include "random.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "rpc/server.h"
#include "rpc/register.h"
#include "zerocoin.h"

#include "test/fixtures.h"
#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

BOOST_FIXTURE_TEST_SUITE(zerocoin_to_sigma_remint_tests, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(remint_basic_test)
{
    string denomination;
    vector<uint256> vtxid;
    std::vector<string> denominations = {"1", "10", "25", "50", "100", "100"};

    string stringError;
    CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();

    pwalletMain->SetBroadcastTransactions(true);

    // Mint 1 XZC zerocoin and remint it on wrong fork
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, "1"), stringError + " - Create Mint failed");
    CreateAndProcessBlock({}, scriptPubKey);
    CBlockIndex *forkBlockIndex = chainActive.Tip();
    // Get to the sigma portion
    for (int i=0; i<200; i++)
        CreateAndProcessBlock({}, scriptPubKey);
    CWalletTx remintOnWrongForkTx;
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinToSigmaRemintModel(stringError, ZEROCOIN_TX_VERSION_2, (libzerocoin::CoinDenomination)1, &remintOnWrongForkTx), stringError + " - Remint failed");
    CreateAndProcessBlock({}, scriptPubKey);

    // Invalidate chain
    {
        LOCK(cs_main);
        CValidationState state;
        InvalidateBlock(state, Params(), forkBlockIndex);
    }
    // Mint and remint txs should be in the mempool now, clear them
    mempool.clear();

    for (int i=0; i<6; i++) {
        denomination = denominations[i];
        string stringError;

        //Verify Mint is successful
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denomination.c_str()), stringError + " - Create Mint failed");

        //Verify Mint gets in the mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Zerocoin mint was not added to mempool");

        CreateAndProcessBlock({}, scriptPubKey);
    }

    for (int i=0; i<5; i++)
        CreateAndProcessBlock({}, scriptPubKey);

    // spend coin for 100 xzc
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", "100", false, true), stringError + " - 100 xzc spend failed");
    CreateAndProcessBlock({}, scriptPubKey);
    BOOST_CHECK_MESSAGE(zerocoinState->usedCoinSerials.size() == 1, "Incorrect used coin serial state after zerocoin spend");
    CBigNum zcSpentSerial = *zerocoinState->usedCoinSerials.begin();

    // get to the sigma portion
    for (int i=0; i<200; i++) {
        CBlock b = CreateAndProcessBlock({}, scriptPubKey);
    }
    // Intentionally do not remint the second 100
    for (int i=0; i<5; i++) {
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinToSigmaRemintModel(stringError, ZEROCOIN_TX_VERSION_2, (libzerocoin::CoinDenomination)atoi(denominations[i].c_str())), stringError + " - Remint failed");
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Zerocoin remint was not added to mempool");
        for (int i=0; i<5; i++)
            CreateAndProcessBlock({}, scriptPubKey);
    }

    // test if sigma mints are spendable
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", "25"), "Sigma spend failed");
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

    for (int i=0; i<5; i++)
        CreateAndProcessBlock({}, scriptPubKey);

    // try double spend by modifying wallet and list of spent serials
    //Temporary disable usedCoinSerials check to force double spend in mempool
    CWalletDB walletdb(pwalletMain->strWalletFile);
    for (const Bignum &serial: zerocoinState->usedCoinSerials) {
        CZerocoinSpendEntry spendEntry;
        spendEntry.coinSerial = serial;
        walletdb.EraseCoinSpendSerialEntry(spendEntry);
    }

    std::list<CZerocoinEntry> zcEntries;
    walletdb.ListPubCoin(zcEntries);
    for (auto &zcEntry : zcEntries) {
        if (zcEntry.IsUsedForRemint) {
            zcEntry.IsUsed = zcEntry.IsUsedForRemint = false;
            walletdb.WriteZerocoinEntry(zcEntry);
        }
    }
    
    auto tempSerials = zerocoinState->usedCoinSerials;
    zerocoinState->usedCoinSerials.clear();

    // Retry remint of 1. Should pass for now
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinToSigmaRemintModel(stringError, ZEROCOIN_TX_VERSION_2, (libzerocoin::CoinDenomination)1), stringError + " - Remint failed");

    // Restore state and generate a block. TestBlockValidity() should fail due to seen serial
    zerocoinState->usedCoinSerials = tempSerials;
    try {
        CreateAndProcessBlock({}, scriptPubKey);
        BOOST_FAIL("Block is created despite having double spend in it");
    }
    catch (std::runtime_error &err) {
        BOOST_CHECK(strstr(err.what(), "TestBlockValidity") != nullptr);
    }

    // clear mempool
    mempool.clear();
    // Block should be created now
    CreateAndProcessBlock({}, scriptPubKey);

    // Temporarily remove spent coin from the list of spent serials
    zerocoinState->usedCoinSerials.erase(zcSpentSerial);

    // Try remint for 100 xzc. Again should pass
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinToSigmaRemintModel(stringError, ZEROCOIN_TX_VERSION_2, (libzerocoin::CoinDenomination)100), stringError + " - Remint failed");

    // Restore state and verify that it fails to get into the block because it was spent as zerocoin
    zerocoinState->usedCoinSerials = tempSerials;
    try {
        CreateAndProcessBlock({}, scriptPubKey);
        BOOST_FAIL("Block is created despite having double spend in it");
    }
    catch (std::runtime_error &err) {
        BOOST_CHECK(strstr(err.what(), "TestBlockValidity") != nullptr);
    }

    // clear mempool again
    mempool.clear();
    // Block should be created now
    CreateAndProcessBlock({}, scriptPubKey);

    // We've got remint saved that references zerocoin mint from the wrong fork. It shouldn't validate now
    pwalletMain->CommitTransaction(remintOnWrongForkTx);
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Remint for non-existent mint was added to the mempool");
}

BOOST_AUTO_TEST_CASE(remint_blacklist)
{
    string stringError;

    pwalletMain->SetBroadcastTransactions(true);

    //Verify Mint is successful
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, "1"), stringError + " - Create Mint failed");

    //Verify Mint gets in the mempool
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Zerocoin mint was not added to mempool");

    // get to the sigma portion
    for (int i=0; i<400; i++) {
        CBlock b = CreateAndProcessBlock({}, scriptPubKey);
    }

    // make an additional entry to the black list
    CWalletDB walletdb(pwalletMain->strWalletFile);
    std::list<CZerocoinEntry> pubCoins;
    walletdb.ListPubCoin(pubCoins);

    // there should be exactly one
    BOOST_CHECK(pubCoins.size() == 1);

    CZerocoinState::BlacklistPublicCoinValue(pubCoins.begin()->value);

    // Now remint should succeed but it should result in transaction in mempool
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinToSigmaRemintModel(stringError, ZEROCOIN_TX_VERSION_2, (libzerocoin::CoinDenomination)1), stringError + " - Remint failed");
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Remint was added to the mempool despite blacklisted public coin value");
}

BOOST_AUTO_TEST_SUITE_END()
