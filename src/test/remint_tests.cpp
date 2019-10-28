#include "util.h"

#include "clientversion.h"
#include "primitives/transaction.h"
#include "random.h"
#include "sync.h"
#include "net.h"
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
    std::vector<string> denominations = {"1", "10", "25", "50", "100", "100"};

    struct CommitTxHelper {
        CReserveKey key;
        CValidationState state;

        CommitTxHelper() : key(pwalletMain), state() {}
    } commitTxHelper[4];

    string stringError;
    CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    CWalletDB walletdb(pwalletMain->strWalletFile);
    std::list<CZerocoinEntry> zcEntries;
    decltype(zerocoinState->usedCoinSerials) tempSerials;

    pwalletMain->SetBroadcastTransactions(true);

    // Mint 1 XZC zerocoin and remint it on wrong fork
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, "1"), stringError + " - Create Mint failed");
    CreateAndProcessBlock(scriptPubKey);
    CBlockIndex *forkBlockIndex = chainActive.Tip();
    // Get to the sigma portion
    for (int i=0; i<200; i++)
        CreateAndProcessBlock(scriptPubKey);

    CWalletTx remintOnWrongForkTx;
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinToSigmaRemintModel(stringError, ZEROCOIN_TX_VERSION_2, (libzerocoin::CoinDenomination)1, &remintOnWrongForkTx), stringError + " - Remint failed");

    // try to double-remint one coin in a single block
    walletdb.ListPubCoin(zcEntries);
    for (auto &zcEntry : zcEntries) {
        if (zcEntry.IsUsedForRemint) {
            zcEntry.IsUsed = zcEntry.IsUsedForRemint = false;
            walletdb.WriteZerocoinEntry(zcEntry);
        }
    }
    CWalletTx dupSerialTx;
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinToSigmaRemintModel(stringError, ZEROCOIN_TX_VERSION_2, (libzerocoin::CoinDenomination)1, &dupSerialTx), stringError + " - Remint failed");
    // Should fail for now
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Remint transaction accepted into mempool when shouldn't");
    // Clear mempool serials and retry
    zerocoinState->mempoolCoinSerials.clear();
    sigmaState->Reset();
    pwalletMain->CommitTransaction(dupSerialTx, commitTxHelper[0].key, g_connman.get(), commitTxHelper[0].state);
    // Mempool should contain two remint transactions both having the same serial
    BOOST_CHECK(mempool.size() == 2);

    // Try to form a block - should fail
    try {
        CreateAndProcessBlock(scriptPubKey);
        BOOST_FAIL("Block is created despite having double spend in it");
    }
    catch (std::runtime_error &err) {
        BOOST_CHECK(strstr(err.what(), "TestBlockValidity") != nullptr);
    }

    // clear the mempool
    mempool.clear();
    zerocoinState->mempoolCoinSerials.clear();

    // Try to change destination sigma mint for the remint transaction. Should fail because metadata signature is wrong
    CWalletTx wtxCopy = remintOnWrongForkTx;
    sigma::Params *sigmaParams = sigma::Params::get_default();

    sigma::PrivateCoin fakeCoin(sigmaParams, sigma::CoinDenomination::SIGMA_DENOM_1, ZEROCOIN_TX_VERSION_3);
    sigma::PublicCoin fakePubCoin = fakeCoin.getPublicCoin();
    BOOST_CHECK(fakePubCoin.validate());

    CScript sigmaMintScript;
    sigmaMintScript << OP_SIGMAMINT;
    std::vector<unsigned char> vch = fakePubCoin.getValue().getvch();
    sigmaMintScript.insert(sigmaMintScript.end(), vch.begin(), vch.end());

    CTxOut sigmaTxOut;
    sigmaTxOut.scriptPubKey = sigmaMintScript;
    sigma::DenominationToInteger(sigma::CoinDenomination::SIGMA_DENOM_1, sigmaTxOut.nValue);
    CMutableTransaction txCopy = *wtxCopy.tx;
    txCopy.vout[0] = sigmaTxOut;
    wtxCopy.tx = MakeTransactionRef(txCopy);

    pwalletMain->CommitTransaction(wtxCopy, commitTxHelper[1].key, g_connman.get(), commitTxHelper[1].state);
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Transaction is accepted despite having forged destination");

    pwalletMain->CommitTransaction(remintOnWrongForkTx, commitTxHelper[2].key, g_connman.get(), commitTxHelper[2].state);
    BOOST_CHECK(mempool.size() == 1);

    CreateAndProcessBlock(scriptPubKey);

    // Invalidate chain
    {
        LOCK(cs_main);
        CValidationState state;
        InvalidateBlock(state, Params(), forkBlockIndex);
    }
    // Mint and remint txs should be in the mempool now, clear them
    mempool.clear();
    zerocoinState->mempoolCoinSerials.clear();

    for (int i=0; i<6; i++) {
        denomination = denominations[i];
        string stringError;

        //Verify Mint is successful
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denomination.c_str()), stringError + " - Create Mint failed");

        //Verify Mint gets in the mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Zerocoin mint was not added to mempool");

        CreateAndProcessBlock(scriptPubKey);
    }

    for (int i=0; i<5; i++)
        CreateAndProcessBlock(scriptPubKey);

    // spend coin for 100 xzc
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", "100", false, true), stringError + " - 100 xzc spend failed");
    CreateAndProcessBlock(scriptPubKey);
    BOOST_CHECK_MESSAGE(zerocoinState->usedCoinSerials.size() == 1, "Incorrect used coin serial state after zerocoin spend");
    CBigNum zcSpentSerial = *zerocoinState->usedCoinSerials.begin();

    // get to the sigma portion
    for (int i=0; i<200; i++) {
        CBlock b = CreateAndProcessBlock(scriptPubKey);
    }
    // Intentionally do not remint the second 100
    for (int i=0; i<5; i++) {
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinToSigmaRemintModel(stringError, ZEROCOIN_TX_VERSION_2, (libzerocoin::CoinDenomination)atoi(denominations[i].c_str())), stringError + " - Remint failed");
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Zerocoin remint was not added to mempool");
        for (int i=0; i<5; i++)
            CreateAndProcessBlock(scriptPubKey);
    }

    // test if sigma mints are spendable
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", "25"), "Sigma spend failed");
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

    for (int i=0; i<5; i++)
        CreateAndProcessBlock(scriptPubKey);

    // try double spend by modifying wallet and list of spent serials
    //Temporary disable usedCoinSerials check to force double spend in mempool
    for (const Bignum &serial: zerocoinState->usedCoinSerials) {
        CZerocoinSpendEntry spendEntry;
        spendEntry.coinSerial = serial;
        walletdb.EraseCoinSpendSerialEntry(spendEntry);
    }

    zcEntries.clear();
    walletdb.ListPubCoin(zcEntries);
    for (auto &zcEntry : zcEntries) {
        if (zcEntry.IsUsedForRemint) {
            zcEntry.IsUsed = zcEntry.IsUsedForRemint = false;
            walletdb.WriteZerocoinEntry(zcEntry);
        }
    }

    tempSerials = zerocoinState->usedCoinSerials;
    zerocoinState->usedCoinSerials.clear();

    // Retry remint of 1. Should pass for now
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinToSigmaRemintModel(stringError, ZEROCOIN_TX_VERSION_2, (libzerocoin::CoinDenomination)1), stringError + " - Remint failed");

    // Restore state and generate a block. TestBlockValidity() should fail due to seen serial
    zerocoinState->usedCoinSerials = tempSerials;
    try {
        CreateAndProcessBlock(scriptPubKey);
        BOOST_FAIL("Block is created despite having double spend in it");
    }
    catch (std::runtime_error &err) {
        BOOST_CHECK(strstr(err.what(), "TestBlockValidity") != nullptr);
    }

    // clear mempool
    mempool.clear();
    // Block should be created now
    CreateAndProcessBlock(scriptPubKey);

    // Temporarily remove spent coin from the list of spent serials
    zerocoinState->usedCoinSerials.erase(zcSpentSerial);

    // Try remint for 100 xzc. Again should pass
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinToSigmaRemintModel(stringError, ZEROCOIN_TX_VERSION_2, (libzerocoin::CoinDenomination)100), stringError + " - Remint failed");

    // Restore state and verify that it fails to get into the block because it was spent as zerocoin
    zerocoinState->usedCoinSerials = tempSerials;
    try {
        CreateAndProcessBlock(scriptPubKey);
        BOOST_FAIL("Block is created despite having double spend in it");
    }
    catch (std::runtime_error &err) {
        BOOST_CHECK(strstr(err.what(), "TestBlockValidity") != nullptr);
    }

    // clear mempool again
    mempool.clear();
    // Block should be created now
    CreateAndProcessBlock(scriptPubKey);

    // We've got remint saved that references zerocoin mint from the wrong fork. It shouldn't validate now
    pwalletMain->CommitTransaction(remintOnWrongForkTx, commitTxHelper[3].key, g_connman.get(), commitTxHelper[3].state);
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
        CBlock b = CreateAndProcessBlock(scriptPubKey);
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
