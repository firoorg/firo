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
    std::vector<string> denominations = {"1", "10", "25", "50", "100"};

    string stringError;

    // Start with spend v2
    Consensus::Params &params = const_cast<Consensus::Params &>(Params().GetConsensus());
    Consensus::Params oldParams = params;
    params.nSpendV2ID_1 = params.nSpendV2ID_10 = params.nSpendV2ID_25 = params.nSpendV2ID_50 = params.nSpendV2ID_100 = 1;

    for (int i=0; i<5; i++) {
        denomination = denominations[i];
        string stringError;

        pwalletMain->SetBroadcastTransactions(true);

        //Verify Mint is successful
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denomination.c_str()), stringError + " - Create Mint failed");

        //Verify Mint gets in the mempool
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Zerocoin mint was not added to mempool");

        for (int i=0; i<5; i++)
            CreateAndProcessBlock({}, scriptPubKey);
    }

    // get to the sigma portion
    for (int i=0; i<400; i++) {
        CBlock b = CreateAndProcessBlock({}, scriptPubKey);
    }

    for (int i=0; i<5; i++) {
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinToSigmaRemintModel(stringError, ZEROCOIN_TX_VERSION_2, (libzerocoin::CoinDenomination)atoi(denominations[i].c_str())), stringError + " - Remint failed");
        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Zerocoin remint was not added to mempool");
        for (int i=0; i<5; i++)
            CreateAndProcessBlock({}, scriptPubKey);
    }

    // test if sigma mints are spendable
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(stringError, "", "10"), "Sigma spend failed");
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Spend was not added to mempool");

    for (int i=0; i<5; i++)
        CreateAndProcessBlock({}, scriptPubKey);

    // try double spend by modifying wallet and list of spent serials
    //Temporary disable usedCoinSerials check to force double spend in mempool
    CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();
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

    // Retry remint. Should pass for now
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

    params = oldParams;
}

BOOST_AUTO_TEST_SUITE_END()
