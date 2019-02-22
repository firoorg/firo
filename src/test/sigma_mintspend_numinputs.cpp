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

BOOST_FIXTURE_TEST_SUITE(sigma_tests, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(sigma_mintspend_numinputs){
    vector<string> denominationsForTx;
    vector<uint256> vtxid;
    std::vector<CMutableTransaction> MinTxns;
    string thirdPartyAddress;
    int previousHeight;
    CBlock b;
    CWalletTx wtx;
    string stringError;

    std::vector<std::string> denominations = {"0.1", "0.5", "1", "10", "100"};
    int denominationIndexA = rand() % 5;
    int denominationIndexB = (denominationIndexA + 5) %4; //guarantees a different number in the range

    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();

    pwalletMain->SetBroadcastTransactions(true);

    // attempt to create a zerocoin spend with more than ZC_SPEND_LIMIT inputs.
    printf("Testing number of inputs for denomination %s", denominations[denominationIndexA].c_str());
    denominationsForTx.clear();

    for (int i = 0; i < (ZC_SPEND_LIMIT+1)*2; i++){
        denominationsForTx.push_back(denominations[denominationIndexA]);
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominations[denominationIndexA].c_str(), SIGMA), stringError + " - Create Mint failed");
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominations[denominationIndexB].c_str(), SIGMA), stringError + " - Create Mint failed");
        if(i<=ZC_SPEND_LIMIT){
            denominationsForTx.push_back(denominations[denominationIndexA]);
        }
    }

    BOOST_CHECK_MESSAGE(mempool.size() == (ZC_SPEND_LIMIT+1)*4, "Num input mints not added to mempool");

    // add block
    previousHeight = chainActive.Height();
    b = CreateAndProcessBlock(MinTxns, scriptPubKey);
    wtx.Init(NULL);
    //Add 5 more blocks
    for (int i = 0; i < 5; i++)
    {
        std::vector<CMutableTransaction> noTxns;
        b = CreateAndProcessBlock(noTxns, scriptPubKey);
        wtx.Init(NULL);
    }

    BOOST_CHECK_MESSAGE(previousHeight + 6 == chainActive.Height(), "Block not added to chain");
    previousHeight = chainActive.Height();

    // Check that the tx creation fails.
    BOOST_CHECK_MESSAGE(!pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend succeeded even though number of inputs > ZC_SPEND_LIMIT");

    // Next add 3 transactions with 2 inputs each, verify mempool==3. mine a block. Verify mempool still has 1 tx.
    for(int i=0;i<3;i++){
        denominationsForTx.clear();
        denominationsForTx.push_back(denominations[denominationIndexA]);
        denominationsForTx.push_back(denominations[denominationIndexB]);
        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinSpendModel(wtx, stringError, thirdPartyAddress, denominationsForTx), "Spend Failed");
    }

    BOOST_CHECK_MESSAGE(mempool.size() == 3, "Num input spends not added to mempool");

    // add block
    b = CreateAndProcessBlock(MinTxns, scriptPubKey);
    wtx.Init(NULL);

    BOOST_CHECK_MESSAGE(mempool.size() != 3 && mempool.size() == 1 && mempool.size() != 0, "Mempool not correctly cleared: Block spend limit not enforced.");

    vtxid.clear();
    MinTxns.clear();
    mempool.clear();
    zerocoinState->Reset();
}
BOOST_AUTO_TEST_SUITE_END()

