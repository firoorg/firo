#include <../../test/fixtures.h>
#include "../../chainparams.h"
#include "../wallet.h"
#include "../../spark/sparkwallet.h"
#include "../../validation.h"

#include <boost/test/unit_test.hpp>

static std::vector<unsigned char> random_char_vector()
{                                                    
    Scalar temp;
    temp.randomize();
    std::vector<unsigned char> result;
    result.resize(spark::SCALAR_ENCODING);
    temp.serialize(result.data());
    return result;
}

CBlock GetCBlock(CBlockIndex const *blockIdx)
{
    CBlock block;
    if (!ReadBlockFromDisk(block, blockIdx, ::Params().GetConsensus())) {
        throw std::invalid_argument("No block index data");
    }

    return block;
}

void ExtractSpend(CTransaction const &tx,                                                 
     std::vector<spark::Coin>& coins,
     std::vector<GroupElement>& lTags) {

     if (tx.vin[0].scriptSig.IsSparkSpend()) {
         coins.clear();
         coins =  spark::GetSparkMintCoins(tx);
         lTags.clear();
         lTags =  spark::GetSparkUsedTags(tx);
     }
}

BOOST_FIXTURE_TEST_SUITE(spark_wallet_tests, SparkTestingSetup)

BOOST_AUTO_TEST_CASE(create_mint_recipient)
{
    const uint64_t v = 1;
    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    spark::MintedCoinData data;
    data.address = sparkAddress;
    data.v = v;
    data.memo = "Test memo";

    std::vector<spark::MintedCoinData> mintedCoins;
    mintedCoins.push_back(data);

    auto recipients = CSparkWallet::CreateSparkMintRecipients(mintedCoins, random_char_vector(), true);

    BOOST_CHECK(recipients[0].scriptPubKey.IsSparkMint());
    BOOST_CHECK_EQUAL(recipients[0].nAmount, v);
}

BOOST_AUTO_TEST_CASE(mint_and_store_spark)
{
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;

    const uint64_t v = 1;
    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    spark::MintedCoinData data;
    data.address = sparkAddress;
    data.v = v;
    data.memo = "Test memo";

    std::vector<spark::MintedCoinData> mintedCoins;
    mintedCoins.push_back(data);

    std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false, true);
    BOOST_CHECK_EQUAL(result, "");

    size_t mintAmount = 0;
    for (const auto& wtx : wtxAndFee) {
        auto tx = wtx.first.tx.get();

        BOOST_CHECK(tx->IsSparkMint());
        BOOST_CHECK(tx->IsSparkTransaction());

        for (const auto& out : tx->vout) {
            if (out.scriptPubKey.IsSparkMint()) {
                mintAmount += out.nValue;
            }
        }
        CMutableTransaction mtx(*tx);
        BOOST_CHECK(GenerateBlock({mtx}));
    }

    BOOST_CHECK_EQUAL(data.v, mintAmount);

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(mint_subtract_fee)
{
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;

    const uint64_t v = 1 * COIN;
    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    spark::MintedCoinData data;
    data.address = sparkAddress;
    data.v = v;
    data.memo = "Test memo";

    std::vector<spark::MintedCoinData> mintedCoins;
    mintedCoins.push_back(data);

    std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, true, true);
    BOOST_CHECK_EQUAL(result, "");

    size_t mintAmount = 0;
    size_t fee = 0;
    for (const auto& wtx : wtxAndFee) {
        auto tx = wtx.first.tx.get();

        BOOST_CHECK(tx->IsSparkMint());
        BOOST_CHECK(tx->IsSparkTransaction());

        for (const auto& out : tx->vout) {
            if (out.scriptPubKey.IsSparkMint()) {
                mintAmount += out.nValue;
            }
        }
        CMutableTransaction mtx(*tx);
        BOOST_CHECK(GenerateBlock({mtx}));
        fee += wtx.second;
    }

    BOOST_CHECK_EQUAL(data.v, mintAmount + fee);

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(list_spark_mints)
{
    GenerateBlocks(1001);
    std::vector<CAmount> confirmedAmounts = {1, 2 * COIN};
    std::vector<CAmount> unconfirmedAmounts = {10 * COIN};
    std::vector<CAmount> allAmounts(confirmedAmounts);
    allAmounts.insert(allAmounts.end(), unconfirmedAmounts.begin(), unconfirmedAmounts.end());

    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints(allAmounts, txs);
    std::vector<CMutableTransaction> inTxs(txs.begin(), txs.begin() + txs.size() - 1);

    auto bIndex = GenerateBlock(inTxs);
    BOOST_CHECK(bIndex);

    auto block = GetCBlock(bIndex);
    pwalletMain->sparkWallet->UpdateMintStateFromBlock(block);

    auto extractAmountsFromAvailableCoins = [](std::vector<CSparkMintMeta> const &coins) -> std::vector<CAmount> {
         std::vector<CAmount> amounts;
         for (auto const &coin : coins) {
             amounts.push_back(coin.v);
         }

         return amounts;
     };

    std::vector<CSparkMintMeta> confirmedCoins = pwalletMain->sparkWallet->ListSparkMints(true, true);
    std::vector<CSparkMintMeta> allCoins = pwalletMain->sparkWallet->ListSparkMints(true, false);
    auto confirmed = extractAmountsFromAvailableCoins(confirmedCoins);
    auto all = extractAmountsFromAvailableCoins(allCoins);

    BOOST_CHECK(std::is_permutation(confirmed.begin(), confirmed.end(), confirmedAmounts.begin()));
    BOOST_CHECK(std::is_permutation(all.begin(), all.end(), allAmounts.begin()));

    // get mint
    CSparkMintMeta mint = pwalletMain->sparkWallet->getMintMeta(mints.front().k);
    BOOST_CHECK(mint.v == mints.front().v);

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}


BOOST_AUTO_TEST_CASE(spend)
{
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);
    const uint64_t v = 2 * COIN;

    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    spark::MintedCoinData data;
    data.address = sparkAddress;
    data.v = v;
    data.memo = "Test memo";

    std::vector<spark::MintedCoinData> mintedCoins;
    mintedCoins.push_back(data);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false, true);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee2;
    pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee2, false, true);

    BOOST_CHECK_EQUAL("", result);

    CMutableTransaction mutableTx(*(wtxAndFee[0].first.tx));
    CMutableTransaction mutableTx2(*(wtxAndFee2[0].first.tx));
    GenerateBlock({mutableTx, mutableTx2}, &script);
    GenerateBlocks(5);
    BOOST_CHECK_EQUAL(1, wtxAndFee.size());
    wtxAndFee.clear();

    auto spTx = GenerateSparkSpend({1 * COIN}, {}, nullptr);

    std::vector<spark::Coin> coins;
    std::vector<GroupElement> tags;
    ExtractSpend(spTx, coins, tags);

    BOOST_CHECK_EQUAL(1, coins.size());
    BOOST_CHECK_EQUAL(1, tags.size());

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(spend_rejects_unbound_cover_set_during_h2_policy_lead)
{
    struct RestoreSparkTestState {
        ~RestoreSparkTestState()
        {
            mempool.clear();
            spark::CSparkState::GetState()->Reset();
        }
    } restoreSparkTestState;

    struct RestoreActivationHeights {
        Consensus::Params& consensus;
        int singleInput;
        int v2;

        RestoreActivationHeights()
            : consensus(const_cast<Consensus::Params&>(
                ::Params().GetConsensus()))
            , singleInput(consensus.nSparkSingleInputStartBlock)
            , v2(consensus.nSparkChaumV2StartBlock)
        {
        }

        ~RestoreActivationHeights()
        {
            consensus.nSparkSingleInputStartBlock = singleInput;
            consensus.nSparkChaumV2StartBlock = v2;
        }
    } restoreActivationHeights;

    GenerateBlocks(500);
    std::vector<CMutableTransaction> mintTransactions;
    GenerateMints({2 * COIN, 2 * COIN}, mintTransactions);
    mempool.clear();
    BOOST_REQUIRE(GenerateBlock(mintTransactions));
    GenerateBlocks(5);
    pwalletMain->sparkWallet->FinishTasks();

    const int nextHeight = chainActive.Height() + 1;
    const int h2Height = nextHeight + 10;
    UpdateRegtestSparkActivationHeights(&nextHeight, &h2Height);

    try {
        GenerateSparkSpend({COIN}, {}, nullptr);
        BOOST_FAIL("Expected an unbound cover-set rejection");
    } catch (const std::runtime_error& error) {
        BOOST_CHECK_EQUAL(
            error.what(),
            "Selected Spark cover set is not yet bound to a canonical state hash");
    }
}

BOOST_AUTO_TEST_CASE(disconnect_block_rolls_back_spend)
{
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);

    // mint the coins to spend from, a spend needs a cover set of at least two coins
    spark::MintedCoinData data;
    data.address = pwalletMain->sparkWallet->getDefaultAddress();
    data.v = 2 * COIN;
    data.memo = "Test memo";

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    BOOST_CHECK_EQUAL("", pwalletMain->MintAndStoreSpark({data, data}, wtxAndFee, false, true));

    std::vector<CMutableTransaction> mintTxs;
    for (const auto& wtx : wtxAndFee)
        mintTxs.emplace_back(*(wtx.first.tx));

    BOOST_REQUIRE(GenerateBlock(mintTxs));
    GenerateBlocks(5);
    BOOST_REQUIRE_EQUAL(2, pwalletMain->sparkWallet->ListSparkMints().size());

    // spend a part of it, the remainder comes back as an SMint output of the spend
    auto spendTx = GenerateSparkSpend({1 * COIN}, {}, nullptr);

    std::vector<spark::Coin> coins;
    std::vector<GroupElement> lTags;
    ExtractSpend(spendTx, coins, lTags);
    BOOST_REQUIRE_EQUAL(1, coins.size());
    BOOST_REQUIRE_EQUAL(1, lTags.size());

    auto blockIdx = GenerateBlock({CMutableTransaction(spendTx)});
    BOOST_REQUIRE(blockIdx);

    // the wallet picks the connected block up on a background thread, let it settle
    // before touching its state
    pwalletMain->sparkWallet->FinishTasks();

    // the wallet holds the mint of the change and the spent coin is marked as used
    uint256 spentLTagHash = primitives::GetLTagHash(lTags[0]);
    CSparkMintMeta changeMeta;
    BOOST_CHECK(pwalletMain->sparkWallet->getMintMeta(coins[0], changeMeta));
    BOOST_CHECK(pwalletMain->sparkWallet->getMintMeta(spentLTagHash).isUsed);
    BOOST_CHECK_EQUAL(3, pwalletMain->sparkWallet->ListSparkMints().size());
    BOOST_CHECK_EQUAL(1, pwalletMain->sparkWallet->ListSparkSpends().size());

    // DisconnectTip resurrects the transactions of the disconnected block into the
    // pools and keeps the wallet state of everything that makes it back. Make the
    // pools reject the spend the way a competing spend of the same coin on the new
    // chain would, so that the transaction is really gone and the wallet has to roll
    // back.
    {
        LOCK(mempool.cs);
        mempool.sparkState.AddSpendToMempool(lTags[0], spendTx.GetHash());
    }
    {
        CTxMemPool &stemPool = txpools.getStemTxPool();
        LOCK(stemPool.cs);
        stemPool.sparkState.AddSpendToMempool(lTags[0], spendTx.GetHash());
    }

    BOOST_CHECK(DisconnectBlocks(1));
    BOOST_CHECK_EQUAL(chainActive.Tip()->nHeight, blockIdx->nHeight - 1);

    // the mint created by the spend is gone and the coin it spent is spendable again
    CSparkMintMeta staleMeta;
    BOOST_CHECK(!pwalletMain->sparkWallet->getMintMeta(coins[0], staleMeta));

    CSparkMintMeta spentMeta = pwalletMain->sparkWallet->getMintMeta(spentLTagHash);
    BOOST_CHECK_EQUAL(data.v, spentMeta.v);
    BOOST_CHECK(!spentMeta.isUsed);

    BOOST_CHECK_EQUAL(2, pwalletMain->sparkWallet->ListSparkMints().size());
    BOOST_CHECK_EQUAL(0, pwalletMain->sparkWallet->ListSparkSpends().size());

    mempool.clear();
    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(mintspark_and_mint_all)
{
    auto countMintsInBalance = [&](
        std::vector<std::pair<CWalletTx, CAmount>> const& wtxs,
        bool includeFee = false) -> CAmount {

        CAmount sum = 0;
        for (auto const &w : wtxs) {
            for (auto const &out : w.first.tx->vout) {
                if (out.scriptPubKey.IsSparkMint()) {
                    sum += out.nValue;
                }
             }

            if (includeFee) {
                sum += w.second;
            }
        }
        return sum;
    };

    auto getAvailableCoinsForMintBalance = [&]() -> CAmount {
        std::vector<std::pair<CAmount, std::vector<COutput>>> valueAndUTXO;
        pwalletMain->AvailableCoinsForLMint(valueAndUTXO, nullptr);
        CAmount s = 0;

        for (auto const &v : valueAndUTXO) {
            s += v.first;
        }

        return s;
    };

    CScript externalScript;
    {
        uint160 seed;
        GetRandBytes(seed.begin(), seed.size());

        externalScript = GetScriptForDestination(CKeyID(seed));
    }

    auto generateBlocksPerScripts = [&](size_t blocks, size_t blocksPerScript) -> std::vector<CScript> {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        std::vector<CScript> scripts;
        while (blocks != 0) {
            CPubKey key;
            key = pwalletMain->GenerateNewKey();
            scripts.push_back(GetScriptForDestination(key.GetID()));
            auto blockCount = std::min(blocksPerScript, blocks);
            GenerateBlocks(blockCount, &scripts.back());
            blocks -= blockCount;
        }

        return scripts;
    };

    auto scripts = generateBlocksPerScripts(200, 10);
    GenerateBlocks(100, &externalScript);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    const uint64_t v = 10 * COIN;

    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    spark::MintedCoinData data;
    data.address = sparkAddress;
    data.v = v;
    data.memo = "Test memo";
    std::vector<spark::MintedCoinData> mintedCoins;
    mintedCoins.push_back(data);

    auto result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false, true);
    BOOST_CHECK_EQUAL("", result);
    BOOST_CHECK_EQUAL(1, wtxAndFee.size());
    BOOST_CHECK_EQUAL(10 * COIN, countMintsInBalance(wtxAndFee));
    wtxAndFee.clear();
    mintedCoins.clear();

    data.v = 600 * COIN;;
    mintedCoins.clear();
    mintedCoins.push_back(data);

    result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false, true);
    BOOST_CHECK_EQUAL("", result);
    BOOST_CHECK_GT(wtxAndFee.size(), 1);
    BOOST_CHECK_EQUAL(600 * COIN, countMintsInBalance(wtxAndFee));

    wtxAndFee.clear();
    mintedCoins.clear();

    auto balance = getAvailableCoinsForMintBalance();
    BOOST_CHECK_GT(balance, 0);

    result = pwalletMain->MintAndStoreSpark({}, wtxAndFee, false, true, true);
    BOOST_CHECK_EQUAL("", result);
    BOOST_CHECK_GT(balance, countMintsInBalance(wtxAndFee));
    BOOST_CHECK_EQUAL(balance, countMintsInBalance(wtxAndFee, true));
    BOOST_CHECK_EQUAL(0, getAvailableCoinsForMintBalance());

    scripts = generateBlocksPerScripts(500, 200);
    GenerateBlocks(100, &externalScript);

    wtxAndFee.clear();
    mintedCoins.clear();
    balance = getAvailableCoinsForMintBalance();
    BOOST_CHECK_GT(balance, 0);

    result = pwalletMain->MintAndStoreSpark({ }, wtxAndFee, false, true, true);
    BOOST_CHECK_EQUAL("", result);
    BOOST_CHECK_GT(balance, countMintsInBalance(wtxAndFee));
    BOOST_CHECK_EQUAL(balance, countMintsInBalance(wtxAndFee, true));
    BOOST_CHECK_EQUAL(0, pwalletMain->GetBalance());

    // Scripts of all changes should unique
    std::set<CScript> changeScripts;
    for (auto const &wtx : wtxAndFee) {
        for (auto const &out : wtx.first.tx->vout) {
            if (!out.scriptPubKey.IsSparkMint()) {
                BOOST_CHECK(!changeScripts.count(out.scriptPubKey));
                changeScripts.insert(out.scriptPubKey);
            }
        }
    }

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
