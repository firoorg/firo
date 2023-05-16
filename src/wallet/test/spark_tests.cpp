#include <../../test/fixtures.h>
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

BOOST_FIXTURE_TEST_SUITE(spark_tests, SparkTestingSetup)

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

    std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false);
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

    std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, true);
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
    std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee2;
    pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee2, false);

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
            {
                LOCK(pwalletMain->cs_wallet);
                key = pwalletMain->GenerateNewKey();
            }
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

    auto result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false);
    BOOST_CHECK_EQUAL("", result);
    BOOST_CHECK_EQUAL(1, wtxAndFee.size());
    BOOST_CHECK_EQUAL(10 * COIN, countMintsInBalance(wtxAndFee));
    wtxAndFee.clear();
    mintedCoins.clear();

    data.v = 600 * COIN;;
    mintedCoins.clear();
    mintedCoins.push_back(data);

    result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false);
    BOOST_CHECK_EQUAL("", result);
    BOOST_CHECK_GT(wtxAndFee.size(), 1);
    BOOST_CHECK_EQUAL(600 * COIN, countMintsInBalance(wtxAndFee));

    wtxAndFee.clear();
    mintedCoins.clear();

    auto balance = getAvailableCoinsForMintBalance();
    BOOST_CHECK_GT(balance, 0);

    result = pwalletMain->MintAndStoreSpark({}, wtxAndFee, false, true);
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

    result = pwalletMain->MintAndStoreSpark({ }, wtxAndFee, false, true);
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
