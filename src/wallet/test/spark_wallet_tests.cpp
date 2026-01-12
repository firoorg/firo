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

// Test for transaction validation with correct transaction object
// This test verifies the fix where IsTransactionAllowed should use txNewConst
// instead of *wtx.tx (which is not yet initialized at that point)
BOOST_AUTO_TEST_CASE(create_spark_mint_transaction_validation)
{
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    
    const uint64_t v = 5 * COIN;
    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    spark::MintedCoinData data;
    data.address = sparkAddress;
    data.v = v;
    data.memo = "Transaction validation test";

    std::vector<spark::MintedCoinData> mintedCoins;
    mintedCoins.push_back(data);

    // This should succeed - the transaction should be properly validated
    std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false, true);
    BOOST_CHECK_EQUAL(result, "");
    BOOST_CHECK_GT(wtxAndFee.size(), 0);

    // Verify that all returned transactions are valid and properly constructed
    for (const auto& wtxPair : wtxAndFee) {
        const CWalletTx& wtx = wtxPair.first;
        
        // Verify the transaction was properly set in wtx
        BOOST_CHECK(wtx.tx != nullptr);
        BOOST_CHECK(wtx.tx->IsSparkMint());
        BOOST_CHECK(wtx.tx->IsSparkTransaction());
        
        // Verify the transaction passes validation
        CValidationState state;
        BOOST_CHECK(mempool.IsTransactionAllowed(*wtx.tx, state));
        
        // Verify transaction has proper inputs and outputs
        BOOST_CHECK_GT(wtx.tx->vin.size(), 0);
        BOOST_CHECK_GT(wtx.tx->vout.size(), 0);
        
        // Verify at least one output is a Spark mint
        bool hasSparkMint = false;
        for (const auto& out : wtx.tx->vout) {
            if (out.scriptPubKey.IsSparkMint()) {
                hasSparkMint = true;
                break;
            }
        }
        BOOST_CHECK(hasSparkMint);
    }

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

// Test transaction validation with multiple outputs
BOOST_AUTO_TEST_CASE(create_spark_mint_transaction_multiple_outputs)
{
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    
    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    std::vector<spark::MintedCoinData> mintedCoins;
    
    // Create multiple mint outputs
    for (int i = 0; i < 3; i++) {
        spark::MintedCoinData data;
        data.address = sparkAddress;
        data.v = (i + 1) * COIN;
        data.memo = "Multiple output test " + std::to_string(i);
        mintedCoins.push_back(data);
    }

    std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false, true);
    BOOST_CHECK_EQUAL(result, "");
    BOOST_CHECK_GT(wtxAndFee.size(), 0);

    // Track total minted amount
    CAmount totalMinted = 0;
    
    for (const auto& wtxPair : wtxAndFee) {
        const CWalletTx& wtx = wtxPair.first;
        
        // Verify transaction object is properly initialized
        BOOST_CHECK(wtx.tx != nullptr);
        
        // Verify transaction validation passes
        CValidationState state;
        BOOST_CHECK(mempool.IsTransactionAllowed(*wtx.tx, state));
        
        // Count minted outputs
        for (const auto& out : wtx.tx->vout) {
            if (out.scriptPubKey.IsSparkMint()) {
                totalMinted += out.nValue;
            }
        }
    }
    
    // Verify total minted amount matches requested
    CAmount expectedTotal = 6 * COIN; // 1 + 2 + 3
    BOOST_CHECK_EQUAL(totalMinted, expectedTotal);

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

// Test transaction validation with fee subtraction
BOOST_AUTO_TEST_CASE(create_spark_mint_transaction_with_fee_subtraction)
{
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    
    const uint64_t v = 10 * COIN;
    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    spark::MintedCoinData data;
    data.address = sparkAddress;
    data.v = v;
    data.memo = "Fee subtraction test";

    std::vector<spark::MintedCoinData> mintedCoins;
    mintedCoins.push_back(data);

    // Mint with fee subtracted from amount
    std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, true, true);
    BOOST_CHECK_EQUAL(result, "");
    BOOST_CHECK_GT(wtxAndFee.size(), 0);

    CAmount totalMinted = 0;
    CAmount totalFees = 0;
    
    for (const auto& wtxPair : wtxAndFee) {
        const CWalletTx& wtx = wtxPair.first;
        const CAmount& fee = wtxPair.second;
        
        // Verify transaction is properly initialized before validation
        BOOST_CHECK(wtx.tx != nullptr);
        
        // Verify transaction passes validation with correct transaction object
        CValidationState state;
        BOOST_CHECK(mempool.IsTransactionAllowed(*wtx.tx, state));
        
        totalFees += fee;
        
        for (const auto& out : wtx.tx->vout) {
            if (out.scriptPubKey.IsSparkMint()) {
                totalMinted += out.nValue;
            }
        }
    }
    
    // When fee is subtracted, total minted + fees should equal original amount
    BOOST_CHECK_EQUAL(totalMinted + totalFees, v);
    BOOST_CHECK_GT(totalFees, 0);

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

// Test transaction construction and validation sequence
BOOST_AUTO_TEST_CASE(spark_mint_transaction_construction_sequence)
{
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    
    const uint64_t v = 3 * COIN;
    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    spark::MintedCoinData data;
    data.address = sparkAddress;
    data.v = v;
    data.memo = "Construction sequence test";

    std::vector<spark::MintedCoinData> mintedCoins;
    mintedCoins.push_back(data);

    std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false, true);
    BOOST_CHECK_EQUAL(result, "");
    
    for (const auto& wtxPair : wtxAndFee) {
        const CWalletTx& wtx = wtxPair.first;
        
        // Critical test: Verify wtx.tx is properly set and not null
        // This ensures the fix is working - wtx.SetTx() was called correctly
        BOOST_CHECK(wtx.tx != nullptr);
        BOOST_CHECK(wtx.tx.get() != nullptr);
        
        // Verify the transaction reference count is correct
        BOOST_CHECK_GT(wtx.tx.use_count(), 0);
        
        // Verify transaction is valid according to mempool rules
        CValidationState state;
        bool isAllowed = mempool.IsTransactionAllowed(*wtx.tx, state);
        BOOST_CHECK(isAllowed);
        
        // If validation failed, state should indicate the reason
        if (!isAllowed) {
            BOOST_TEST_MESSAGE("Transaction validation failed: " + state.GetRejectReason());
        }
        
        // Verify transaction has been properly signed
        BOOST_CHECK_GT(wtx.tx->vin.size(), 0);
        for (const auto& in : wtx.tx->vin) {
            BOOST_CHECK_GT(in.scriptSig.size(), 0);
        }
    }

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

// Test edge case: small mint amounts
BOOST_AUTO_TEST_CASE(spark_mint_transaction_small_amounts)
{
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    
    // Test with very small amounts
    const uint64_t v = 1000; // Minimal amount
    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    spark::MintedCoinData data;
    data.address = sparkAddress;
    data.v = v;
    data.memo = "Small amount test";

    std::vector<spark::MintedCoinData> mintedCoins;
    mintedCoins.push_back(data);

    std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false, true);
    
    // Small amounts might fail or succeed depending on fee requirements
    // If it succeeds, verify proper validation
    if (result.empty() && wtxAndFee.size() > 0) {
        for (const auto& wtxPair : wtxAndFee) {
            const CWalletTx& wtx = wtxPair.first;
            
            BOOST_CHECK(wtx.tx != nullptr);
            
            CValidationState state;
            BOOST_CHECK(mempool.IsTransactionAllowed(*wtx.tx, state));
        }
    }

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

// Test transaction validation consistency across multiple mints
BOOST_AUTO_TEST_CASE(spark_mint_transaction_validation_consistency)
{
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(1001);

    spark::Address sparkAddress = pwalletMain->sparkWallet->getDefaultAddress();

    // Perform multiple mint operations
    for (int iteration = 0; iteration < 3; iteration++) {
        std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
        
        spark::MintedCoinData data;
        data.address = sparkAddress;
        data.v = (iteration + 1) * COIN;
        data.memo = "Consistency test iteration " + std::to_string(iteration);

        std::vector<spark::MintedCoinData> mintedCoins;
        mintedCoins.push_back(data);

        std::string result = pwalletMain->MintAndStoreSpark(mintedCoins, wtxAndFee, false, true);
        BOOST_CHECK_EQUAL(result, "");
        
        // Each iteration should produce valid transactions
        for (const auto& wtxPair : wtxAndFee) {
            const CWalletTx& wtx = wtxPair.first;
            
            // Verify transaction object consistency
            BOOST_CHECK(wtx.tx != nullptr);
            BOOST_CHECK(wtx.GetHash() == wtx.tx->GetHash());
            
            // Verify validation passes consistently
            CValidationState state;
            BOOST_CHECK(mempool.IsTransactionAllowed(*wtx.tx, state));
            
            // Verify transaction properties
            BOOST_CHECK(wtx.tx->IsSparkMint());
            BOOST_CHECK_GT(wtx.tx->vin.size(), 0);
            BOOST_CHECK_GT(wtx.tx->vout.size(), 0);
        }
    }

    auto sparkState = spark::CSparkState::GetState();
    sparkState->Reset();
}

