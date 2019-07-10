#include "../sigma/params.h"
#include "../sigma/coinspend.h"
#include "../sigma/coin.h"
#include "../main.h"
#include "../secp256k1/include/Scalar.h"
#include "../zerocoin_v3.h"
#include "./test_bitcoin.h"
#include "../wallet/wallet.h"

#include "test/fixtures.h"
#include "test/testutil.h"

#include <boost/test/unit_test.hpp>

#include <stdlib.h>

BOOST_FIXTURE_TEST_SUITE(sigma_state_tests, ZerocoinTestingSetup200)

static const uint256 txHash = uint256S("a64bf7b459d3bb09653e444d75a942e9848ed8e1f30e2890f999426ed6dd4a2c");

CBlockIndex CreateBlockIndex(int nHeight)
{
    CBlockIndex index;
    index.nHeight = nHeight;
    index.pprev = chainActive.Tip();
    index.phashBlock = new uint256();
    return index;
}

CBlock CreateBlockWithMints(const std::vector<sigma::PublicCoin> mints)
{
    CBlock block;
    block.sigmaTxInfo = std::make_shared<sigma::CSigmaTxInfo>();
    block.sigmaTxInfo->mints = mints;
    return block;
}

std::vector<sigma::PrivateCoin> generateCoins(
    const sigma::Params* params, int n, sigma::CoinDenomination denom)
{
    std::vector<sigma::PrivateCoin> privCoins;

    for(int i =0; i<n; i++)
        privCoins.push_back(sigma::PrivateCoin(params, denom));

    return privCoins;
}

std::vector<sigma::PublicCoin> getPubcoins(const std::vector<sigma::PrivateCoin> coins)
{
    std::vector<sigma::PublicCoin> pubCoins;

    BOOST_FOREACH(auto& coin, coins)
        pubCoins.push_back(coin.getPublicCoin());

    return pubCoins;
}

// Checking AddSpend
BOOST_AUTO_TEST_CASE(sigma_addspend)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend coin(params, privcoin, anonymity_set, metaData);

    auto coinSerial = coin.getCoinSerialNumber();
    auto initSize = sigmaState->GetSpends().count(coinSerial);
    sigmaState->AddSpend(coinSerial, pubcoin.denomination, 0);
    auto actSize = sigmaState->GetSpends().count(coinSerial);

    BOOST_CHECK_MESSAGE(initSize + 1 == actSize, "Serial was not added to usedCoinSerials.");
    sigmaState->Reset();
}

// Checking HasCoin when coin does not exist
BOOST_AUTO_TEST_CASE(sigma_hascoin_false)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();
    auto hasCoin = sigmaState->HasCoin(pubcoin);

    BOOST_CHECK_MESSAGE(!hasCoin, "The coin should not be in mintedPubCoins.");
    sigmaState->Reset();
}

// Checking HasCoin when coin exists
BOOST_AUTO_TEST_CASE(sigma_hascoin_true)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    CScript scriptPubKey2;
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();
    CBlockIndex index = CreateBlockIndex(1);
    auto mintsBlock = CreateBlockWithMints({pubcoin});

    sigmaState->AddMintsToStateAndBlockIndex(&index, &mintsBlock);
    auto hasCoin = sigmaState->HasCoin(pubcoin);

    BOOST_CHECK_MESSAGE(hasCoin, "The coin should not be in mintedPubCoins.");
    sigmaState->Reset();
}

// Checking GetMintedCoinHeightAndId when coin exists
BOOST_AUTO_TEST_CASE(sigma_getmintcoinheightandid_true)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    CScript scriptPubKey2;
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();
    CBlockIndex index = CreateBlockIndex(1);
    auto mintsBlock = CreateBlockWithMints({pubcoin});

    sigmaState->AddMintsToStateAndBlockIndex(&index, &mintsBlock);
    auto cnData = sigmaState->GetMintedCoinHeightAndId(pubcoin);

    BOOST_CHECK_MESSAGE(cnData.first == 1, "Unexpected minted coin height.");
    BOOST_CHECK_MESSAGE(cnData.second == 1, "Unexpected minted coin id.");
    sigmaState->Reset();
}

// Checking GetMintedCoinHeightAndId when coin does not exist
BOOST_AUTO_TEST_CASE(sigma_get_mintcoin_height_and_id_false)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    CScript scriptPubKey2;
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    auto cnData = sigmaState->GetMintedCoinHeightAndId(pubcoin);
    BOOST_CHECK_MESSAGE(cnData.first == -1, "Unexpected minted coin height.");
    BOOST_CHECK_MESSAGE(cnData.second == -1, "Unexpected minted coin id.");

    sigmaState->Reset();
}

// Checking AddMint two times with same coin
BOOST_AUTO_TEST_CASE(sigma_addmint_double)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    CScript scriptPubKey2;
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();
    CBlockIndex index = CreateBlockIndex(1);
    auto mintsBlock = CreateBlockWithMints({pubcoin});

    sigmaState->AddMintsToStateAndBlockIndex(&index, &mintsBlock);
    auto mintedPubCoin = sigmaState->GetMints();

    BOOST_CHECK_MESSAGE(mintedPubCoin.size() == 1,
        "Unexpected mintedPubCoin size after first call.");

    sigmaState->AddMintsToStateAndBlockIndex(&index, &mintsBlock);
    mintedPubCoin = sigmaState->GetMints();

    BOOST_CHECK_MESSAGE(mintedPubCoin.size() == 1,
         "Unexpected mintedPubCoin size after second call.");

    sigmaState->Reset();
}

// Checking AddMint two different coins on one block
BOOST_AUTO_TEST_CASE(sigma_addmint_two)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    CScript scriptPubKey2;
    auto params1 = sigma::Params::get_default();
    const sigma::PrivateCoin privcoin1(params1, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin1;
    pubcoin1 = privcoin1.getPublicCoin();

    auto params2 = sigma::Params::get_default();
    const sigma::PrivateCoin privcoin2(params2, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin2;
    pubcoin2 = privcoin2.getPublicCoin();

    auto mintsBlock = CreateBlockWithMints({pubcoin1, pubcoin2});

    CBlockIndex index = CreateBlockIndex(1);
    sigmaState->AddMintsToStateAndBlockIndex(&index, &mintsBlock);

    auto mintedPubCoin = sigmaState->GetMints();

    BOOST_CHECK_MESSAGE(mintedPubCoin.size() == 2, "Unexpected mintedPubCoin size.");

    sigmaState->Reset();
}

// Checking AddMint ZC_SPEND_V3_COINSPERID_LIMIT and check group id increase.
BOOST_AUTO_TEST_CASE(sigma_addmints_coinperid_limit)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    const sigma::CoinDenomination testDenomination = sigma::CoinDenomination::SIGMA_DENOM_0_05;
    const auto testDenomStr = sigma::DenominationToString(testDenomination);

    // To make sure have coin more than ZC_SPEND_V3_COINSPERID in first group.
    auto mintsPerBlock = 100;

    std::string strError;
    // Make sure that transactions get to mempool
    pwalletMain->SetBroadcastTransactions(true);

    // Create 400-200+1 = 201 new empty blocks. // consensus.nMintV3SigmaStartBlock = 400
    CreateAndProcessEmptyBlocks(201, scriptPubKey);

    // Generate mints ZC_SPEND_V3_COINSPERID - 1, last group ID should be 1.
    int allMints = 0;
    while (allMints < ZC_SPEND_V3_COINSPERID_LIMIT - 1) {
        auto mintThisBlock = std::min(ZC_SPEND_V3_COINSPERID_LIMIT - 1 - allMints, mintsPerBlock);
        allMints += mintThisBlock;

        BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
            strError, {{testDenomStr, mintThisBlock}}, SIGMA), strError + " - Create Mint failed");

        BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");
        CreateAndProcessBlock({}, scriptPubKey);
        BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool did not get empty.");
    }

    sigma::CSigmaState::SigmaCoinGroupInfo group1;
    sigmaState->GetCoinGroupInfo(testDenomination, 1, group1);
    BOOST_CHECK_EQUAL(group1.nCoins, ZC_SPEND_V3_COINSPERID_LIMIT - 1);
    BOOST_CHECK_EQUAL(sigmaState->GetLatestCoinIds().find(testDenomination)->second, 1);

    // Try to generate more coins to make exceed hardcap, new coins should be push to new group instead.
    auto exceedHardCapAmount = ZC_SPEND_V3_COINSPERID_LIMIT + 1;
    auto moreMintsToMakeExceedLimit =  exceedHardCapAmount - group1.nCoins;

    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
        strError, {{testDenomStr, moreMintsToMakeExceedLimit}}, SIGMA), strError + " - Create Mint failed");
    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint was not added to mempool");
    CreateAndProcessBlock({}, scriptPubKey);
    BOOST_CHECK_MESSAGE(mempool.size() == 0, "Mempool did not get empty.");

    // New Mints should not be added to first group.
    sigmaState->GetCoinGroupInfo(testDenomination, 1, group1);
    BOOST_CHECK_EQUAL(group1.nCoins, ZC_SPEND_V3_COINSPERID_LIMIT - 1);

    // New Mints should be added to news group.
    BOOST_CHECK_EQUAL(sigmaState->GetLatestCoinIds().find(testDenomination)->second, 2);
    sigma::CSigmaState::SigmaCoinGroupInfo group2;
    sigmaState->GetCoinGroupInfo(testDenomination, 2, group2);
    BOOST_CHECK_EQUAL(group2.nCoins, moreMintsToMakeExceedLimit);

    // Remove last block, coin ID should be decrease back.
    DisconnectBlocks(1);

    BOOST_CHECK_EQUAL(sigmaState->GetLatestCoinIds().find(testDenomination)->second, 1);

    sigmaState->Reset();
}

// Checking RemoveSpendFromMempool, when coin is in mempool
BOOST_AUTO_TEST_CASE(sigma_remove_spend_from_mempool_coin_in)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend coin(params, privcoin, anonymity_set, metaData);

    auto coinSerial = coin.getCoinSerialNumber();

    sigmaState->AddSpendToMempool(coinSerial, txHash);
    BOOST_CHECK_MESSAGE(sigmaState->GetMempoolCoinSerials().size() == 1,
      "Unexpected mempoolCoinSerials size after call AddSpendToMempool.");

    sigmaState->RemoveSpendFromMempool(coinSerial);
    BOOST_CHECK_MESSAGE(sigmaState->GetMempoolCoinSerials().size() == 0,
      "Unexpected mempoolCoinSerials size after call AddSpendToMempool.");
    sigmaState->Reset();
}

// Checking RemoveSpendFromMempool, when coin is not in mempool
BOOST_AUTO_TEST_CASE(sigma_remove_spend_from_mempool_coin_not_in)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend coin(params, privcoin, anonymity_set, metaData);

    auto coinSerial = coin.getCoinSerialNumber();

    sigmaState->RemoveSpendFromMempool(coinSerial);
    BOOST_CHECK_MESSAGE(sigmaState->GetMempoolCoinSerials().size() == 0,
      "Unexpected mempoolCoinSerials size after call AddSpendToMempool.");
    sigmaState->Reset();
}

// Checking AddSpendToMempool, when coin was used (in usedCoinSerials)
BOOST_AUTO_TEST_CASE(sigma_addspend_to_mempool_coin_used)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);
    sigma::CoinSpend coin(params, privcoin, anonymity_set, metaData);

    auto coinSerial = coin.getCoinSerialNumber();

    sigmaState->AddSpend(coinSerial, pubcoin.denomination, 0);
    BOOST_CHECK_MESSAGE(sigmaState->GetMempoolCoinSerials().size() == 0,
      "Unexpected mempoolCoinSerials size before call AddSpendToMempool.");

    sigmaState->AddSpendToMempool(coinSerial, txHash);
    BOOST_CHECK_MESSAGE(sigmaState->GetMempoolCoinSerials().size() == 0,
      "Unexpected mempoolCoinSerials size after call AddSpendToMempool.");

    sigmaState->Reset();
}

// Checking AddSpendToMempool, when coin was not used
BOOST_AUTO_TEST_CASE(sigma_addspendtomempool)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend coin(params, privcoin, anonymity_set, metaData);

    auto coinSerial = coin.getCoinSerialNumber();

    sigmaState->AddSpendToMempool(coinSerial, txHash);
    BOOST_CHECK_MESSAGE(sigmaState->GetMempoolCoinSerials().size() == 1,
      "Unexpected mempoolCoinSerials size after call AddSpendToMempool.");

    sigmaState->Reset();
}

// Checking AddSpendToMempool, when coin is already in mempool
BOOST_AUTO_TEST_CASE(sigma_addspendtomempool_coinin)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend coin(params, privcoin, anonymity_set, metaData);

    auto coinSerial = coin.getCoinSerialNumber();

    sigmaState->AddSpendToMempool(coinSerial, txHash);

    BOOST_CHECK_MESSAGE(sigmaState->GetMempoolCoinSerials().size() == 1,
      "Unexpected mempoolCoinSerials size after first call AddSpendToMempool.");
    sigmaState->AddSpendToMempool(coinSerial, txHash);
    BOOST_CHECK_MESSAGE(sigmaState->GetMempoolCoinSerials().size() == 1,
      "Unexpected mempoolCoinSerials size after second call AddSpendToMempool.");

    sigmaState->Reset();
}

// Checking CanAddSpendToMempool, when coin is already in mempool
BOOST_AUTO_TEST_CASE(sigma_canaddspendtomempool_inmempool)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend coin(params, privcoin, anonymity_set, metaData);

    auto coinSerial = coin.getCoinSerialNumber();

    BOOST_CHECK_MESSAGE(sigmaState->CanAddSpendToMempool(coinSerial),
      "CanAddSpendToMempool return false, which means coin already in use, but should not.");

    sigmaState->AddSpendToMempool(coinSerial, txHash);

    BOOST_CHECK_MESSAGE(!sigmaState->CanAddSpendToMempool(coinSerial),
      "CanAddSpendToMempool return true, which means coin not in use, but should be.");

    sigmaState->Reset();
}

// Checking CanAddSpendToMempool, when coin is already used
BOOST_AUTO_TEST_CASE(sigma_canaddspendtomempool_used)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend coin(params, privcoin, anonymity_set, metaData);

    auto coinSerial = coin.getCoinSerialNumber();

    sigmaState->AddSpend(coinSerial, pubcoin.denomination, 0);

    BOOST_CHECK_MESSAGE(!sigmaState->CanAddSpendToMempool(coinSerial),
      "CanAddSpendToMempool return true, which means coin not in use, but should be.");

    sigmaState->Reset();
}

// Checking Reset
BOOST_AUTO_TEST_CASE(sigma_reset)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    CScript scriptPubKey2;
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();
    CBlockIndex index = CreateBlockIndex(1);

    // Let's add data to zerocoinstate before reset

    auto mintsBlock = CreateBlockWithMints({pubcoin});
    sigmaState->AddMintsToStateAndBlockIndex(&index, &mintsBlock);

    BOOST_CHECK_MESSAGE(sigmaState->GetMints().size() == 1,
      "Unexpected mintedPubCoin size before reset.");
    BOOST_CHECK_MESSAGE(sigmaState->GetCoinGroups().size() == 1,
      "Unexpected coinGroups size before reset.");

    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend coin(params, privcoin, anonymity_set, metaData);

    auto coinSerial = coin.getCoinSerialNumber();

    sigmaState->AddSpendToMempool(coinSerial, txHash);

    BOOST_CHECK_MESSAGE(sigmaState->GetMempoolCoinSerials().size() == 1,
      "Unexpected mempoolCoinSerials size before reset.");

    sigmaState->AddSpend(coinSerial, pubcoin.denomination, 0);

    BOOST_CHECK_MESSAGE(sigmaState->GetSpends().size() == 1,
      "Unexpected usedCoinSerials size before reset.");
    BOOST_CHECK_MESSAGE(sigmaState->GetLatestCoinIds().size() == 1,
      "Unexpected mintedPubCoin size before reset.");

    sigmaState->Reset();

    BOOST_CHECK_MESSAGE(sigmaState->GetMints().size() == 0,
      "Unexpected mintedPubCoin size after reset.");
    BOOST_CHECK_MESSAGE(sigmaState->GetCoinGroups().size() == 0,
      "Unexpected coinGroups size after reset.");
    BOOST_CHECK_MESSAGE(sigmaState->GetSpends().size() == 0,
      "Unexpected usedCoinSerials size after reset.");
    BOOST_CHECK_MESSAGE(sigmaState->GetLatestCoinIds().size() == 0,
      "Unexpected mintedPubCoin size after reset.");
    BOOST_CHECK_MESSAGE(sigmaState->GetMempoolCoinSerials().size() == 0,
      "Unexpected mintedPubCoin size after reset.");
}

// Checking GetCoinGroupInfo, when coingroup is exist
BOOST_AUTO_TEST_CASE(sigma_getcoingroupinfo_existing)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    CScript scriptPubKey2;
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();
    CBlockIndex index = CreateBlockIndex(1);
    auto mintsBlock = CreateBlockWithMints({pubcoin});

    sigmaState->AddMintsToStateAndBlockIndex(&index, &mintsBlock);
    auto mintedPubCoin = sigmaState->GetMints();

    BOOST_CHECK_MESSAGE(mintedPubCoin.size() == 1,
        "Unexpected mintedPubCoin size after first call.");

    sigma::CSigmaState::SigmaCoinGroupInfo result;
    sigmaState->GetCoinGroupInfo(pubcoin.getDenomination(), 1, result);
    BOOST_CHECK_MESSAGE(result.nCoins == 1,
        "Unexpected number of coins in group.");
    BOOST_CHECK_MESSAGE(result.firstBlock->mintedPubCoins.size() == index.mintedPubCoins.size(),
        "Unexpected first block index for Group info.");
    BOOST_CHECK_MESSAGE(result.lastBlock->mintedPubCoins.size() == index.mintedPubCoins.size(),
        "Unexpected last block index for Group info.");

    sigmaState->Reset();
}

// Checking GetCoinGroupInfo, when coingroup is not minted
BOOST_AUTO_TEST_CASE(sigma_getcoingroupinfo_not_minted)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    CScript scriptPubKey2;
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();
    CBlockIndex index = CreateBlockIndex(1);

    sigma::CSigmaState::SigmaCoinGroupInfo result;
    sigmaState->GetCoinGroupInfo(pubcoin.getDenomination(), 1, result);
    BOOST_CHECK_MESSAGE(result.nCoins == 0,
        "Unexpected number of coins in group.");

    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(zerocoin_sigma_addblock_nonexist_index)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    CScript scriptPubKey2;
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin;
    pubcoin = privcoin.getPublicCoin();
    CBlockIndex index = CreateBlockIndex(1);

	sigmaState->AddBlock(&index);
	BOOST_CHECK_MESSAGE(sigmaState->GetMints().size() == 0,
	  "Unexpected mintedPubCoins size, add new block without minted txs.");

	BOOST_CHECK_MESSAGE(sigmaState->GetSpends().size() == 0,
	  "Unexpected usedCoinSerials size, add new block without spend txs.");

    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(zerocoin_sigma_addblock_minted_spend)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    CScript scriptPubKey2;
    auto params = sigma::Params::get_default();

    const sigma::PrivateCoin privcoin1(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin1;
    pubcoin1 = privcoin1.getPublicCoin();

    const sigma::PrivateCoin privcoin2(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin2;
    pubcoin2 = privcoin2.getPublicCoin();

    CBlockIndex index = CreateBlockIndex(1);
    std::pair<sigma::CoinDenomination, int> denomination1Group1(
        sigma::CoinDenomination::SIGMA_DENOM_1,1);

	index.sigmaMintedPubCoins[denomination1Group1].push_back(pubcoin1);
	index.sigmaMintedPubCoins[denomination1Group1].push_back(pubcoin2);

	sigmaState->AddBlock(&index);
	BOOST_CHECK_MESSAGE(sigmaState->GetMints().size() == 2,
	  "Unexpected mintedPubCoins size, add new block with 2 minted txs.");

	BOOST_CHECK_MESSAGE(sigmaState->GetSpends().size() == 0,
	  "Unexpected usedCoinSerials size, add new block without spend txs.");

	// spend
    std::vector<sigma::PublicCoin> anonymity_set;
    anonymity_set.push_back(pubcoin1);
    anonymity_set.push_back(pubcoin2);


    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend coinSpend(params,privcoin1,anonymity_set, metaData);

	auto spendSerial = coinSpend.getCoinSerialNumber();

    CBlockIndex index2 = CreateBlockIndex(2);
	index2.sigmaSpentSerials.clear();
	index2.sigmaSpentSerials.insert(std::make_pair(spendSerial, sigma::CSpendCoinInfo::make(coinSpend.getDenomination(), 0)));
	sigmaState->AddBlock(&index2);
	BOOST_CHECK_MESSAGE(sigmaState->GetMints().size() == 2,
	  "Unexpected mintedPubCoins size, add new block without additional minted.");

	BOOST_CHECK_MESSAGE(sigmaState->GetSpends().size() == 1,
	  "Unexpected usedCoinSerials size, add new block with 1 spend txs.");

    // minted more coin
    const sigma::PrivateCoin privcoin3(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PublicCoin pubcoin3;
    pubcoin3 = privcoin3.getPublicCoin();
    CBlockIndex index3 = CreateBlockIndex(3);

    index3.sigmaMintedPubCoins[denomination1Group1].push_back(pubcoin3);
    sigmaState->AddBlock(&index3);
    BOOST_CHECK_MESSAGE(sigmaState->GetMints().size() == 3,
	  "Unexpected mintedPubCoins size, add new block with one more minted.");

	BOOST_CHECK_MESSAGE(sigmaState->GetSpends().size() == 1,
	  "Unexpected usedCoinSerials size, add new block without new spend");

    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(zerocoin_sigma_removeblock_remove)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    CScript scriptPubKey2;
    auto params = sigma::Params::get_default();

    // add index 1 with 10 minted
    auto coins = generateCoins(params, 10, sigma::CoinDenomination::SIGMA_DENOM_1);
    auto pubCoins = getPubcoins(coins);

    auto index1 = CreateBlockIndex(1);
    std::pair<sigma::CoinDenomination, int> denomination1Group1(sigma::CoinDenomination::SIGMA_DENOM_1, 1);
    index1.sigmaMintedPubCoins[denomination1Group1] = pubCoins;

    // add index 2 with 10 minted and 1 spend
    auto coins2 = generateCoins(params,10, sigma::CoinDenomination::SIGMA_DENOM_1);
    auto pubCoins2 = getPubcoins(coins2);

    auto index2 = CreateBlockIndex(2);
    std::pair<sigma::CoinDenomination, int> denomination1Group2(sigma::CoinDenomination::SIGMA_DENOM_1, 2);
    index2.sigmaMintedPubCoins[denomination1Group2] = pubCoins2;

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend coinSpend(params, coins[0], pubCoins, metaData);

    index2.sigmaSpentSerials.clear();
    index2.sigmaSpentSerials.insert(std::make_pair(coinSpend.getCoinSerialNumber(), sigma::CSpendCoinInfo::make(coinSpend.getDenomination(), 0)));

    sigmaState->AddBlock(&index1);
    sigmaState->AddBlock(&index2);

    BOOST_CHECK_MESSAGE(sigmaState->GetLatestCoinIds().find(sigma::CoinDenomination::SIGMA_DENOM_1)->second == 2,
      "Unexpected lastestcoinId");
    BOOST_CHECK_MESSAGE(sigmaState->HasCoin(pubCoins2[0]),
      "Coin isn't in state before remove index 2");

    // remove one
    sigmaState->RemoveBlock(&index2);
    BOOST_CHECK_MESSAGE(sigmaState->GetMints().size() == 10,
	  "Unexpected mintedPubCoins size, remove index contain 10 minteds.");

    BOOST_CHECK_MESSAGE(sigmaState->GetSpends().size() == 0,
      "Unexpected usedCoinSerials size, remove index contain 1 spend.");

    BOOST_CHECK_MESSAGE(sigmaState->GetLatestCoinIds().find(sigma::CoinDenomination::SIGMA_DENOM_1)->second == 1,
      "Unexpected lastestcoinId");

    BOOST_CHECK_MESSAGE(sigmaState->HasCoin(pubCoins[0]),
      "Coin isn't in state before remove index 1");
    BOOST_CHECK_MESSAGE(!sigmaState->HasCoin(pubCoins2[0]),
      "Coin is in state after remove index 2");

    // remove all
    sigmaState->RemoveBlock(&index1);
    BOOST_CHECK_MESSAGE(sigmaState->GetMints().size() == 0,
	  "Unexpected mintedPubCoins size, remove index contain 10 minteds.");

	BOOST_CHECK_MESSAGE(sigmaState->GetSpends().size() == 0,
	  "Unexpected usedCoinSerials size, remove index contain no spend.");

    BOOST_CHECK_MESSAGE(sigmaState->GetLatestCoinIds().find(sigma::CoinDenomination::SIGMA_DENOM_1) == sigmaState->GetLatestCoinIds().end(),
      "Unexpected lastestcoinId remove all");

    BOOST_CHECK_MESSAGE(!sigmaState->HasCoin(pubCoins[0]),
      "Coin is in state after remove index 1");

    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(getmempoolconflictingtxhash_added_no)
{
    sigma::CSigmaState state;

    secp_primitives::Scalar serial;
    serial.randomize();

    BOOST_CHECK(state.GetMempoolConflictingTxHash(serial) == uint256());
}

BOOST_AUTO_TEST_CASE(getmempoolconflictingtxhash_added_yes)
{
    sigma::CSigmaState state;

    secp_primitives::Scalar serial;
    serial.randomize();

    auto txid = uint256S("c8cdacf6b51275a3de9496073c75708abde26cb2f6cb164e0a1a0ed942c3c6e7");

    BOOST_CHECK(state.AddSpendToMempool(serial, txid));
    BOOST_CHECK(state.GetMempoolConflictingTxHash(serial) == txid);
}

BOOST_AUTO_TEST_CASE(zerocoingetspendserialnumberv3_valid_tx_valid_vin)
{
    // setup
    CScript scriptPubKey2;
    auto params = sigma::Params::get_default();

    // spend
    auto coins = generateCoins(params, 10, sigma::CoinDenomination::SIGMA_DENOM_0_1);
    auto pubCoins = getPubcoins(coins);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend coinSpend(params, coins[0], pubCoins, metaData);

    CDataStream serializedCoinSpend(SER_NETWORK, PROTOCOL_VERSION);
    serializedCoinSpend << coinSpend;

    // create tx and vin

    CTxIn newTxIn;
    newTxIn.scriptSig = CScript();
    newTxIn.prevout.SetNull();

    CScript tmp = CScript() << OP_SIGMASPEND;
    tmp.insert(tmp.end(),serializedCoinSpend.begin(),serializedCoinSpend.end());

    newTxIn.scriptSig.assign(tmp.begin(),tmp.end());

    CMutableTransaction newtx;
    newtx.vin.clear();
    newtx.vout.clear();

    newtx.vin.push_back(newTxIn);

    // mock vout
    CTxOut newTxOut(0, CScript());
    newtx.vout.push_back(newTxOut);

    CTransaction ctx(newtx);

    // check
    BOOST_CHECK_MESSAGE(sigma::GetSigmaSpendSerialNumber(ctx,newTxIn) != Scalar(uint64_t(0)),
      "Expect serial number, got 0");

    // add more spend vin
    sigma::CoinSpend coinSpend2(params, coins[1], pubCoins, metaData);

    CDataStream serializedCoinSpend2(SER_NETWORK, PROTOCOL_VERSION);
    serializedCoinSpend2 << coinSpend2;

    CTxIn newTxIn2;
    newTxIn2.scriptSig = CScript();
    newTxIn2.prevout.SetNull();

    CScript tmp2 = CScript() << OP_SIGMASPEND;
    tmp2.insert(tmp2.end(), serializedCoinSpend2.begin(), serializedCoinSpend2.end());

    newTxIn2.scriptSig.assign(tmp2.begin(), tmp2.end());
    newtx.vin.push_back(newTxIn);

    CTransaction ctx2(newtx);

    // check
    BOOST_CHECK_MESSAGE(sigma::GetSigmaSpendSerialNumber(ctx2,newTxIn2) != Scalar(uint64_t(0)),
      "2 vin, Expect serial number, got 0");

    // not allow unspend vin
    // add unspend vin
    CTxIn newTxVin3;
    newTxVin3.scriptSig = CScript();
    newTxVin3.prevout.SetNull();

    CScript tmp3 = CScript() << OP_RETURN;
    newTxVin3.scriptSig.assign(tmp3.begin(), tmp3.end());

    newtx.vin.push_back(newTxVin3);

    CTransaction ctx3(newtx);

    BOOST_CHECK_MESSAGE(sigma::GetSigmaSpendSerialNumber(ctx3, newTxVin3) == Scalar(uint64_t(0)),
      "Expect 0 got serial");
}

BOOST_AUTO_TEST_CASE(zerocoingetspendserialnumberv3_invalid_script)
{
    // setup
    CScript scriptPubKey2;
    auto params = sigma::Params::get_default();

    // spend
    auto coins = generateCoins(params, 10, sigma::CoinDenomination::SIGMA_DENOM_0_1);
    auto pubCoins = getPubcoins(coins);

    // Doesn't really matter what metadata we give here, it must pass.
    sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

    sigma::CoinSpend coinSpend(params, coins[0], pubCoins, metaData);

    CDataStream serializedCoinSpend(SER_NETWORK, PROTOCOL_VERSION);
    serializedCoinSpend << coinSpend;

    // create tx and vin

    CTxIn newTxIn;
    newTxIn.scriptSig = CScript();
    newTxIn.prevout.SetNull();

    CScript tmp = CScript() << OP_SIGMASPEND;
    auto itr = serializedCoinSpend.begin();
    // ignore first byte to make it invalid
    tmp.insert(tmp.end(),++itr,serializedCoinSpend.end());

    CMutableTransaction newtx;

    newtx.vin.push_back(newTxIn);

    // mock vout
    CTxOut newTxOut(0, CScript());
    newtx.vout.push_back(newTxOut);

    CTransaction ctx(newtx);

    // check
    BOOST_CHECK_MESSAGE(sigma::GetSigmaSpendSerialNumber(ctx,newTxIn) == Scalar(uint64_t(0)),
      "Expect 0 got serial, Wrong script");
}

BOOST_AUTO_TEST_CASE(getzerocoinstate_not_null)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    BOOST_CHECK_MESSAGE(sigmaState != NULL, "sigma::CSigmaState::GetState() returned null");
}

BOOST_AUTO_TEST_CASE(sigma_build_state)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    auto params = sigma::Params::get_default();

    CBlockIndex index0 = CreateBlockIndex(0);
    chainActive.SetTip(&index0);

    CBlockIndex index1 = CreateBlockIndex(1);

    // add index 1 with 10 SIGMA_DENOM_1
    auto coins = generateCoins(params, 10, sigma::CoinDenomination::SIGMA_DENOM_1);
    auto pubCoins = getPubcoins(coins);
    std::pair<sigma::CoinDenomination, int> denomination1Group1(sigma::CoinDenomination::SIGMA_DENOM_1, 1);
    std::pair<sigma::CoinDenomination, int> denomination10Group1(sigma::CoinDenomination::SIGMA_DENOM_10, 1);

    index1.sigmaMintedPubCoins[denomination1Group1] = pubCoins;

    chainActive.SetTip(&index1);

    CBlockIndex index2 = CreateBlockIndex(2);
    // add index 2 with 1 DENOMINATION_1  mints and 1 spend
    auto coins2 = generateCoins(params, 1, sigma::CoinDenomination::SIGMA_DENOM_1);
    auto pubCoins2 = getPubcoins(coins2);
    auto coins3 = generateCoins(params, 1, sigma::CoinDenomination::SIGMA_DENOM_10);
    auto pubCoins3 = getPubcoins(coins3);

    // mock spend
    secp_primitives::Scalar serial;
    serial.randomize();

    index2.sigmaSpentSerials.insert(std::make_pair(serial, sigma::CSpendCoinInfo::make(sigma::CoinDenomination::SIGMA_DENOM_1, 0)));

    index2.sigmaMintedPubCoins[denomination1Group1] = pubCoins2;
    index2.sigmaMintedPubCoins[denomination10Group1] = pubCoins3;

    chainActive.SetTip(&index2);

    for(int i =3 ;i<=100;i++){
		CBlockIndex index = CreateBlockIndex(i);
        chainActive.SetTip(&index);
	}

    sigma::BuildSigmaStateFromIndex(&chainActive);

    // check group
    sigma::CSigmaState::SigmaCoinGroupInfo group;
    sigmaState->GetCoinGroupInfo(sigma::CoinDenomination::SIGMA_DENOM_1, 1, group);
    BOOST_CHECK_MESSAGE(group.firstBlock->nHeight == index1.nHeight, "Expect firstBlock == index1");
    BOOST_CHECK_MESSAGE(group.lastBlock->nHeight == index2.nHeight, "Expect lastBlock == index2");
    BOOST_CHECK_MESSAGE(group.nCoins == 11, "Expect nCoins == 11");

    sigma::CSigmaState::SigmaCoinGroupInfo group2;
    sigmaState->GetCoinGroupInfo(sigma::CoinDenomination::SIGMA_DENOM_10, 1, group2);
    BOOST_CHECK_MESSAGE(group2.firstBlock->nHeight == index2.nHeight, "Expect firstBlock == index2");
    BOOST_CHECK_MESSAGE(group2.lastBlock->nHeight == index2.nHeight, "Expect lastBlock == index2");
    BOOST_CHECK_MESSAGE(group2.nCoins == 1, "Expect nCoins == 1");

    // check serial
    secp_primitives::Scalar notFoundSerial;
    notFoundSerial.randomize();
    BOOST_CHECK_MESSAGE(sigmaState->IsUsedCoinSerial(serial), "Expect found serial");
    BOOST_CHECK_MESSAGE(!sigmaState->IsUsedCoinSerial(notFoundSerial), "Expect not found serial");

    // has coin
    auto notFoundCoins = generateCoins(params, 10, sigma::CoinDenomination::SIGMA_DENOM_0_1);
    auto notFoundPubCoins = getPubcoins(notFoundCoins);
    BOOST_CHECK_MESSAGE(sigmaState->HasCoin(pubCoins[0]), "Expect found pubcoin");
    BOOST_CHECK_MESSAGE(sigmaState->HasCoin(pubCoins3[0]), "Expect found pubcoin");
    BOOST_CHECK_MESSAGE(!sigmaState->HasCoin(notFoundPubCoins[0]), "Expect not found pubcoin");

    // get mint coin heigh and id
    std::pair<int,int> groupHeightAndID = sigmaState->GetMintedCoinHeightAndId(pubCoins2[0]);
    BOOST_CHECK_MESSAGE(groupHeightAndID.first == index2.nHeight, "Expect pubcoin on index2");
    BOOST_CHECK_MESSAGE(groupHeightAndID.second == 1, "Expect pubcoin id == 1");

    std::pair<int,int> notFoundGroupHeightAndID = sigmaState->GetMintedCoinHeightAndId(notFoundPubCoins[0]);
    BOOST_CHECK_MESSAGE(notFoundGroupHeightAndID == std::make_pair(-1,-1),"Expect not found return -1,-1");

    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(sigma_build_state_no_sigma)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    auto params = sigma::Params::get_default();

    std::vector<CBlockIndex> indexs;
    indexs.resize(101);
    for(int i =0 ;i<=100;i++){
		CBlockIndex index = CreateBlockIndex(i);
        chainActive.SetTip(&index);
        indexs[i] = index;
	}

    sigma::BuildSigmaStateFromIndex(&chainActive);

    // check group
    sigma::CSigmaState::SigmaCoinGroupInfo group;
    bool found = sigmaState->GetCoinGroupInfo(sigma::CoinDenomination::SIGMA_DENOM_1, 1, group);
    BOOST_CHECK_MESSAGE(!found, "Expect group not found");

    // check serial
    secp_primitives::Scalar notFoundSerial;
    notFoundSerial.randomize();
    BOOST_CHECK_MESSAGE(!sigmaState->IsUsedCoinSerial(notFoundSerial), "Expect not found serial");

    // has coin
    auto notFoundCoins = generateCoins(params,10, sigma::CoinDenomination::SIGMA_DENOM_0_1);
    auto notFoundPubCoins = getPubcoins(notFoundCoins);
    BOOST_CHECK_MESSAGE(!sigmaState->HasCoin(notFoundPubCoins[0]), "Expect not found pubcoin");

    // get mint coin heigh and id
    std::pair<int,int> notFoundGroupHeightAndID = sigmaState->GetMintedCoinHeightAndId(notFoundPubCoins[0]);
    BOOST_CHECK_MESSAGE(notFoundGroupHeightAndID == std::make_pair(-1,-1),"Expect not found return -1,-1");

    sigmaState->Reset();
}


BOOST_AUTO_TEST_CASE(sigma_getcoinsetforspend)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    sigma::Params* params = sigma::Params::get_default();
    int nextIndex = 0;
    std::vector<CBlockIndex> indexes;
    indexes.resize(101);

    // nextIndex = 0
    indexes[nextIndex] = CreateBlockIndex(nextIndex);
    chainActive.SetTip(&indexes[nextIndex]);

    // nextIndex = 1
    nextIndex++;
    indexes[nextIndex] = CreateBlockIndex(nextIndex);

    std::pair<sigma::CoinDenomination, int> denomination1Group1(sigma::CoinDenomination::SIGMA_DENOM_1, 1);
    std::pair<sigma::CoinDenomination, int> denomination10Group1(sigma::CoinDenomination::SIGMA_DENOM_10, 1);

    // add index 1 with 10 SIGMA_DENOM_1
    auto coins = generateCoins(params, 10, sigma::CoinDenomination::SIGMA_DENOM_1);
    auto pubCoins = getPubcoins(coins);

    // add index 2 with 1 DENOM_1  mints and 1 spend
    auto coins2 = generateCoins(params, 1, sigma::CoinDenomination::SIGMA_DENOM_1);
    auto pubCoins2 = getPubcoins(coins2);
    auto coins3 = generateCoins(params, 5, sigma::CoinDenomination::SIGMA_DENOM_10);
    auto pubCoins3 = getPubcoins(coins3);

    indexes[nextIndex].sigmaMintedPubCoins[denomination1Group1] = pubCoins;
    chainActive.SetTip(&indexes[nextIndex]);

    nextIndex++;
    indexes[nextIndex] = CreateBlockIndex(nextIndex);

    // mock spend
    secp_primitives::Scalar serial;
    serial.randomize();

    indexes[nextIndex].sigmaSpentSerials.insert(std::make_pair(serial, sigma::CSpendCoinInfo::make(sigma::CoinDenomination::SIGMA_DENOM_1, 0)));
    indexes[nextIndex].sigmaMintedPubCoins[denomination1Group1] = pubCoins2;
    indexes[nextIndex].sigmaMintedPubCoins[denomination10Group1] = pubCoins3;

    chainActive.SetTip(&indexes[nextIndex]);

    // nextIndex = 3
    nextIndex++;
    for( ; nextIndex<=100; nextIndex++){
		indexes[nextIndex] = CreateBlockIndex(nextIndex);
        chainActive.SetTip(&indexes[nextIndex]);
	}

    sigma::BuildSigmaStateFromIndex(&chainActive);

    uint256 blockHash_out;
    uint256 blockHash_empty;

    std::vector<sigma::PublicCoin> coins_out3;
    // maxheight < blockheight
    auto coins_amount = sigmaState->GetCoinSetForSpend(&chainActive, 1,
    sigma::CoinDenomination::SIGMA_DENOM_10, 1, blockHash_out, coins_out3);
    BOOST_CHECK_MESSAGE(coins_amount == 0, "Unexpected Coins amount for spend, should be 0.");
    BOOST_CHECK_MESSAGE(coins_out3.size() == 0, "Unexpected coins out, should be 0.");
    BOOST_CHECK_MESSAGE(blockHash_out == blockHash_empty , "Unexpected blockhash for small height.");

    std::vector<sigma::PublicCoin> coins_out1;
    // maxheight > blockheight
    coins_amount = sigmaState->GetCoinSetForSpend(&chainActive, nextIndex,
    sigma::CoinDenomination::SIGMA_DENOM_10, 1, blockHash_out, coins_out1);
    BOOST_CHECK_MESSAGE(coins_amount == 5, "Unexpected Coins amount for spend, should be 5.");
    BOOST_CHECK_MESSAGE(coins_out1 == pubCoins3, "Unexpected coins out for denom 10.");
    BOOST_CHECK_MESSAGE(blockHash_out == indexes[2].GetBlockHash(), "Unexpected blockhash for denom 10.");

    std::vector<sigma::PublicCoin> coins_out2;
    // maxheight > blockheight another denom
    coins_amount = sigmaState->GetCoinSetForSpend(&chainActive, nextIndex,
    sigma::CoinDenomination::SIGMA_DENOM_1, 1, blockHash_out, coins_out2);
    BOOST_CHECK_MESSAGE(coins_amount == 11, "Unexpected Coins amount for spend, should be 11.");
    BOOST_CHECK_MESSAGE(coins_out2.size() == pubCoins2.size() + pubCoins.size(), "Unexpected coins out for denom 1.");
    BOOST_CHECK_MESSAGE(blockHash_out == indexes[2].GetBlockHash(), "Unexpected blockhash for denom 1.");

    sigmaState->Reset();
}

namespace {
    Scalar generateSpend(sigma::CoinDenomination denom) {
        auto params = sigma::Params::get_default();

        const sigma::PrivateCoin privcoin(params, denom);
        sigma::PublicCoin pubcoin;
        pubcoin = privcoin.getPublicCoin();

        std::vector<sigma::PublicCoin> anonymity_set;
        anonymity_set.push_back(pubcoin);

        // Doesn't really matter what metadata we give here, it must pass.
        sigma::SpendMetaData metaData(0, uint256S("120"), uint256S("120"));

        sigma::CoinSpend coin(params, privcoin, anonymity_set, metaData);

        return coin.getCoinSerialNumber();
    }

    CBlock generateMint(sigma::CoinDenomination denom) {
        auto params = sigma::Params::get_default();

        const sigma::PrivateCoin privcoin(params, denom);

        return CreateBlockWithMints({privcoin.getPublicCoin()});
    }
}

BOOST_AUTO_TEST_CASE(sigma_surge_detection_positive)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();

    CBlockIndex index = CreateBlockIndex(1);
    CBlock mintsBlock = generateMint(sigma::CoinDenomination::SIGMA_DENOM_1);
    sigmaState->AddMintsToStateAndBlockIndex(&index, &mintsBlock);
    BOOST_CHECK(sigmaState->IsSurgeConditionDetected() == false);

    sigmaState->AddSpend(generateSpend(sigma::CoinDenomination::SIGMA_DENOM_1), sigma::CoinDenomination::SIGMA_DENOM_1, 1);
    BOOST_CHECK(sigmaState->IsSurgeConditionDetected() == false);

    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(sigma_surge_detection_reset)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();

    sigmaState->Reset();
    BOOST_CHECK(sigmaState->IsSurgeConditionDetected() == false);


    sigmaState->AddSpend(generateSpend(sigma::CoinDenomination::SIGMA_DENOM_1), sigma::CoinDenomination::SIGMA_DENOM_1, 1);
    BOOST_CHECK(sigmaState->IsSurgeConditionDetected() == true);

    CBlockIndex index = CreateBlockIndex(1);
    CBlock mintsBlock = generateMint(sigma::CoinDenomination::SIGMA_DENOM_1);
    sigmaState->AddMintsToStateAndBlockIndex(&index, &mintsBlock);
    BOOST_CHECK(sigmaState->IsSurgeConditionDetected() == false);

    sigmaState->Reset();
}

// Check that failure in any [denom, group] makes it failed for all other
// combinations of [denom,group]
BOOST_AUTO_TEST_CASE(sigma_surge_detection_failure_anywhere)
{
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();

    sigmaState->Reset();
    BOOST_CHECK(sigmaState->IsSurgeConditionDetected() == false);


    sigmaState->AddSpend(generateSpend(sigma::CoinDenomination::SIGMA_DENOM_1), sigma::CoinDenomination::SIGMA_DENOM_100, 1);
    BOOST_CHECK(sigmaState->IsSurgeConditionDetected() == true);

    CBlockIndex index = CreateBlockIndex(1);
    CBlock mintsBlock1 = generateMint(sigma::CoinDenomination::SIGMA_DENOM_1);
    sigmaState->AddMintsToStateAndBlockIndex(&index, &mintsBlock1);
    BOOST_CHECK(sigmaState->IsSurgeConditionDetected() == true);

    sigmaState->AddSpend(generateSpend(sigma::CoinDenomination::SIGMA_DENOM_1), sigma::CoinDenomination::SIGMA_DENOM_1, 1);
    BOOST_CHECK(sigmaState->IsSurgeConditionDetected() == true);

    CBlock mintsBlock100 = generateMint(sigma::CoinDenomination::SIGMA_DENOM_100);
    sigmaState->AddMintsToStateAndBlockIndex(&index, &mintsBlock100);
    BOOST_CHECK(sigmaState->IsSurgeConditionDetected() == false);

    sigmaState->Reset();
}


BOOST_AUTO_TEST_SUITE_END()
