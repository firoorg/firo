#include "../libzerocoin/sigma/Params.h"
#include "../libzerocoin/sigma/CoinSpend.h"
#include "../libzerocoin/sigma/Coin.h"
#include "../main.h"
#include "../secp256k1/include/Scalar.h"
#include "../zerocoin_v3.h"

#include <boost/test/unit_test.hpp>

#include <stdlib.h>

BOOST_AUTO_TEST_SUITE(sigma_state_tests)

static const uint256 txHash = uint256S("a64bf7b459d3bb09653e444d75a942e9848ed8e1f30e2890f999426ed6dd4a2c");

CBlockIndex CreateBlockIndex(int nHeight)
{
    CBlockIndex index;
    index.nHeight = nHeight;
    index.pprev = chainActive.Tip();
    index.phashBlock = new uint256();
    return index;
}

std::vector<PrivateCoinV3> generateCoins(const ParamsV3* params,int n)
{
    std::vector<sigma::PrivateCoinV3> privCoins;

    for(int i =0 ;i< n;i++)
        privCoins.push_back(sigma::PrivateCoinV3(params));

    return privCoins;
}

std::vector<PublicCoinV3> getPubcoins(const std::vector<PrivateCoinV3> coins)
{
    std::vector<sigma::PublicCoinV3> pubCoins;
    
    BOOST_FOREACH(auto& coin, coins)
        pubCoins.push_back(coin.getPublicCoin());
    
    return pubCoins;
}

// Checking AddSpend
BOOST_AUTO_TEST_CASE(sigma_addspend)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoinV3> anonymity_set;
    anonymity_set.push_back(pubcoin);

    sigma::CoinSpendV3 coin(params,privcoin,anonymity_set);

    auto coinSerial = coin.getCoinSerialNumber();
    auto initSize = zerocoinState->usedCoinSerials.count(coinSerial);
    zerocoinState->AddSpend(coinSerial);
    auto actSize = zerocoinState->usedCoinSerials.count(coinSerial);

    BOOST_CHECK_MESSAGE(initSize + 1 == actSize, "Serial was not added to usedCoinSerials.");
    zerocoinState->Reset();
}

// Checking HasCoin when coin does not exist
BOOST_AUTO_TEST_CASE(sigma_hascoin_false)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();
    auto hasCoin = zerocoinState->HasCoin(pubcoin);

    BOOST_CHECK_MESSAGE(!hasCoin, "The coin should not be in mintedPubCoins.");
    zerocoinState->Reset();
}

// Checking HasCoin when coin exists
BOOST_AUTO_TEST_CASE(sigma_hascoin_true)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    CScript scriptPubKey2;
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();
    CBlockIndex index = CreateBlockIndex(1);

    zerocoinState->AddMint(&index, pubcoin);
    auto hasCoin = zerocoinState->HasCoin(pubcoin);

    BOOST_CHECK_MESSAGE(hasCoin, "The coin should not be in mintedPubCoins.");
    zerocoinState->Reset();
}

// Checking GetMintedCoinHeightAndId when coin exists
BOOST_AUTO_TEST_CASE(sigma_getmintcoinheightandid_true)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    CScript scriptPubKey2;
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();
    CBlockIndex index = CreateBlockIndex(1);

    zerocoinState->AddMint(&index, pubcoin);
    auto cnData = zerocoinState->GetMintedCoinHeightAndId(pubcoin);

    BOOST_CHECK_MESSAGE(cnData.first == 1, "Unexpected minted coin height.");
    BOOST_CHECK_MESSAGE(cnData.second == 1, "Unexpected minted coin id.");
    zerocoinState->Reset();
}

// Checking GetMintedCoinHeightAndId when coin does not exist
BOOST_AUTO_TEST_CASE(sigma_get_mintcoin_height_and_id_false)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    CScript scriptPubKey2;
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();

    auto cnData = zerocoinState->GetMintedCoinHeightAndId(pubcoin);
    BOOST_CHECK_MESSAGE(cnData.first == -1, "Unexpected minted coin height.");
    BOOST_CHECK_MESSAGE(cnData.second == -1, "Unexpected minted coin id.");

    zerocoinState->Reset();
}

// Checking AddMint two times with same coin
BOOST_AUTO_TEST_CASE(sigma_addmint_double)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    CScript scriptPubKey2;
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();
    CBlockIndex index = CreateBlockIndex(1);

    zerocoinState->AddMint(&index, pubcoin);
    auto mintedPubCoin = zerocoinState->mintedPubCoins;

    BOOST_CHECK_MESSAGE(mintedPubCoin.size() == 1,
        "Unexpected mintedPubCoin size after first call.");

    zerocoinState->AddMint(&index, pubcoin);
    mintedPubCoin = zerocoinState->mintedPubCoins;

    BOOST_CHECK_MESSAGE(mintedPubCoin.size() == 1,
         "Unexpected mintedPubCoin size after second call.");

    zerocoinState->Reset();
}

// Checking AddMint two different coins on one block
BOOST_AUTO_TEST_CASE(sigma_addmint_two)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    CScript scriptPubKey2;
    auto params1 = sigma::ParamsV3::get_default();
    const sigma::PrivateCoinV3 privcoin1(params1);
    sigma::PublicCoinV3 pubcoin1;
    pubcoin1 = privcoin1.getPublicCoin();

    auto params2 = sigma::ParamsV3::get_default();
    const sigma::PrivateCoinV3 privcoin2(params2);
    sigma::PublicCoinV3 pubcoin2;
    pubcoin2 = privcoin2.getPublicCoin();

    CBlockIndex index = CreateBlockIndex(1);
    zerocoinState->AddMint(&index, pubcoin1);
    zerocoinState->AddMint(&index, pubcoin2);

    auto mintedPubCoin = zerocoinState->mintedPubCoins;

    BOOST_CHECK_MESSAGE(mintedPubCoin.size() == 2, "Unexpected mintedPubCoin size.");

    zerocoinState->Reset();
}

// Checking AddMint ZC_SPEND_V3_COINSPERID+1 coins on one block should pass
BOOST_AUTO_TEST_CASE(sigma_addmint_more_than_restriction_in_one)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    CScript scriptPubKey2;
    CBlockIndex index = CreateBlockIndex(1);
    for (int i = 0; i <= ZC_SPEND_V3_COINSPERID; ++i){
        auto params = sigma::ParamsV3::get_default();
        const sigma::PrivateCoinV3 privcoin(params);
        auto pubcoin = privcoin.getPublicCoin();
        zerocoinState->AddMint(&index, pubcoin);
    }
    auto mintedPubCoin = zerocoinState->mintedPubCoins;
    BOOST_CHECK_MESSAGE(mintedPubCoin.size() == 15001, "Unexpected mintedPubCoin size in one block of one group.");

    zerocoinState->Reset();
}

// This is a correct case, but should be commented till fix of code
// Cause code of creating another coin group is not in the state class itself
/*
// Checking AddMint ZC_SPEND_V3_COINSPERID+1 coins on different blocks should have two group id
BOOST_AUTO_TEST_CASE(sigma_addmint_more_than_restriction_in_diff)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    CScript scriptPubKey2;
    sigma::PublicCoinV3 pubcoin;
    CBlockIndex index;
    for (int i = 0; i <= ZC_SPEND_V3_COINSPERID; ++i){
        index = CreateBlockIndex(i+1);
        auto params = sigma::ParamsV3::get_default();
        const sigma::PrivateCoinV3 privcoin(params);
        pubcoin = privcoin.getPublicCoin();
        zerocoinState->AddMint(&index, pubcoin);
    }
    auto mintedPubCoin = zerocoinState->mintedPubCoins;
    BOOST_CHECK_MESSAGE(mintedPubCoin.size() == 15001,
         "Unexpected mintedPubCoin size in diff block of one group.");

    BOOST_CHECK_MESSAGE(zerocoinState->latestCoinIds[pubcoin.getDenomination()] == 2,
        "Unexpected latest coin id of common denomination.");

    zerocoinState->RemoveBlock(&index);
    BOOST_CHECK_MESSAGE(zerocoinState->latestCoinIds[pubcoin.getDenomination()] == 1,
         "Unexpected latestcoin id of common denomination after remove 15001 block.");

    zerocoinState->Reset();
} */

// Checking RemoveSpendFromMempool, when coin is in mempool
BOOST_AUTO_TEST_CASE(sigma_remove_spend_from_mempool_coin_in)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoinV3> anonymity_set;
    anonymity_set.push_back(pubcoin);
    sigma::CoinSpendV3 coin(params,privcoin,anonymity_set);

    auto coinSerial = coin.getCoinSerialNumber();

    zerocoinState->AddSpendToMempool(coinSerial, txHash);
    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 1,
      "Unexpected mempoolCoinSerials size after call AddSpendToMempool.");

    zerocoinState->RemoveSpendFromMempool(coinSerial);
    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 0,
      "Unexpected mempoolCoinSerials size after call AddSpendToMempool.");
    zerocoinState->Reset();
}

// Checking RemoveSpendFromMempool, when coin is not in mempool
BOOST_AUTO_TEST_CASE(sigma_remove_spend_from_mempool_coin_not_in)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoinV3> anonymity_set;
    anonymity_set.push_back(pubcoin);
    sigma::CoinSpendV3 coin(params,privcoin,anonymity_set);

    auto coinSerial = coin.getCoinSerialNumber();

    zerocoinState->RemoveSpendFromMempool(coinSerial);
    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 0,
      "Unexpected mempoolCoinSerials size after call AddSpendToMempool.");
    zerocoinState->Reset();
}

// Checking AddSpendToMempool, when coin was used (in usedCoinSerials)
BOOST_AUTO_TEST_CASE(sigma_addspend_to_mempool_coin_used)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoinV3> anonymity_set;
    anonymity_set.push_back(pubcoin);
    sigma::CoinSpendV3 coin(params,privcoin,anonymity_set);

    auto coinSerial = coin.getCoinSerialNumber();

    zerocoinState->AddSpend(coinSerial);
    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 0,
      "Unexpected mempoolCoinSerials size before call AddSpendToMempool.");

    zerocoinState->AddSpendToMempool(coinSerial, txHash);
    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 0,
      "Unexpected mempoolCoinSerials size after call AddSpendToMempool.");

    zerocoinState->Reset();
}

// Checking AddSpendToMempool, when coin was not used
BOOST_AUTO_TEST_CASE(sigma_addspendtomempool)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoinV3> anonymity_set;
    anonymity_set.push_back(pubcoin);
    sigma::CoinSpendV3 coin(params,privcoin,anonymity_set);

    auto coinSerial = coin.getCoinSerialNumber();

    zerocoinState->AddSpendToMempool(coinSerial, txHash);
    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 1,
      "Unexpected mempoolCoinSerials size after call AddSpendToMempool.");

    zerocoinState->Reset();
}

// Checking AddSpendToMempool, when coin is already in mempool
BOOST_AUTO_TEST_CASE(sigma_addspendtomempool_coinin)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoinV3> anonymity_set;
    anonymity_set.push_back(pubcoin);
    sigma::CoinSpendV3 coin(params,privcoin, anonymity_set);

    auto coinSerial = coin.getCoinSerialNumber();

    zerocoinState->AddSpendToMempool(coinSerial, txHash);

    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 1,
      "Unexpected mempoolCoinSerials size after first call AddSpendToMempool.");
    zerocoinState->AddSpendToMempool(coinSerial, txHash);
    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 1,
      "Unexpected mempoolCoinSerials size after second call AddSpendToMempool.");

    zerocoinState->Reset();
}

// Checking CanAddSpendToMempool, when coin is already in mempool
BOOST_AUTO_TEST_CASE(sigma_canaddspendtomempool_inmempool)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoinV3> anonymity_set;
    anonymity_set.push_back(pubcoin);
    sigma::CoinSpendV3 coin(params,privcoin,anonymity_set);

    auto coinSerial = coin.getCoinSerialNumber();

    BOOST_CHECK_MESSAGE(zerocoinState->CanAddSpendToMempool(coinSerial),
      "CanAddSpendToMempool return false, which means coin already in use, but should not.");

    zerocoinState->AddSpendToMempool(coinSerial, txHash);

    BOOST_CHECK_MESSAGE(!zerocoinState->CanAddSpendToMempool(coinSerial),
      "CanAddSpendToMempool return true, which means coin not in use, but should be.");

    zerocoinState->Reset();
}

// Checking CanAddSpendToMempool, when coin is already used
BOOST_AUTO_TEST_CASE(sigma_canaddspendtomempool_used)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();

    std::vector<sigma::PublicCoinV3> anonymity_set;
    anonymity_set.push_back(pubcoin);
    sigma::CoinSpendV3 coin(params,privcoin,anonymity_set);

    auto coinSerial = coin.getCoinSerialNumber();

    zerocoinState->AddSpend(coinSerial);

    BOOST_CHECK_MESSAGE(!zerocoinState->CanAddSpendToMempool(coinSerial),
      "CanAddSpendToMempool return true, which means coin not in use, but should be.");

    zerocoinState->Reset();
}

// Checking Reset
BOOST_AUTO_TEST_CASE(sigma_reset)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    CScript scriptPubKey2;
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();
    CBlockIndex index = CreateBlockIndex(1);

    // Let's add data to zerocoinstate before reset

    zerocoinState->AddMint(&index, pubcoin);

    BOOST_CHECK_MESSAGE(zerocoinState->mintedPubCoins.size() == 1,
      "Unexpected mintedPubCoin size before reset.");
    BOOST_CHECK_MESSAGE(zerocoinState->coinGroups.size() == 1,
      "Unexpected coinGroups size before reset.");

    std::vector<sigma::PublicCoinV3> anonymity_set;
    anonymity_set.push_back(pubcoin);
    sigma::CoinSpendV3 coin(params,privcoin,anonymity_set);

    auto coinSerial = coin.getCoinSerialNumber();

    zerocoinState->AddSpendToMempool(coinSerial, txHash);

    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 1,
      "Unexpected mempoolCoinSerials size before reset.");

    zerocoinState->AddSpend(coinSerial);

    BOOST_CHECK_MESSAGE(zerocoinState->usedCoinSerials.size() == 1,
      "Unexpected usedCoinSerials size before reset.");
    BOOST_CHECK_MESSAGE(zerocoinState->latestCoinIds.size() == 1,
      "Unexpected mintedPubCoin size before reset.");

    zerocoinState->Reset();

    BOOST_CHECK_MESSAGE(zerocoinState->mintedPubCoins.size() == 0,
      "Unexpected mintedPubCoin size after reset.");
    BOOST_CHECK_MESSAGE(zerocoinState->coinGroups.size() == 0,
      "Unexpected coinGroups size after reset.");
    BOOST_CHECK_MESSAGE(zerocoinState->usedCoinSerials.size() == 0,
      "Unexpected usedCoinSerials size after reset.");
    BOOST_CHECK_MESSAGE(zerocoinState->latestCoinIds.size() == 0,
      "Unexpected mintedPubCoin size after reset.");
    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 0,
      "Unexpected mintedPubCoin size after reset.");
}

// Checking GetCoinGroupInfo, when coingroup is exist
BOOST_AUTO_TEST_CASE(sigma_getcoingroupinfo_existing)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    CScript scriptPubKey2;
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();
    CBlockIndex index = CreateBlockIndex(1);

    zerocoinState->AddMint(&index, pubcoin);
    auto mintedPubCoin = zerocoinState->mintedPubCoins;

    BOOST_CHECK_MESSAGE(mintedPubCoin.size() == 1,
        "Unexpected mintedPubCoin size after first call.");

    CZerocoinStateV3::CoinGroupInfoV3 result;
    zerocoinState->GetCoinGroupInfo(pubcoin.getDenomination(), 1, result);
    BOOST_CHECK_MESSAGE(result.nCoins == 1,
        "Unexpected number of coins in group.");
    BOOST_CHECK_MESSAGE(result.firstBlock->mintedPubCoins.size() == index.mintedPubCoins.size(),
        "Unexpected first block index for Group info.");
    BOOST_CHECK_MESSAGE(result.lastBlock->mintedPubCoins.size() == index.mintedPubCoins.size(),
        "Unexpected last block index for Group info.");

    zerocoinState->Reset();
}

// Checking GetCoinGroupInfo, when coingroup is not minted
BOOST_AUTO_TEST_CASE(sigma_getcoingroupinfo_not_minted)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    CScript scriptPubKey2;
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();
    CBlockIndex index = CreateBlockIndex(1);

    CZerocoinStateV3::CoinGroupInfoV3 result;
    zerocoinState->GetCoinGroupInfo(pubcoin.getDenomination(), 1, result);
    BOOST_CHECK_MESSAGE(result.nCoins == 0,
        "Unexpected number of coins in group.");

    zerocoinState->Reset();
}

BOOST_AUTO_TEST_CASE(zerocoin_sigma_addblock_nonexist_index)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    CScript scriptPubKey2;
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin;
    pubcoin = privcoin.getPublicCoin();
    CBlockIndex index = CreateBlockIndex(1);

	zerocoinState->AddBlock(&index);
	BOOST_CHECK_MESSAGE(zerocoinState->mintedPubCoins.size() == 0,
	  "Unexpected mintedPubCoins size, add new block without minted txs.");

	BOOST_CHECK_MESSAGE(zerocoinState->usedCoinSerials.size() == 0,
	  "Unexpected usedCoinSerials size, add new block without spend txs.");

    zerocoinState->Reset();
}

BOOST_AUTO_TEST_CASE(zerocoin_sigma_addblock_minted_spend)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    CScript scriptPubKey2;
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin1(params);
    sigma::PublicCoinV3 pubcoin1;
    pubcoin1 = privcoin1.getPublicCoin();

    const sigma::PrivateCoinV3 privcoin2(params);
    sigma::PublicCoinV3 pubcoin2;
    pubcoin2 = privcoin2.getPublicCoin();

    CBlockIndex index = CreateBlockIndex(1);
    std::pair<CoinDenominationV3, int> denomination1Group1(
        CoinDenominationV3::SIGMA_DENOM_1,1);
    
	index.mintedPubCoinsV3[denomination1Group1].push_back(pubcoin1);
	index.mintedPubCoinsV3[denomination1Group1].push_back(pubcoin2);

	zerocoinState->AddBlock(&index);
	BOOST_CHECK_MESSAGE(zerocoinState->mintedPubCoins.size() == 2,
	  "Unexpected mintedPubCoins size, add new block with 2 minted txs.");

	BOOST_CHECK_MESSAGE(zerocoinState->usedCoinSerials.size() == 0,
	  "Unexpected usedCoinSerials size, add new block without spend txs.");

	// spend
    std::vector<sigma::PublicCoinV3> anonymity_set;
    anonymity_set.push_back(pubcoin1);
    anonymity_set.push_back(pubcoin2);
    sigma::CoinSpendV3 coinSpend(params,privcoin1,anonymity_set);

	auto spendSerial = coinSpend.getCoinSerialNumber();

    CBlockIndex index2 = CreateBlockIndex(2);
	index2.spentSerialsV3.clear();
	index2.spentSerialsV3.insert(spendSerial);
	zerocoinState->AddBlock(&index2);
	BOOST_CHECK_MESSAGE(zerocoinState->mintedPubCoins.size() == 2,
	  "Unexpected mintedPubCoins size, add new block without additional minted.");

	BOOST_CHECK_MESSAGE(zerocoinState->usedCoinSerials.size() == 1,
	  "Unexpected usedCoinSerials size, add new block with 1 spend txs.");

    // minted more coin
    const sigma::PrivateCoinV3 privcoin3(params);
    sigma::PublicCoinV3 pubcoin3;
    pubcoin3 = privcoin3.getPublicCoin();
    CBlockIndex index3 = CreateBlockIndex(3);

    index3.mintedPubCoinsV3[denomination1Group1].push_back(pubcoin3);
    zerocoinState->AddBlock(&index3);
    BOOST_CHECK_MESSAGE(zerocoinState->mintedPubCoins.size() == 3,
	  "Unexpected mintedPubCoins size, add new block with one more minted.");

	BOOST_CHECK_MESSAGE(zerocoinState->usedCoinSerials.size() == 1,
	  "Unexpected usedCoinSerials size, add new block without new spend");

    zerocoinState->Reset();
}

BOOST_AUTO_TEST_CASE(zerocoin_sigma_removeblock_remove)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    CScript scriptPubKey2;
    auto params = sigma::ParamsV3::get_default();

    // add index 1 with 10 minted
    auto coins = generateCoins(params,10);
    auto pubCoins = getPubcoins(coins);

    auto index1 = CreateBlockIndex(1);
    std::pair<CoinDenominationV3, int> denomination1Group1(CoinDenominationV3::SIGMA_DENOM_1, 1);
    index1.mintedPubCoinsV3[denomination1Group1] = pubCoins;
    
    // add index 2 with 10 minted and 1 spend
    auto coins2 = generateCoins(params,10);
    auto pubCoins2 = getPubcoins(coins2);

    auto index2 = CreateBlockIndex(2);
    std::pair<CoinDenominationV3, int> denomination1Group2(CoinDenominationV3::SIGMA_DENOM_1, 2);
    index2.mintedPubCoinsV3[denomination1Group2] = pubCoins2;

    sigma::CoinSpendV3 coinSpend(params,coins[0],pubCoins);

    index2.spentSerialsV3.clear();
	index2.spentSerialsV3.insert(coinSpend.getCoinSerialNumber());

    zerocoinState->AddBlock(&index1);
    zerocoinState->AddBlock(&index2);

    BOOST_CHECK_MESSAGE(zerocoinState->latestCoinIds[CoinDenominationV3::SIGMA_DENOM_1] == 2,
      "Unexpected lastestcoinId");
    BOOST_CHECK_MESSAGE(zerocoinState->HasCoin(pubCoins2[0]),
      "Coin isn't in state before remove index 2");

    // remove one
    zerocoinState->RemoveBlock(&index2);
    BOOST_CHECK_MESSAGE(zerocoinState->mintedPubCoins.size() == 10,
	  "Unexpected mintedPubCoins size, remove index contain 10 minteds.");

	BOOST_CHECK_MESSAGE(zerocoinState->usedCoinSerials.size() == 0,
	  "Unexpected usedCoinSerials size, remove index contain 1 spend.");
    
    BOOST_CHECK_MESSAGE(zerocoinState->latestCoinIds[CoinDenominationV3::SIGMA_DENOM_1] == 1,
      "Unexpected lastestcoinId");

    BOOST_CHECK_MESSAGE(zerocoinState->HasCoin(pubCoins[0]),
      "Coin isn't in state before remove index 1");
    BOOST_CHECK_MESSAGE(!zerocoinState->HasCoin(pubCoins2[0]),
      "Coin is in state after remove index 2");

    // remove all
    zerocoinState->RemoveBlock(&index1);
    BOOST_CHECK_MESSAGE(zerocoinState->mintedPubCoins.size() == 0,
	  "Unexpected mintedPubCoins size, remove index contain 10 minteds.");

	BOOST_CHECK_MESSAGE(zerocoinState->usedCoinSerials.size() == 0,
	  "Unexpected usedCoinSerials size, remove index contain no spend.");
    
    BOOST_CHECK_MESSAGE(zerocoinState->latestCoinIds[CoinDenominationV3::SIGMA_DENOM_1] == 0,
      "Unexpected lastestcoinId remove all");

    BOOST_CHECK_MESSAGE(!zerocoinState->HasCoin(pubCoins[0]),
      "Coin is in state after remove index 1");

    zerocoinState->Reset();
}

BOOST_AUTO_TEST_CASE(getmempoolconflictingtxhash_added_no)
{
    CZerocoinStateV3 state;

    secp_primitives::Scalar serial;
    serial.randomize();

    BOOST_CHECK(state.GetMempoolConflictingTxHash(serial) == uint256());
}

BOOST_AUTO_TEST_CASE(getmempoolconflictingtxhash_added_yes)
{
    CZerocoinStateV3 state;

    secp_primitives::Scalar serial;
    serial.randomize();

    auto txid = uint256S("c8cdacf6b51275a3de9496073c75708abde26cb2f6cb164e0a1a0ed942c3c6e7");

    BOOST_TEST(state.AddSpendToMempool(serial, txid));
    BOOST_CHECK(state.GetMempoolConflictingTxHash(serial) == txid);
}

BOOST_AUTO_TEST_CASE(zerocoingetspendserialnumberv3_valid_tx_valid_vin)
{
    // setup
    CScript scriptPubKey2;
    auto params = sigma::ParamsV3::get_default();

    // spend
    auto coins = generateCoins(params,10);
    auto pubCoins = getPubcoins(coins);

    sigma::CoinSpendV3 coinSpend(params,coins[0],pubCoins);

    CDataStream serializedCoinSpend(SER_NETWORK, PROTOCOL_VERSION);
    serializedCoinSpend << coinSpend;

    // create tx and vin
    
    CTxIn newTxIn;
    newTxIn.scriptSig = CScript();
    newTxIn.prevout.SetNull();

    CScript tmp = CScript() << OP_ZEROCOINSPENDV3;
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
    BOOST_CHECK_MESSAGE(ZerocoinGetSpendSerialNumberV3(ctx,newTxIn) != Scalar(uint64_t(0)),
      "Expect serial number, got 0");

    // add more spend vin
    sigma::CoinSpendV3 coinSpend2(params,coins[1],pubCoins);

    CDataStream serializedCoinSpend2(SER_NETWORK, PROTOCOL_VERSION);
    serializedCoinSpend2 << coinSpend2;

    CTxIn newTxIn2;
    newTxIn2.scriptSig = CScript();
    newTxIn2.prevout.SetNull();

    CScript tmp2 = CScript() << OP_ZEROCOINSPENDV3;
    tmp2.insert(tmp2.end(), serializedCoinSpend2.begin(), serializedCoinSpend2.end());

    newTxIn2.scriptSig.assign(tmp2.begin(), tmp2.end());
    newtx.vin.push_back(newTxIn);

    CTransaction ctx2(newtx);

    // check
    BOOST_CHECK_MESSAGE(ZerocoinGetSpendSerialNumberV3(ctx2,newTxIn2) != Scalar(uint64_t(0)),
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

    BOOST_CHECK_MESSAGE(ZerocoinGetSpendSerialNumberV3(ctx3, newTxVin3) == Scalar(uint64_t(0)),
      "Expect 0 got serial");
}

BOOST_AUTO_TEST_CASE(zerocoingetspendserialnumberv3_invalid_script)
{
    // setup
    CScript scriptPubKey2;
    auto params = sigma::ParamsV3::get_default();

    // spend
    auto coins = generateCoins(params,10);
    auto pubCoins = getPubcoins(coins);

    sigma::CoinSpendV3 coinSpend(params,coins[0],pubCoins);

    CDataStream serializedCoinSpend(SER_NETWORK, PROTOCOL_VERSION);
    serializedCoinSpend << coinSpend;

    // create tx and vin
    
    CTxIn newTxIn;
    newTxIn.scriptSig = CScript();
    newTxIn.prevout.SetNull();

    CScript tmp = CScript() << OP_ZEROCOINSPENDV3;
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
    BOOST_CHECK_MESSAGE(ZerocoinGetSpendSerialNumberV3(ctx,newTxIn) == Scalar(uint64_t(0)),
      "Expect 0 got serial, Wrong script");
}

BOOST_AUTO_TEST_CASE(getzerocoinstate_not_null)
{
    BOOST_CHECK_MESSAGE(CZerocoinStateV3::GetZerocoinState() != NULL,
      "GetZerocoinState() return null");
}

BOOST_AUTO_TEST_CASE(sigma_build_state)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    auto params = sigma::ParamsV3::get_default();

    CBlockIndex index0 = CreateBlockIndex(0);
    chainActive.SetTip(&index0);

    CBlockIndex index1 = CreateBlockIndex(1);

    // add index 1 with 10 SIGMA_DENOM_1
    auto coins = generateCoins(params, 10);
    auto pubCoins = getPubcoins(coins);
    std::pair<CoinDenominationV3, int> denomination1Group1(CoinDenominationV3::SIGMA_DENOM_1, 1);
    std::pair<CoinDenominationV3, int> denomination10Group1(CoinDenominationV3::SIGMA_DENOM_10, 1);

    index1.mintedPubCoinsV3[denomination1Group1] = pubCoins;

    chainActive.SetTip(&index1);

    CBlockIndex index2 = CreateBlockIndex(2);
    // add index 2 with 1 DENOMINATIO_1  mints and 1 spend
    auto coins2 = generateCoins(params,1);
    auto pubCoins2 = getPubcoins(coins2);
    auto coins3 = generateCoins(params,1);
    auto pubCoins3 = getPubcoins(coins3);

    // mock spend
    secp_primitives::Scalar serial;
    serial.randomize();

    index2.spentSerialsV3.insert(serial);

    index2.mintedPubCoinsV3[denomination1Group1] = pubCoins2;
    index2.mintedPubCoinsV3[denomination10Group1] = pubCoins3;

    chainActive.SetTip(&index2);

    for(int i =3 ;i<=100;i++){
		CBlockIndex index = CreateBlockIndex(i);
        chainActive.SetTip(&index);
	}

    ZerocoinBuildStateFromIndexV3(&chainActive);

    // check group
    CZerocoinStateV3::CoinGroupInfoV3 group;
    zerocoinState->GetCoinGroupInfo(CoinDenominationV3::SIGMA_DENOM_1, 1, group);
    BOOST_CHECK_MESSAGE(group.firstBlock->nHeight == index1.nHeight, "Expect firstBlock == index1");
    BOOST_CHECK_MESSAGE(group.lastBlock->nHeight == index2.nHeight, "Expect lastBlock == index2");
    BOOST_CHECK_MESSAGE(group.nCoins == 11, "Expect nCoins == 11");

    CZerocoinStateV3::CoinGroupInfoV3 group2;
    zerocoinState->GetCoinGroupInfo(CoinDenominationV3::SIGMA_DENOM_10, 1, group2);
    BOOST_CHECK_MESSAGE(group2.firstBlock->nHeight == index2.nHeight, "Expect firstBlock == index2");
    BOOST_CHECK_MESSAGE(group2.lastBlock->nHeight == index2.nHeight, "Expect lastBlock == index2");
    BOOST_CHECK_MESSAGE(group2.nCoins == 1, "Expect nCoins == 1");

    // check serial
    secp_primitives::Scalar notFoundSerial;
    notFoundSerial.randomize();
    BOOST_CHECK_MESSAGE(zerocoinState->IsUsedCoinSerial(serial), "Expect found serial");
    BOOST_CHECK_MESSAGE(!zerocoinState->IsUsedCoinSerial(notFoundSerial), "Expect not found serial");

    // has coin
    auto notFoundCoins = generateCoins(params,10);
    auto notFoundPubCoins = getPubcoins(notFoundCoins);
    BOOST_CHECK_MESSAGE(zerocoinState->HasCoin(pubCoins[0]), "Expect found pubcoin");
    BOOST_CHECK_MESSAGE(zerocoinState->HasCoin(pubCoins3[0]), "Expect found pubcoin");
    BOOST_CHECK_MESSAGE(!zerocoinState->HasCoin(notFoundPubCoins[0]), "Expect not found pubcoin");

    // get mint coin heigh and id
    std::pair<int,int> groupHeightAndID = zerocoinState->GetMintedCoinHeightAndId(pubCoins2[0]);
    BOOST_CHECK_MESSAGE(groupHeightAndID.first == index2.nHeight, "Expect pubcoin on index2");
    BOOST_CHECK_MESSAGE(groupHeightAndID.second == 1, "Expect pubcoin id == 1");

    std::pair<int,int> notFoundGroupHeightAndID = zerocoinState->GetMintedCoinHeightAndId(notFoundPubCoins[0]);
    BOOST_CHECK_MESSAGE(notFoundGroupHeightAndID == std::make_pair(-1,-1),"Expect not found return -1,-1");

    zerocoinState->Reset();
}

BOOST_AUTO_TEST_CASE(sigma_build_state_no_sigma)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    auto params = sigma::ParamsV3::get_default();

    std::vector<CBlockIndex> indexs;
    indexs.resize(101);
    for(int i =0 ;i<=100;i++){
		CBlockIndex index = CreateBlockIndex(i);
        chainActive.SetTip(&index);
        indexs[i] = index;
	}

    ZerocoinBuildStateFromIndexV3(&chainActive);

    // check group
    CZerocoinStateV3::CoinGroupInfoV3 group;
    bool found = zerocoinState->GetCoinGroupInfo(CoinDenominationV3::SIGMA_DENOM_1, 1, group);
    BOOST_CHECK_MESSAGE(!found, "Expect group not found");

    // check serial
    secp_primitives::Scalar notFoundSerial;
    notFoundSerial.randomize();
    BOOST_CHECK_MESSAGE(!zerocoinState->IsUsedCoinSerial(notFoundSerial), "Expect not found serial");

    // has coin
    auto notFoundCoins = generateCoins(params,10);
    auto notFoundPubCoins = getPubcoins(notFoundCoins);
    BOOST_CHECK_MESSAGE(!zerocoinState->HasCoin(notFoundPubCoins[0]), "Expect not found pubcoin");

    // get mint coin heigh and id
    std::pair<int,int> notFoundGroupHeightAndID = zerocoinState->GetMintedCoinHeightAndId(notFoundPubCoins[0]);
    BOOST_CHECK_MESSAGE(notFoundGroupHeightAndID == std::make_pair(-1,-1),"Expect not found return -1,-1");

    zerocoinState->Reset();
}


BOOST_AUTO_TEST_CASE(sigma_getcoinsetforspend)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    auto params = sigma::ParamsV3::get_default();
    int nextIndex = 0;
    std::vector<CBlockIndex> indexes;
    indexes.resize(101);
    
    // nextIndex = 0
    indexes[nextIndex] = CreateBlockIndex(nextIndex);
    chainActive.SetTip(&indexes[nextIndex]);

    // nextIndex = 1
    nextIndex++;
    indexes[nextIndex] = CreateBlockIndex(nextIndex);

    std::pair<CoinDenominationV3, int> denomination1Group1(CoinDenominationV3::SIGMA_DENOM_1, 1);
    std::pair<CoinDenominationV3, int> denomination10Group1(CoinDenominationV3::SIGMA_DENOM_10, 1);

    // add index 1 with 10 SIGMA_DENOM_1
    auto coins = generateCoins(params, 10);
    auto pubCoins = getPubcoins(coins);
    
    // add index 2 with 1 DENOM_1  mints and 1 spend
    auto coins2 = generateCoins(params, 1);
    auto pubCoins2 = getPubcoins(coins2);
    auto coins3 = generateCoins(params, 5);
    auto pubCoins3 = getPubcoins(coins3);

    indexes[nextIndex].mintedPubCoinsV3[denomination1Group1] = pubCoins;
    chainActive.SetTip(&indexes[nextIndex]);

    nextIndex++;
    indexes[nextIndex] = CreateBlockIndex(nextIndex);

    // mock spend
    secp_primitives::Scalar serial;
    serial.randomize();

    indexes[nextIndex].spentSerialsV3.insert(serial);
    indexes[nextIndex].mintedPubCoinsV3[denomination1Group1] = pubCoins2;
    indexes[nextIndex].mintedPubCoinsV3[denomination10Group1] = pubCoins3;

    chainActive.SetTip(&indexes[nextIndex]);
    
    // nextIndex = 3
    nextIndex++;
    for( ; nextIndex<=100; nextIndex++){
		indexes[nextIndex] = CreateBlockIndex(nextIndex);
        chainActive.SetTip(&indexes[nextIndex]);
	}

    ZerocoinBuildStateFromIndexV3(&chainActive);

    uint256 blockHash_out;
    uint256 blockHash_empty;

    std::vector<PublicCoinV3> coins_out3;
    // maxheight < blockheight
    auto coins_amount = zerocoinState->GetCoinSetForSpend(&chainActive, 1,
    CoinDenominationV3::SIGMA_DENOM_10, 1, blockHash_out, coins_out3);
    BOOST_CHECK_MESSAGE(coins_amount == 0, "Unexpected Coins amount for spend, should be 0.");
    BOOST_CHECK_MESSAGE(coins_out3.size() == 0, "Unexpected coins out, should be 0.");
    BOOST_CHECK_MESSAGE(blockHash_out == blockHash_empty , "Unexpected blockhash for small height.");

    std::vector<PublicCoinV3> coins_out1;
    // maxheight > blockheight
    coins_amount = zerocoinState->GetCoinSetForSpend(&chainActive, nextIndex, 
    CoinDenominationV3::SIGMA_DENOM_10, 1, blockHash_out, coins_out1);
    BOOST_CHECK_MESSAGE(coins_amount == 5, "Unexpected Coins amount for spend, should be 5.");
    BOOST_CHECK_MESSAGE(coins_out1 == pubCoins3, "Unexpected coins out for denom 10.");
    BOOST_CHECK_MESSAGE(blockHash_out == indexes[2].GetBlockHash(), "Unexpected blockhash for denom 10.");

    std::vector<PublicCoinV3> coins_out2;
    // maxheight > blockheight another denom
    coins_amount = zerocoinState->GetCoinSetForSpend(&chainActive, nextIndex, 
    CoinDenominationV3::SIGMA_DENOM_1, 1, blockHash_out, coins_out2);
    BOOST_CHECK_MESSAGE(coins_amount == 11, "Unexpected Coins amount for spend, should be 11.");
    BOOST_CHECK_MESSAGE(coins_out2.size() == pubCoins2.size() + pubCoins.size(), "Unexpected coins out for denom 1.");
    BOOST_CHECK_MESSAGE(blockHash_out == indexes[2].GetBlockHash(), "Unexpected blockhash for denom 1.");

    zerocoinState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
