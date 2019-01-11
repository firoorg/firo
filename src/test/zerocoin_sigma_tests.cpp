#include "main.h"
#include "zerocoin_v3.h"

#include <boost/test/unit_test.hpp>
#include <libzerocoin/sigma/CoinSpend.h>
#include <libzerocoin/sigma/Coin.h>

using namespace std;

BOOST_AUTO_TEST_SUITE(zerocoin_sigma_test)

const uint256 txHash = uint256S("a64bf7b459d3bb09653e444d75a942e9848ed8e1f30e2890f999426ed6dd4a2c");

CBlockIndex CreateBlockIndex(int nHeight)
{
    CBlockIndex index;
    index.nHeight = nHeight;
    index.pprev = chainActive.Tip();
    return index;
}

// Checking AddSpend
BOOST_AUTO_TEST_CASE(zerocoin_sigma_addspend)
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
BOOST_AUTO_TEST_CASE(zerocoin_sigma_hascoin_false)
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
BOOST_AUTO_TEST_CASE(zerocoin_sigma_hascoin_true)
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
BOOST_AUTO_TEST_CASE(zerocoin_sigma_getmintcoinheightandid_true)
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
BOOST_AUTO_TEST_CASE(zerocoin_sigma_get_mintcoin_height_and_id_false)
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
BOOST_AUTO_TEST_CASE(zerocoin_sigma_addmint_double)
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
BOOST_AUTO_TEST_CASE(zerocoin_sigma_addmint_two)
{
    CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
    CScript scriptPubKey2;
    auto params = sigma::ParamsV3::get_default();

    const sigma::PrivateCoinV3 privcoin(params);
    sigma::PublicCoinV3 pubcoin1;
    sigma::PublicCoinV3 pubcoin2;

    pubcoin1 = privcoin.getPublicCoin();
    pubcoin2 = privcoin.getPublicCoin();

    CBlockIndex index = CreateBlockIndex(1);
    zerocoinState->AddMint(&index, pubcoin1);
    zerocoinState->AddMint(&index, pubcoin2);

    auto mintedPubCoin = zerocoinState->mintedPubCoins;
    
    BOOST_CHECK_MESSAGE(mintedPubCoin.size() == 2, "Unexpected mintedPubCoin size.");

    zerocoinState->Reset();
}

// Checking AddSpendToMempool, when coin was used (in usedCoinSerials)
BOOST_AUTO_TEST_CASE(zerocoin_sigma_addspend_to_mempool_coin_used)
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
    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 0, \
     "Unexpected mempoolCoinSerials size before call AddSpendToMempool."); 

    zerocoinState->AddSpendToMempool(coinSerial, txHash);
    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 0, \
     "Unexpected mempoolCoinSerials size after call AddSpendToMempool."); 

    zerocoinState->Reset(); 
}

// Checking AddSpendToMempool, when coin was not used
BOOST_AUTO_TEST_CASE(zerocoin_sigma_addspendtomempool)
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
    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 1, \
     "Unexpected mempoolCoinSerials size after call AddSpendToMempool."); 
    
    zerocoinState->Reset();
}

// Checking AddSpendToMempool, when coin is already in mempool
BOOST_AUTO_TEST_CASE(zerocoin_sigma_addspendtomempool_coinin)
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

    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 1, \
     "Unexpected mempoolCoinSerials size after first call AddSpendToMempool."); 
    zerocoinState->AddSpendToMempool(coinSerial, txHash);
    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 1, \
     "Unexpected mempoolCoinSerials size after second call AddSpendToMempool."); 
    
    zerocoinState->Reset();
}

// Checking CanAddSpendToMempool, when coin is already in mempool
BOOST_AUTO_TEST_CASE(zerocoin_sigma_canaddspendtomempool_inmempool)
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

    BOOST_CHECK_MESSAGE(zerocoinState->CanAddSpendToMempool(coinSerial), \
     "CanAddSpendToMempool return false, which means coin already in use, but should not."); 

    zerocoinState->AddSpendToMempool(coinSerial, txHash);

    BOOST_CHECK_MESSAGE(!zerocoinState->CanAddSpendToMempool(coinSerial), \
     "CanAddSpendToMempool return true, which means coin not in use, but should be."); 
    
    zerocoinState->Reset();
}

// Checking CanAddSpendToMempool, when coin is already used
BOOST_AUTO_TEST_CASE(zerocoin_sigma_canaddspendtomempool_used)
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

    BOOST_CHECK_MESSAGE(!zerocoinState->CanAddSpendToMempool(coinSerial), \
     "CanAddSpendToMempool return true, which means coin not in use, but should be."); 
    
    zerocoinState->Reset();
}

// Checking Reset 
BOOST_AUTO_TEST_CASE(zerocoin_sigma_reset)
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

    BOOST_CHECK_MESSAGE(zerocoinState->mintedPubCoins.size() == 1, \
     "Unexpected mintedPubCoin size before reset.");
    BOOST_CHECK_MESSAGE(zerocoinState->coinGroups.size() == 1, \
     "Unexpected coinGroups size before reset.");

    std::vector<sigma::PublicCoinV3> anonymity_set;
    anonymity_set.push_back(pubcoin);
    sigma::CoinSpendV3 coin(params,privcoin,anonymity_set);

    auto coinSerial = coin.getCoinSerialNumber();

    zerocoinState->AddSpendToMempool(coinSerial, txHash);

    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 1, \
     "Unexpected mempoolCoinSerials size before reset."); 
    
    zerocoinState->AddSpend(coinSerial);

    BOOST_CHECK_MESSAGE(zerocoinState->usedCoinSerials.size() == 1, \
     "Unexpected usedCoinSerials size before reset.");
    BOOST_CHECK_MESSAGE(zerocoinState->latestCoinIds.size() == 1, \
     "Unexpected mintedPubCoin size before reset.");

    zerocoinState->Reset();

    BOOST_CHECK_MESSAGE(zerocoinState->mintedPubCoins.size() == 0, \
     "Unexpected mintedPubCoin size after reset.");
    BOOST_CHECK_MESSAGE(zerocoinState->coinGroups.size() == 0, \
     "Unexpected coinGroups size after reset.");
    BOOST_CHECK_MESSAGE(zerocoinState->usedCoinSerials.size() == 0, \
     "Unexpected usedCoinSerials size after reset.");
    BOOST_CHECK_MESSAGE(zerocoinState->latestCoinIds.size() == 0, \
     "Unexpected mintedPubCoin size after reset.");
    BOOST_CHECK_MESSAGE(zerocoinState->mempoolCoinSerials.size() == 0, \
     "Unexpected mintedPubCoin size after reset."); 
}
BOOST_AUTO_TEST_SUITE_END()