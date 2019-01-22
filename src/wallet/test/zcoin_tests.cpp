// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"

#include <set>
#include <stdint.h>
#include <utility>
#include <vector>
#include <exception>
#include <algorithm>

#include "wallet/test/wallet_test_fixture.h"
#include "zerocoin_v3.h"

#include <boost/foreach.hpp>
#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_FIXTURE_TEST_SUITE(sigma_wallet_tests, WalletTestingSetup)

static bool addSigmaCoin(const sigma::PrivateCoinV3& coin, const sigma::CoinDenominationV3 denomination)
{
    sigma::PublicCoinV3 pubCoin = coin.getPublicCoin();

    CZerocoinEntryV3 zerocoinTx;
    zerocoinTx.IsUsed = false;
    zerocoinTx.denomination = denomination;
    zerocoinTx.value = pubCoin.getValue();
    zerocoinTx.randomness = coin.getRandomness();
    zerocoinTx.serialNumber = coin.getSerialNumber();

    return CWalletDB(pwalletMain->strWalletFile).WriteZerocoinEntry(zerocoinTx);
}

static bool generateWalletCoin( const std::vector<std::pair<sigma::CoinDenominationV3,int>> coins)
{
    auto params = sigma::ParamsV3::get_default();
    BOOST_FOREACH(auto &coin, coins)
    {
        for(int i =0;i<coin.second;i++){
            sigma::PrivateCoinV3 privCoin(params);
            addSigmaCoin(privCoin,coin.first);
        }
    }

    return true;
}

static bool checkDenominationCoins(const std::vector<std::pair<sigma::CoinDenominationV3,int>>& need,const std::vector<CZerocoinEntryV3>& gots)
{
    // flatter need
    std::vector<sigma::CoinDenominationV3> needDenominations;
    BOOST_FOREACH(auto &denominationNeed, need){
        for(int i =0 ;i<denominationNeed.second;i++)
        {
            needDenominations.push_back(denominationNeed.first);
        }
    }

    // got denominations set for `got` vector
    std::vector<sigma::CoinDenominationV3> gotDenominations;
    BOOST_FOREACH(auto &got,gots){
        sigma::CoinDenominationV3 denomination_result;
        bool result = sigma::IntegerToDenomination(got.denomination*COIN,denomination_result);
        BOOST_CHECK_MESSAGE(result,"Wrong denomination");
        gotDenominations.push_back(denomination_result);
    }

    // miss coin number
    if(needDenominations.size() != gotDenominations.size())
        return false;

    std::sort(needDenominations.begin(),needDenominations.end());
    std::sort(gotDenominations.begin(),gotDenominations.end());

    // denominations must be match
    for(int i =0 ;i< needDenominations.size();i++)
        if(needDenominations[i] != gotDenominations[i])
            return false;

    return true;
}

BOOST_AUTO_TEST_CASE(auto_no_coin)
{
    CAmount require(0);
    require += sigma::ZQ_LOVELACE;

    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetMintCoins(require,coins) == 0, \
      "Expect enough coin and equal to one for each denomination with more ZQ_LOVELACE");

    std::vector<std::pair<sigma::CoinDenominationV3,int>> needCoins;

    BOOST_CHECK_MESSAGE(checkDenominationCoins(needCoins, coins), \
      "Expect one for each denomination with onemore ZQ_LOVELACE");
}

BOOST_AUTO_TEST_CASE(auto_different_denomination)
{
    std::vector<std::pair<sigma::CoinDenominationV3,int>> newCoins;
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_LOVELACE,2));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_GOLDWASSER,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_RACKOFF,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_PEDERSEN,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_WILLIAMSON,1));
    generateWalletCoin(newCoins);

    CAmount require(0);
    require += sigma::ZQ_LOVELACE*2;
    require += sigma::ZQ_GOLDWASSER;
    require += sigma::ZQ_RACKOFF;
    require += sigma::ZQ_PEDERSEN;
    require += sigma::ZQ_WILLIAMSON;

    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetMintCoins(require,coins) == require, \
      "Expect enough coin and equal to one for each denomination with more ZQ_LOVELACE");

    std::vector<std::pair<sigma::CoinDenominationV3,int>> needCoins;
    needCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(ZQ_LOVELACE,2));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(ZQ_GOLDWASSER,1));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(ZQ_RACKOFF,1));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(ZQ_PEDERSEN,1));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(ZQ_WILLIAMSON,1));

    BOOST_CHECK_MESSAGE(checkDenominationCoins(needCoins, coins), \
      "Expect one for each denomination with onemore ZQ_LOVELACE");
}

BOOST_AUTO_TEST_CASE(auto_not_enough)
{
    std::vector<std::pair<sigma::CoinDenominationV3,int>> newCoins;
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_LOVELACE,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_GOLDWASSER,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_RACKOFF,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_PEDERSEN,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_WILLIAMSON,1));
    generateWalletCoin(newCoins);

    CAmount require(0);
    require += sigma::ZQ_LOVELACE*2;
    require += sigma::ZQ_GOLDWASSER;
    require += sigma::ZQ_RACKOFF;
    require += sigma::ZQ_PEDERSEN;
    require += sigma::ZQ_WILLIAMSON;
    
    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetMintCoins(require,coins) == require-sigma::ZQ_LOVELACE, \
      "Expect not enough coin and equal to one for each denomination");

    std::vector<std::pair<sigma::CoinDenominationV3,int>> needCoins;
    needCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(ZQ_LOVELACE,1));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(ZQ_GOLDWASSER,1));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(ZQ_RACKOFF,1));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(ZQ_PEDERSEN,1));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(ZQ_WILLIAMSON,1));

    BOOST_CHECK_MESSAGE(checkDenominationCoins(needCoins, coins), \
      "Expect one for each denomination");
}

BOOST_AUTO_TEST_CASE(auto_large_coin_first)
{
    std::vector<std::pair<sigma::CoinDenominationV3,int>> newCoins;
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_PEDERSEN,2));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_WILLIAMSON,1));
    generateWalletCoin(newCoins);

    CAmount require(0);
    require += sigma::ZQ_WILLIAMSON;
    
    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetMintCoins(require,coins) == sigma::ZQ_WILLIAMSON, \
      "Expect enough coin and equal to one ZQ_WILLIAMSON");

    std::vector<std::pair<sigma::CoinDenominationV3,int>> needCoins;
    needCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(ZQ_WILLIAMSON,1));

    BOOST_CHECK_MESSAGE(checkDenominationCoins(needCoins, coins), \
      "Expect only one ZQ_WALLIAMSON");
}

BOOST_AUTO_TEST_CASE(auto_minimize_coins_spend)
{
    std::vector<std::pair<sigma::CoinDenominationV3,int>> newCoins;
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_RACKOFF,2));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_WILLIAMSON,1));
    generateWalletCoin(newCoins);

    CAmount require(0);
    require += sigma::ZQ_PEDERSEN;
    
    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetMintCoins(require,coins) == sigma::ZQ_WILLIAMSON, \
      "Expect enough coin and equal one ZQ_WILLIAMSON");

    std::vector<std::pair<sigma::CoinDenominationV3,int>> needCoins;
    needCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(ZQ_WILLIAMSON,1));

    BOOST_CHECK_MESSAGE(checkDenominationCoins(needCoins, coins), \
      "Expect only one ZQ_WALLIAMSON");;
}

BOOST_AUTO_TEST_CASE(auto_choose_smallest_enough)
{
    std::vector<std::pair<sigma::CoinDenominationV3,int>> newCoins;
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_WILLIAMSON,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_PEDERSEN,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(sigma::ZQ_RACKOFF,1));
    generateWalletCoin(newCoins);

    CAmount require(0);
    require += sigma::ZQ_GOLDWASSER;
    
    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetMintCoins(require,coins) == sigma::ZQ_RACKOFF, \
      "Expect enough coin and equal one ZQ_RACKOFF");

    std::vector<std::pair<sigma::CoinDenominationV3,int>> needCoins;
    needCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(ZQ_RACKOFF,1));

    BOOST_CHECK_MESSAGE(checkDenominationCoins(needCoins, coins), \
      "Expect only one ZQ_RACKOFF");
}

BOOST_AUTO_TEST_SUITE_END()
