// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../wallet.h"

#include <set>
#include <stdint.h>
#include <utility>
#include <vector>
#include <exception>
#include <algorithm>

#include "wallet_test_fixture.h"
#include "../../zerocoin_v3.h"

#include <boost/foreach.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(wallet_sigma_tests, WalletTestingSetup)

static bool AddSigmaCoin(const sigma::PrivateCoinV3& coin, const sigma::CoinDenominationV3 denomination)
{
    sigma::PublicCoinV3 pubCoin(coin.getPublicCoin());

    CZerocoinEntryV3 zerocoinTx;
    zerocoinTx.IsUsed = false;
    zerocoinTx.denomination = denomination;
    zerocoinTx.value = pubCoin.getValue();
    zerocoinTx.randomness = coin.getRandomness();
    zerocoinTx.serialNumber = coin.getSerialNumber();

    return CWalletDB(pwalletMain->strWalletFile).WriteZerocoinEntry(zerocoinTx);
}

static bool GenerateWalletCoin( const std::vector<std::pair<sigma::CoinDenominationV3,int>> coins)
{
    auto params = sigma::ParamsV3::get_default();

    for (auto& coin : coins) {
        for (int i = 0; i < coin.second; i++) {
            sigma::PrivateCoinV3 privCoin(params);
            AddSigmaCoin(privCoin,coin.first);
        }
    }

    return true;
}

static bool CheckDenominationCoins(const std::vector<std::pair<sigma::CoinDenominationV3,int>>& need, const std::vector<CZerocoinEntryV3>& gots)
{
    // flatter need
    std::vector<sigma::CoinDenominationV3> needDenominations;

    for (auto& denominationNeed: need){
        for (int i =0; i < denominationNeed.second; i++){
            needDenominations.push_back(denominationNeed.first);
        }
    }

    // got denominations set for `got` vector
    std::vector<sigma::CoinDenominationV3> gotDenominations;
    for(auto& got: gots){
        sigma::CoinDenominationV3 denominationResult;
        bool result = sigma::IntegerToDenomination(got.denomination*COIN, denominationResult);

        BOOST_CHECK_MESSAGE(result, "Wrong denomination");
        gotDenominations.push_back(denominationResult);
    }

    // miss coin number
    if (needDenominations.size() != gotDenominations.size())
        return false;

    std::sort(needDenominations.begin(), needDenominations.end());
    std::sort(gotDenominations.begin(), gotDenominations.end());

    // denominations must be match
    for (int i =0; i < needDenominations.size(); i++)
        if (needDenominations[i] != gotDenominations[i])
            return false;

    return true;
}

BOOST_AUTO_TEST_CASE(get_coin_no_coin)
{
    CAmount require(0);
    require += sigma::ZQ_LOVELACE;

    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins) == 0,
      "Expect enough coin and equal to one for each denomination with more ZQ_LOVELACE");

    std::vector<std::pair<sigma::CoinDenominationV3,int>> needCoins;

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(needCoins, coins),
      "Expect one for each denomination with onemore ZQ_LOVELACE");
}

BOOST_AUTO_TEST_CASE(get_coin_different_denomination)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;

    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_LOVELACE,2));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_GOLDWASSER,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_RACKOFF,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_PEDERSEN,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_WILLIAMSON,1));
    GenerateWalletCoin(newCoins);

    CAmount require(0);
    require += sigma::ZQ_LOVELACE * 2;
    require += sigma::ZQ_GOLDWASSER;
    require += sigma::ZQ_RACKOFF;
    require += sigma::ZQ_PEDERSEN;
    require += sigma::ZQ_WILLIAMSON;
	require *= COIN;

    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins) == require,
      "Expect enough coin and equal to one for each denomination with more ZQ_LOVELACE");

    std::vector<std::pair<sigma::CoinDenominationV3, int>> needCoins;
    needCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(ZQ_LOVELACE,2));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(ZQ_GOLDWASSER,1));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(ZQ_RACKOFF,1));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(ZQ_PEDERSEN,1));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(ZQ_WILLIAMSON,1));

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(needCoins, coins),
      "Expect one for each denomination with onemore ZQ_LOVELACE");
}

BOOST_AUTO_TEST_CASE(get_coin_not_enough)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_LOVELACE,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_GOLDWASSER,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_RACKOFF,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_PEDERSEN,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_WILLIAMSON,1));
    GenerateWalletCoin(newCoins);

    CAmount require(0);
    require += sigma::ZQ_LOVELACE * 2;
    require += sigma::ZQ_GOLDWASSER;
    require += sigma::ZQ_RACKOFF;
    require += sigma::ZQ_PEDERSEN;
    require += sigma::ZQ_WILLIAMSON;
	require *= COIN;
    
    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require,coins) == require-sigma::ZQ_LOVELACE*COIN,
      "Expect not enough coin and equal to one for each denomination");

    std::vector<std::pair<sigma::CoinDenominationV3, int>> needCoins;
    needCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(ZQ_LOVELACE,1));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(ZQ_GOLDWASSER,1));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(ZQ_RACKOFF,1));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(ZQ_PEDERSEN,1));
    needCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(ZQ_WILLIAMSON,1));

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(needCoins, coins),
      "Expect one for each denomination");
}

BOOST_AUTO_TEST_CASE(get_coin_minimize_coins_spend_fit_amount)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_PEDERSEN,2));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_WILLIAMSON,1));
    GenerateWalletCoin(newCoins);

    CAmount require(0);
    require += sigma::ZQ_WILLIAMSON;
	require *= COIN;
    
    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require,coins) == sigma::ZQ_WILLIAMSON*COIN,
      "Expect enough coin and equal to one ZQ_WILLIAMSON");

    std::vector<std::pair<sigma::CoinDenominationV3, int>> needCoins;
    needCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(ZQ_WILLIAMSON,1));

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(needCoins, coins),
      "Expect only one ZQ_WALLIAMSON");
}

BOOST_AUTO_TEST_CASE(get_coin_minimize_coins_spend)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_RACKOFF,2));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_WILLIAMSON,1));
    GenerateWalletCoin(newCoins);

    CAmount require(0);
    require += sigma::ZQ_PEDERSEN;
	require *= COIN;
    
    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins) == sigma::ZQ_WILLIAMSON*COIN,
      "Expect enough coin and equal one ZQ_WILLIAMSON");

    std::vector<std::pair<sigma::CoinDenominationV3, int>> needCoins;
    needCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(ZQ_WILLIAMSON,1));

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(needCoins, coins),
      "Expect only one ZQ_WALLIAMSON");;
}

BOOST_AUTO_TEST_CASE(get_coin_choose_smallest_enough)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_WILLIAMSON,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_PEDERSEN,1));
    newCoins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::ZQ_RACKOFF,1));
    GenerateWalletCoin(newCoins);

    CAmount require(0);
    require += sigma::ZQ_GOLDWASSER;
	require *= COIN;
    
    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require,coins) == sigma::ZQ_RACKOFF * COIN,
      "Expect enough coin and equal one ZQ_RACKOFF");

    std::vector<std::pair<sigma::CoinDenominationV3,int>> needCoins;
    needCoins.push_back(std::pair<sigma::CoinDenominationV3,int>(ZQ_RACKOFF,1));

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(needCoins, coins),
      "Expect only one ZQ_RACKOFF");
}

BOOST_AUTO_TEST_SUITE_END()
