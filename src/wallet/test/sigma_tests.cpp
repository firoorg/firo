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

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(wallet_sigma_tests, WalletTestingSetup)

static bool AddSigmaCoin(const sigma::PrivateCoinV3& coin, const sigma::CoinDenominationV3 denomination)
{
    sigma::PublicCoinV3 pubCoin(coin.getPublicCoin());

    CZerocoinEntryV3 zerocoinTx;
    zerocoinTx.IsUsed = false;
    zerocoinTx.set_denomination(denomination);
    zerocoinTx.value = pubCoin.getValue();
    zerocoinTx.randomness = coin.getRandomness();
    zerocoinTx.serialNumber = coin.getSerialNumber();

    return CWalletDB(pwalletMain->strWalletFile).WriteZerocoinEntry(zerocoinTx);
}

static bool GenerateWalletCoin(const std::vector<std::pair<sigma::CoinDenominationV3, int>>& coins)
{
    auto params = sigma::ParamsV3::get_default();

    for (auto& coin : coins) {
        for (int i = 0; i < coin.second; i++) {
            sigma::PrivateCoinV3 privCoin(params, coin.first);
            AddSigmaCoin(privCoin, coin.first);
        }
    }

    return true;
}

static bool CheckDenominationCoins(const std::vector<std::pair<sigma::CoinDenominationV3, int>>& need, const std::vector<CZerocoinEntryV3>& gots)
{
    // flatter need
    std::vector<sigma::CoinDenominationV3> needDenominations;

    for (auto& denominationNeed : need) {
        for (int i = 0; i < denominationNeed.second; i++) {
            needDenominations.push_back(denominationNeed.first);
        }
    }

    // got denominations set for `got` vector
    std::vector<sigma::CoinDenominationV3> gotDenominations;
    for (auto& got : gots) {
        gotDenominations.push_back(got.get_denomination());
    }

    // miss coin number
    if (needDenominations.size() != gotDenominations.size())
        return false;

    std::sort(needDenominations.begin(), needDenominations.end());
    std::sort(gotDenominations.begin(), gotDenominations.end());

    // denominations must be match
    for (int i = 0; i < needDenominations.size(); i++) {
        if (needDenominations[i] != gotDenominations[i]) {
            return false;
        }
    }

    return true;
}

static CAmount GetCoinSetByDenominationAmount(
    std::vector<std::pair<sigma::CoinDenominationV3, int>>& coins,
    int D01 = 0,
    int D05 = 0,
    int D1 = 0,
    int D10 = 0,
    int D100 = 0)
{
    coins.clear();

    coins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::CoinDenominationV3::SIGMA_DENOM_0_1, D01));
    coins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::CoinDenominationV3::SIGMA_DENOM_0_5, D05));
    coins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::CoinDenominationV3::SIGMA_DENOM_1, D1));
    coins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::CoinDenominationV3::SIGMA_DENOM_10, D10));
    coins.push_back(std::pair<sigma::CoinDenominationV3, int>(sigma::CoinDenominationV3::SIGMA_DENOM_100, D100));

    CAmount sum(0);
    for (auto& coin : coins) {
        CAmount r;
        sigma::DenominationToInteger(coin.first, r);
        sum += r * coin.second;
    }

    return sum;
}

BOOST_AUTO_TEST_CASE(get_coin_no_coin)
{
    CAmount require = COIN / 10;

    std::vector<CZerocoinEntryV3> coins;
    std::vector<sigma::CoinDenominationV3> coinsToMint;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins, coinsToMint) == 0,
      "Expect no coin in group");

    std::vector<std::pair<sigma::CoinDenominationV3, int>> needCoins;

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(needCoins, coins),
      "Expect no coin in group");
}

BOOST_AUTO_TEST_CASE(get_coin_different_denomination)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    GetCoinSetByDenominationAmount(newCoins, 2, 1, 1, 1, 1);
    GenerateWalletCoin(newCoins);

    CAmount require(111 * COIN + 7 * COIN / 10); // 111.7

    std::vector<CZerocoinEntryV3> coins;
    std::vector<sigma::CoinDenominationV3> coinsToMint;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins, coinsToMint),
      "Expect enough for requirement");

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(newCoins, coins),
      "Expect one for each denomination with onemore SIGMA_DENOM_0_1");
}

BOOST_AUTO_TEST_CASE(get_coin_not_enough)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    CAmount have = GetCoinSetByDenominationAmount(newCoins, 1, 1, 1, 1, 1);
    GenerateWalletCoin(newCoins);

    CAmount require(111 * COIN + 7 * COIN / 10); // 111.7

    std::vector<CZerocoinEntryV3> coins;
    std::vector<sigma::CoinDenominationV3> coinsToMint;
    BOOST_CHECK_MESSAGE(!pwalletMain->GetCoinsToSpend(require, coins, coinsToMint),
        "Expect not enough coin and equal to one for each denomination");
}

BOOST_AUTO_TEST_CASE(get_coin_minimize_coins_spend_fit_amount)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    GetCoinSetByDenominationAmount(newCoins, 0, 0, 0, 10, 1);
    GenerateWalletCoin(newCoins);

    CAmount require(100 * COIN);

    std::vector<CZerocoinEntryV3> coins;
    std::vector<sigma::CoinDenominationV3> coinsToMint;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins,coinsToMint),
      "Expect enough coin and equal to one SIGMA_DENOM_100");

    std::vector<std::pair<sigma::CoinDenominationV3, int>> expectedCoins;
    GetCoinSetByDenominationAmount(expectedCoins, 0, 0, 0, 0, 1);

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(expectedCoins, coins),
      "Expect only one SIGMA_DENOM_100");
}

BOOST_AUTO_TEST_CASE(get_coin_minimize_coins_spend)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    GetCoinSetByDenominationAmount(newCoins, 1, 0, 7, 1, 1);
    GenerateWalletCoin(newCoins);

    CAmount require(17 * COIN);

    std::vector<CZerocoinEntryV3> coins;
    std::vector<sigma::CoinDenominationV3> coinsToMint;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins, coinsToMint),
      "Coins to spend value is not equal to required amount.");

    std::vector<std::pair<sigma::CoinDenominationV3, int>> expectedCoins;
    GetCoinSetByDenominationAmount(expectedCoins, 0, 0, 7, 1, 0);

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(expectedCoins, coins),
      "Expect only one SIGMA_DENOM_10 and 7 SIGMA_DENOM_1");
}

BOOST_AUTO_TEST_CASE(get_coin_choose_smallest_enough)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    GetCoinSetByDenominationAmount(newCoins, 1, 1, 1, 1, 1);
    GenerateWalletCoin(newCoins);

    CAmount require(9 * COIN / 10); // 0.9

    std::vector<CZerocoinEntryV3> coins;
    std::vector<sigma::CoinDenominationV3> coinsToMint;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins,coinsToMint),
      "Expect enough coin and equal one SIGMA_DENOM_1");

    std::vector<std::pair<sigma::CoinDenominationV3, int>> expectedCoins;
    GetCoinSetByDenominationAmount(expectedCoins, 0, 0, 1, 0, 0);

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(expectedCoins, coins),
      "Expect only one SIGMA_DENOM_1");
}

BOOST_AUTO_TEST_SUITE_END()
