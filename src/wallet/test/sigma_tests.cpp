// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../wallet.h"
#include "../walletexcept.h"

#include "../../main.h"

#include <set>
#include <stdint.h>
#include <utility>
#include <vector>
#include <exception>
#include <algorithm>

#include "wallet_test_fixture.h"
#include "../../zerocoin_v3.h"

#include <boost/test/unit_test.hpp>

static const CBitcoinAddress randomAddr1("aBydwLXzmGc7j4mr4CVf461NvBjBFk71U1");
static const CBitcoinAddress randomAddr2("aLTSv7QbTZbkgorYEhbNx2gH4hGYNLsoGv");
static const CBitcoinAddress randomAddr3("a6r15E8Q9gqgWZSLLxZRQs4CWNkaaP5Y5b");

struct WalletSigmaTestingSetup : WalletTestingSetup
{
    ~WalletSigmaTestingSetup()
    {
        auto block = chainActive.Tip();

        while (block && block != chainActive.Genesis()) {
            auto current = block;
            block = block->pprev;

            delete current->phashBlock;
            delete current;
        }
    }
};

BOOST_FIXTURE_TEST_SUITE(wallet_sigma_tests, WalletSigmaTestingSetup)

static void AddSigmaCoin(const sigma::PrivateCoinV3& coin, const sigma::CoinDenominationV3 denomination)
{
    sigma::PublicCoinV3 pubCoin(coin.getPublicCoin());

    CZerocoinEntryV3 zerocoinTx;
    zerocoinTx.IsUsed = false;
    zerocoinTx.set_denomination(denomination);
    zerocoinTx.value = pubCoin.getValue();
    zerocoinTx.randomness = coin.getRandomness();
    zerocoinTx.serialNumber = coin.getSerialNumber();

    if (!CWalletDB(pwalletMain->strWalletFile).WriteZerocoinEntry(zerocoinTx)) {
        throw std::runtime_error("failed to update zerocoin entry");
    }
}

static void GenerateBlockWithCoins(const uint256& hash, const std::vector<std::pair<sigma::CoinDenominationV3, int>>& coins)
{
    auto params = sigma::ParamsV3::get_default();
    auto state = CZerocoinStateV3::GetZerocoinState();
    auto block = std::unique_ptr<CBlockIndex>(new CBlockIndex());
    auto h = std::unique_ptr<uint256>(new uint256(hash));

    // setup block
    block->pprev = chainActive.Tip();
    block->phashBlock = h.get();
    block->nHeight = block->pprev->nHeight + 1;

    // generate coins
    for (auto& coin : coins) {
        for (int i = 0; i < coin.second; i++) {
            sigma::PrivateCoinV3 priv(params, coin.first);
            auto& pub = priv.getPublicCoin();

            block->mintedPubCoinsV3[std::make_pair(coin.first, 1)].push_back(pub);
            state->AddBlock(block.get());

            AddSigmaCoin(priv, coin.first);
        }
    }

    // add block
    auto ptr = block.release();

    try {
        chainActive.SetTip(ptr);
        h.release();
    } catch (...) {
        delete ptr;
        throw;
    }
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
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins) == 0,
      "Expect no coin in group");

    std::vector<std::pair<sigma::CoinDenominationV3, int>> needCoins;

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(needCoins, coins),
      "Expect no coin in group");
}

BOOST_AUTO_TEST_CASE(get_coin_different_denomination)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    GetCoinSetByDenominationAmount(newCoins, 2, 1, 1, 1, 1);
    GenerateBlockWithCoins(uint256S("c0c53331e3d96dbe4a20976196c0a214124bef9a7829df574f00f4e5a1b7ae52"), newCoins);

    CAmount require(111 * COIN + 7 * COIN / 10); // 111.7

    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins) == (111 * COIN + 7 * COIN / 10), // 111.7
      "Expect enough for requirement");

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(newCoins, coins),
      "Expect one for each denomination with onemore SIGMA_DENOM_0_1");
}

BOOST_AUTO_TEST_CASE(get_coin_not_enough)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    CAmount have = GetCoinSetByDenominationAmount(newCoins, 1, 1, 1, 1, 1);
    GenerateBlockWithCoins(uint256S("c0c53331e3d96dbe4a20976196c0a214124bef9a7829df574f00f4e5a1b7ae52"), newCoins);

    CAmount require(111 * COIN + 7 * COIN / 10); // 111.7

    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins) == (111 * COIN + 6 * COIN / 10), // 111.6
      "Expect not enough coin and equal to one for each denomination");

    std::vector<std::pair<sigma::CoinDenominationV3, int>> expectedCoins;
    GetCoinSetByDenominationAmount(expectedCoins, 1, 1, 1, 1, 1);

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(expectedCoins, coins),
      "Expect one for each denomination");
}

BOOST_AUTO_TEST_CASE(get_coin_minimize_coins_spend_fit_amount)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    GetCoinSetByDenominationAmount(newCoins, 0, 0, 0, 10, 1);
    GenerateBlockWithCoins(uint256S("c0c53331e3d96dbe4a20976196c0a214124bef9a7829df574f00f4e5a1b7ae52"), newCoins);

    CAmount require(100 * COIN);

    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins) == 100 * COIN,
      "Expect enough coin and equal to one SIGMA_DENOM_100");

    std::vector<std::pair<sigma::CoinDenominationV3, int>> expectedCoins;
    GetCoinSetByDenominationAmount(expectedCoins, 0, 0, 0, 0, 1);

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(expectedCoins, coins),
      "Expect only one SIGMA_DENOM_100");
}

BOOST_AUTO_TEST_CASE(get_coin_minimize_coins_spend)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    GetCoinSetByDenominationAmount(newCoins, 0, 0, 0, 2, 1);
    GenerateBlockWithCoins(uint256S("c0c53331e3d96dbe4a20976196c0a214124bef9a7829df574f00f4e5a1b7ae52"), newCoins);

    CAmount require(20 * COIN);

    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins) == 100 * COIN,
      "Expect enough coin and equal one SIGMA_DENOM_100");

    std::vector<std::pair<sigma::CoinDenominationV3, int>> expectedCoins;
    GetCoinSetByDenominationAmount(expectedCoins, 0, 0, 0, 0, 1);

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(expectedCoins, coins),
      "Expect only one SIGMA_DENOM_100");;
}

BOOST_AUTO_TEST_CASE(get_coin_choose_smallest_enough)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    GetCoinSetByDenominationAmount(newCoins, 1, 1, 1, 1, 1);
    GenerateBlockWithCoins(uint256S("c0c53331e3d96dbe4a20976196c0a214124bef9a7829df574f00f4e5a1b7ae52"), newCoins);

    CAmount require(9 * COIN / 10); // 0.9

    std::vector<CZerocoinEntryV3> coins;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins) == 1 * COIN,
      "Expect enough coin and equal one SIGMA_DENOM_1");

    std::vector<std::pair<sigma::CoinDenominationV3, int>> expectedCoins;
    GetCoinSetByDenominationAmount(expectedCoins, 0, 0, 1, 0, 0);

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(expectedCoins, coins),
      "Expect only one SIGMA_DENOM_1");
}

BOOST_AUTO_TEST_CASE(create_spend_with_empty_recipients)
{
    CAmount fee = 0;
    CWalletTx tx;
    std::vector<CZerocoinEntryV3> selected;

    BOOST_CHECK_EXCEPTION(
        pwalletMain->CreateZerocoinSpendTransactionV3({}, tx, fee, selected),
        std::invalid_argument,
        [](const std::invalid_argument& e) { return e.what() == std::string("Transaction amounts must be positive"); });
}

BOOST_AUTO_TEST_CASE(create_spend_with_some_recipients_have_negative_amount)
{
    CAmount fee = 0;
    CWalletTx tx;
    std::vector<CZerocoinEntryV3> selected;
    std::vector<CRecipient> recipients;

    recipients.push_back(CRecipient());
    recipients.back().scriptPubKey = GetScriptForDestination(randomAddr1.Get());
    recipients.back().nAmount = -1;
    recipients.back().fSubtractFeeFromAmount = false;

    BOOST_CHECK_EXCEPTION(
        pwalletMain->CreateZerocoinSpendTransactionV3(recipients, tx, fee, selected),
        std::invalid_argument,
        [](const std::invalid_argument& e) { return e.what() == std::string("Transaction amounts must be positive"); });
}

BOOST_AUTO_TEST_CASE(create_spend_with_insufficient_coins)
{
    CAmount fee = 0;
    CWalletTx tx;
    std::vector<CZerocoinEntryV3> selected;
    std::vector<CRecipient> recipients;

    GenerateBlockWithCoins(uint256S("c0c53331e3d96dbe4a20976196c0a214124bef9a7829df574f00f4e5a1b7ae52"), { std::make_pair(sigma::CoinDenominationV3::SIGMA_DENOM_10, 1) });

    recipients.push_back(CRecipient());
    recipients.back().scriptPubKey = GetScriptForDestination(randomAddr1.Get());
    recipients.back().nAmount = 5 * COIN;
    recipients.back().fSubtractFeeFromAmount = false;

    recipients.push_back(CRecipient());
    recipients.back().scriptPubKey = GetScriptForDestination(randomAddr2.Get());
    recipients.back().nAmount = 5 * COIN;
    recipients.back().fSubtractFeeFromAmount = false;

    recipients.push_back(CRecipient());
    recipients.back().scriptPubKey = GetScriptForDestination(randomAddr3.Get());
    recipients.back().nAmount = 1 * COIN;
    recipients.back().fSubtractFeeFromAmount = false;

    BOOST_CHECK_EXCEPTION(
        pwalletMain->CreateZerocoinSpendTransactionV3(recipients, tx, fee, selected),
        InsufficientFunds,
        [](const InsufficientFunds&) { return true; });
}

BOOST_AUTO_TEST_CASE(create_spend_with_confirmation_less_than_6)
{
    CAmount fee = 0;
    CWalletTx tx;
    std::vector<CZerocoinEntryV3> selected;
    std::vector<CRecipient> recipients;

    GenerateBlockWithCoins(uint256S("c0c53331e3d96dbe4a20976196c0a214124bef9a7829df574f00f4e5a1b7ae52"), { std::make_pair(sigma::CoinDenominationV3::SIGMA_DENOM_10, 2) });

    recipients.push_back(CRecipient());
    recipients.back().scriptPubKey = GetScriptForDestination(randomAddr1.Get());
    recipients.back().nAmount = 5 * COIN;
    recipients.back().fSubtractFeeFromAmount = false;

    recipients.push_back(CRecipient());
    recipients.back().scriptPubKey = GetScriptForDestination(randomAddr2.Get());
    recipients.back().nAmount = 5 * COIN;
    recipients.back().fSubtractFeeFromAmount = false;

    recipients.push_back(CRecipient());
    recipients.back().scriptPubKey = GetScriptForDestination(randomAddr3.Get());
    recipients.back().nAmount = 1 * COIN;
    recipients.back().fSubtractFeeFromAmount = false;

    BOOST_CHECK_EXCEPTION(
        pwalletMain->CreateZerocoinSpendTransactionV3(recipients, tx, fee, selected),
        WalletError,
        [](const WalletError& e) { return e.what() == std::string("it has to have at least two mint coins with at least 6 confirmation in order to spend a coin"); });
}

BOOST_AUTO_TEST_CASE(create_spend_with_coins_less_than_2)
{
    CAmount fee = 0;
    CWalletTx tx;
    std::vector<CZerocoinEntryV3> selected;
    std::vector<CRecipient> recipients;

    GenerateBlockWithCoins(uint256S("c0c53331e3d96dbe4a20976196c0a214124bef9a7829df574f00f4e5a1b7ae52"), { std::make_pair(sigma::CoinDenominationV3::SIGMA_DENOM_10, 1) });
    GenerateBlockWithCoins(uint256S("bdf3fe560c2a65f563111afa39247fc2584fc9315118f86a9c9e2f93f974bace"), {});
    GenerateBlockWithCoins(uint256S("2663970914b4e4617e68955147651758b0626c8cd27070d1a15a2b952bf88ae4"), {});
    GenerateBlockWithCoins(uint256S("3df15a7adf7567a58fa73bf5a95689522fc1e577f919761c49269da114db588c"), {});
    GenerateBlockWithCoins(uint256S("03c3ec77f27dc60fd7b195aa81291fbe3af120bac42be18cf4e5c42157d165f0"), {});
    GenerateBlockWithCoins(uint256S("9112757a6575496bc9c5887ef24aa3470d622a56bf72868729e05b2a327bf42c"), {});

    recipients.push_back(CRecipient());
    recipients.back().scriptPubKey = GetScriptForDestination(randomAddr1.Get());
    recipients.back().nAmount = 5 * COIN;
    recipients.back().fSubtractFeeFromAmount = false;

    BOOST_CHECK_EXCEPTION(
        pwalletMain->CreateZerocoinSpendTransactionV3(recipients, tx, fee, selected),
        WalletError,
        [](const WalletError& e) { return e.what() == std::string("it has to have at least two mint coins with at least 6 confirmation in order to spend a coin"); });
}

BOOST_AUTO_TEST_CASE(create_spend_with_coins_more_than_1)
{
    CAmount fee = 0;
    CWalletTx tx;
    std::vector<CZerocoinEntryV3> selected;
    std::vector<CRecipient> recipients;

    GenerateBlockWithCoins(uint256S("c0c53331e3d96dbe4a20976196c0a214124bef9a7829df574f00f4e5a1b7ae52"), { std::make_pair(sigma::CoinDenominationV3::SIGMA_DENOM_10, 2) });
    GenerateBlockWithCoins(uint256S("bdf3fe560c2a65f563111afa39247fc2584fc9315118f86a9c9e2f93f974bace"), {});
    GenerateBlockWithCoins(uint256S("2663970914b4e4617e68955147651758b0626c8cd27070d1a15a2b952bf88ae4"), {});
    GenerateBlockWithCoins(uint256S("3df15a7adf7567a58fa73bf5a95689522fc1e577f919761c49269da114db588c"), {});
    GenerateBlockWithCoins(uint256S("03c3ec77f27dc60fd7b195aa81291fbe3af120bac42be18cf4e5c42157d165f0"), {});
    GenerateBlockWithCoins(uint256S("9112757a6575496bc9c5887ef24aa3470d622a56bf72868729e05b2a327bf42c"), {});

    recipients.push_back(CRecipient());
    recipients.back().scriptPubKey = GetScriptForDestination(randomAddr1.Get());
    recipients.back().nAmount = 5 * COIN;
    recipients.back().fSubtractFeeFromAmount = false;

    recipients.push_back(CRecipient());
    recipients.back().scriptPubKey = GetScriptForDestination(randomAddr2.Get());
    recipients.back().nAmount = 10 * COIN;
    recipients.back().fSubtractFeeFromAmount = false;

    pwalletMain->CreateZerocoinSpendTransactionV3(recipients, tx, fee, selected);

    BOOST_TEST(tx.vin.size() == 2);
    BOOST_TEST(tx.vin[0].IsZerocoinSpendV3());
    BOOST_TEST(tx.vin[1].IsZerocoinSpendV3());
    BOOST_TEST(tx.vout.size() == 2);
    BOOST_TEST(tx.vout[0].nValue == 5 * COIN);
    BOOST_TEST(tx.vout[1].nValue == 10 * COIN);
    BOOST_TEST(selected.size() == 2);
    BOOST_TEST(selected[0].get_denomination() == sigma::CoinDenominationV3::SIGMA_DENOM_10);
    BOOST_TEST(selected[1].get_denomination() == sigma::CoinDenominationV3::SIGMA_DENOM_10);
}

BOOST_AUTO_TEST_SUITE_END()
