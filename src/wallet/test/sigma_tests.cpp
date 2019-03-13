// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../wallet.h"

#include "../../libzerocoin/sigma/CoinSpend.h"
#include "../../main.h"
#include "../../random.h"

#include <set>
#include <stdint.h>
#include <utility>
#include <vector>
#include <exception>
#include <algorithm>
#include <list>
#include <numeric>

#include "wallet_test_fixture.h"
#include "../../zerocoin_v3.h"

#include <boost/test/unit_test.hpp>

static const CBitcoinAddress randomAddr1("aBydwLXzmGc7j4mr4CVf461NvBjBFk71U1");
static const CBitcoinAddress randomAddr2("aLTSv7QbTZbkgorYEhbNx2gH4hGYNLsoGv");
static const CBitcoinAddress randomAddr3("a6r15E8Q9gqgWZSLLxZRQs4CWNkaaP5Y5b");

static std::list<std::pair<uint256, CBlockIndex>> blocks;

struct WalletSigmaTestingSetup : WalletTestingSetup
{
    ~WalletSigmaTestingSetup()
    {
        blocks.clear();
    }
};

static void AddSigmaCoin(const sigma::PrivateCoinV3& coin, const sigma::CoinDenominationV3 denomination)
{
    CZerocoinEntryV3 zerocoinTx;

    zerocoinTx.IsUsed = false;
    zerocoinTx.set_denomination(denomination);
    zerocoinTx.value = coin.getPublicCoin().getValue();
    zerocoinTx.randomness = coin.getRandomness();
    zerocoinTx.serialNumber = coin.getSerialNumber();
    zerocoinTx.ecdsaSecretKey.resize(32);

    std::copy_n(coin.getEcdsaSeckey(), 32, zerocoinTx.ecdsaSecretKey.begin());

    if (!CWalletDB(pwalletMain->strWalletFile).WriteZerocoinEntry(zerocoinTx)) {
        throw std::runtime_error("Failed to add zerocoin to wallet");
    }
}

static void GenerateBlockWithCoins(const std::vector<std::pair<sigma::CoinDenominationV3, int>>& coins)
{
    auto params = sigma::ParamsV3::get_default();
    auto state = CZerocoinStateV3::GetZerocoinState();
    auto block = blocks.emplace(blocks.end());

    // setup block
    block->first = GetRandHash();
    block->second.phashBlock = &block->first;
    block->second.pprev = chainActive.Tip();
    block->second.nHeight = block->second.pprev->nHeight + 1;

    // generate coins
    for (auto& coin : coins) {
        for (int i = 0; i < coin.second; i++) {
            sigma::PrivateCoinV3 priv(params, coin.first);
            auto& pub = priv.getPublicCoin();

            block->second.mintedPubCoinsV3[std::make_pair(coin.first, 1)].push_back(pub);

            AddSigmaCoin(priv, coin.first);
        }
    }

    // add block
    state->AddBlock(&block->second);
    chainActive.SetTip(&block->second);
}

static bool CheckDenominationCoins(
        const std::vector<std::pair<sigma::CoinDenominationV3, int>>& expected,
        std::vector<sigma::CoinDenominationV3> actualDenominations)
{
    // Flatten expected.
    std::vector<sigma::CoinDenominationV3> expectedDenominations;

    for (auto& denominationExpected : expected) {
        for (int i = 0; i < denominationExpected.second; i++) {
            expectedDenominations.push_back(denominationExpected.first);
        }
    }

    // Number of coins does not match.
    if (expectedDenominations.size() != actualDenominations.size())
        return false;

    std::sort(expectedDenominations.begin(), expectedDenominations.end());
    std::sort(actualDenominations.begin(), actualDenominations.end());

    // Denominations must match.
    return expectedDenominations == actualDenominations;
}

static bool CheckDenominationCoins(
        const std::vector<std::pair<sigma::CoinDenominationV3, int>>& expected,
        const std::vector<CZerocoinEntryV3>& actual)
{
    // Flatten expected.
    std::vector<sigma::CoinDenominationV3> expectedDenominations;

    for (auto& denominationExpected : expected) {
        for (int i = 0; i < denominationExpected.second; i++) {
            expectedDenominations.push_back(denominationExpected.first);
        }
    }

    // Get denominations set for `actual` vector
    std::vector<sigma::CoinDenominationV3> actualDenominations;
    for (auto& entry : actual) {
        actualDenominations.push_back(entry.get_denomination());
    }

    // Number of coins does not match.
    if (expectedDenominations.size() != actualDenominations.size())
        return false;

    std::sort(expectedDenominations.begin(), expectedDenominations.end());
    std::sort(actualDenominations.begin(), actualDenominations.end());

    // Denominations must match.
    return expectedDenominations == actualDenominations;
}

static bool CheckSpend(const CTxIn& vin, const CZerocoinEntryV3& expected)
{
    // check vin properties
    if (!vin.IsZerocoinSpendV3()) {
        return false;
    }

    if (vin.nSequence != 1) {
        return false;
    }

    if (!vin.prevout.IsNull()) {
        return false;
    }

    // check spend script
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized.write(reinterpret_cast<const char *>(&vin.scriptSig[1]), vin.scriptSig.size() - 1);

    sigma::CoinSpendV3 spend(sigma::ParamsV3::get_default(), serialized);

    if (!spend.HasValidSerial() || spend.getCoinSerialNumber() != expected.serialNumber) {
        return false;
    }

    if (spend.getDenomination() != expected.get_denomination()) {
        return false;
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

static bool ContainTxOut(const std::vector<CTxOut>& outs, const std::pair<const CScript&, const CAmount&>& expected, int expectedOccurrence = -1) {

    const auto occurrence = std::count_if(outs.begin(), outs.end(),
        [&expected](const CTxOut& txout) {
            return expected.first == txout.scriptPubKey && expected.second == txout.nValue;
        });

    // occurrence less than zero mean outs contain at least one expected
    return (expectedOccurrence < 0 && occurrence > 0) || (occurrence == expectedOccurrence);
}

BOOST_FIXTURE_TEST_SUITE(wallet_sigma_tests, WalletSigmaTestingSetup)

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
    GenerateBlockWithCoins(newCoins);

    CAmount require(111 * COIN + 7 * COIN / 10); // 111.7

    std::vector<CZerocoinEntryV3> coins;
    std::vector<sigma::CoinDenominationV3> coinsToMint;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins, coinsToMint),
      "Expect enough for requirement");

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(newCoins, coins),
      "Expect one for each denomination with onemore SIGMA_DENOM_0_1");
}

BOOST_AUTO_TEST_CASE(get_coin_round_up)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    GetCoinSetByDenominationAmount(newCoins, 5, 5, 5, 5, 5);
    GenerateBlockWithCoins(newCoins);

    // This must get rounded up to 111.8
    CAmount require(111 * COIN + 7 * COIN / 10 + 5 * COIN / 100); // 111.75

    std::vector<CZerocoinEntryV3> coinsToSpend;
    std::vector<sigma::CoinDenominationV3> coinsToMint;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coinsToSpend, coinsToMint),
      "Expect enough for requirement");

    // We would expect to spend 100 + 10 + 1 + 1 and re-mint 0.1 + 0.1.
    std::vector<std::pair<sigma::CoinDenominationV3, int>> expectedToSpend;
    GetCoinSetByDenominationAmount(expectedToSpend, 0, 0, 2, 1, 1);

    std::vector<std::pair<sigma::CoinDenominationV3, int>> expectedToMint;
    GetCoinSetByDenominationAmount(expectedToMint, 2, 0, 0, 0, 0);

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(expectedToSpend, coinsToSpend),
      "Expected to get coins to spend with denominations 100 + 10 + 1 + 1.");

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(expectedToMint, coinsToMint),
      "Expected to re-mint coins with denominations 0.1 + 0.1.");
}

BOOST_AUTO_TEST_CASE(get_coin_not_enough)
{
    std::vector<std::pair<sigma::CoinDenominationV3, int>> newCoins;
    GetCoinSetByDenominationAmount(newCoins, 1, 1, 1, 1, 1);
    GenerateBlockWithCoins(newCoins);

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
    GenerateBlockWithCoins(newCoins);

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
    GenerateBlockWithCoins(newCoins);

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
    GenerateBlockWithCoins(newCoins);

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

BOOST_AUTO_TEST_CASE(create_spend_with_empty_recipients)
{
    CAmount fee;
    std::vector<CZerocoinEntryV3> selected;
    std::vector<CZerocoinEntryV3> changes;

    BOOST_CHECK_EXCEPTION(
        pwalletMain->CreateZerocoinSpendTransactionV3({}, fee, selected, changes),
        std::invalid_argument,
        [](const std::invalid_argument& e) { return e.what() == std::string("No recipients"); });
}

BOOST_AUTO_TEST_CASE(create_spend_with_some_recipients_have_negative_amount)
{
    CAmount fee;
    std::vector<CZerocoinEntryV3> selected;
    std::vector<CZerocoinEntryV3> changes;
    std::vector<CRecipient> recipients;

    recipients.push_back(CRecipient{
        .scriptPubKey = GetScriptForDestination(randomAddr1.Get()),
        .nAmount = -1,
        .fSubtractFeeFromAmount = false
    });

    BOOST_CHECK_EXCEPTION(
        pwalletMain->CreateZerocoinSpendTransactionV3(recipients, fee, selected, changes),
        std::invalid_argument,
        [](const std::invalid_argument& e) { return e.what() == std::string("Recipient 0 has negative amount"); });
}

BOOST_AUTO_TEST_CASE(create_spend_with_insufficient_coins)
{
    CAmount fee;
    CWalletTx tx;
    std::vector<CZerocoinEntryV3> selected;
    std::vector<CZerocoinEntryV3> changes;
    std::vector<CRecipient> recipients;

    GenerateBlockWithCoins({ std::make_pair(sigma::CoinDenominationV3::SIGMA_DENOM_10, 1) });

    recipients.push_back(CRecipient{
        .scriptPubKey = GetScriptForDestination(randomAddr1.Get()),
        .nAmount = 5 * COIN,
        .fSubtractFeeFromAmount = false
    });

    recipients.push_back(CRecipient{
        .scriptPubKey = GetScriptForDestination(randomAddr2.Get()),
        .nAmount = 5 * COIN,
        .fSubtractFeeFromAmount = false
    });

    recipients.push_back(CRecipient{
        .scriptPubKey = GetScriptForDestination(randomAddr3.Get()),
        .nAmount = 1 * COIN,
        .fSubtractFeeFromAmount = false
    });

    BOOST_CHECK_EXCEPTION(
        pwalletMain->CreateZerocoinSpendTransactionV3(recipients, fee, selected, changes),
        std::runtime_error,
        [](const std::runtime_error& e) { return e.what() == std::string("Insufficient funds"); });
}

BOOST_AUTO_TEST_CASE(create_spend_with_confirmation_less_than_6)
{
    CAmount fee;
    std::vector<CZerocoinEntryV3> selected;
    std::vector<CZerocoinEntryV3> changes;
    std::vector<CRecipient> recipients;

    GenerateBlockWithCoins({ std::make_pair(sigma::CoinDenominationV3::SIGMA_DENOM_10, 2) });

    recipients.push_back(CRecipient{
        .scriptPubKey = GetScriptForDestination(randomAddr1.Get()),
        .nAmount = 5 * COIN,
        .fSubtractFeeFromAmount = false
    });

    recipients.push_back(CRecipient{
        .scriptPubKey = GetScriptForDestination(randomAddr2.Get()),
        .nAmount = 5 * COIN,
        .fSubtractFeeFromAmount = false
    });

    recipients.push_back(CRecipient{
        .scriptPubKey = GetScriptForDestination(randomAddr3.Get()),
        .nAmount = 1 * COIN,
        .fSubtractFeeFromAmount = false
    });

    BOOST_CHECK_EXCEPTION(
        pwalletMain->CreateZerocoinSpendTransactionV3(recipients, fee, selected, changes),
        std::runtime_error,
        [](const std::runtime_error& e) { return e.what() == std::string("Has to have at least two mint coins with at least 6 confirmation in order to spend a coin"); });
}

BOOST_AUTO_TEST_CASE(create_spend_with_coins_less_than_2)
{
    CAmount fee;
    std::vector<CZerocoinEntryV3> selected;
    std::vector<CZerocoinEntryV3> changes;
    std::vector<CRecipient> recipients;

    GenerateBlockWithCoins({ std::make_pair(sigma::CoinDenominationV3::SIGMA_DENOM_10, 1) });
    GenerateBlockWithCoins({});
    GenerateBlockWithCoins({});
    GenerateBlockWithCoins({});
    GenerateBlockWithCoins({});
    GenerateBlockWithCoins({});

    recipients.push_back(CRecipient{
        .scriptPubKey = GetScriptForDestination(randomAddr1.Get()),
        .nAmount = 5 * COIN,
        .fSubtractFeeFromAmount = false
    });

    BOOST_CHECK_EXCEPTION(
        pwalletMain->CreateZerocoinSpendTransactionV3(recipients, fee, selected, changes),
        std::runtime_error,
        [](const std::runtime_error& e) { return e.what() == std::string("Has to have at least two mint coins with at least 6 confirmation in order to spend a coin"); });
}

BOOST_AUTO_TEST_CASE(create_spend_with_coins_more_than_1)
{
    CAmount fee;
    std::vector<CZerocoinEntryV3> selected;
    std::vector<CZerocoinEntryV3> changes;
    std::vector<CRecipient> recipients;

    GenerateBlockWithCoins({ std::make_pair(sigma::CoinDenominationV3::SIGMA_DENOM_10, 2) });
    GenerateBlockWithCoins({});
    GenerateBlockWithCoins({});
    GenerateBlockWithCoins({});
    GenerateBlockWithCoins({});
    GenerateBlockWithCoins({});

    recipients.push_back(CRecipient{
        .scriptPubKey = GetScriptForDestination(randomAddr1.Get()),
        .nAmount = 5 * COIN,
        .fSubtractFeeFromAmount = false
    });

    recipients.push_back(CRecipient{
        .scriptPubKey = GetScriptForDestination(randomAddr2.Get()),
        .nAmount = 10 * COIN,
        .fSubtractFeeFromAmount = false
    });

    CWalletTx tx = pwalletMain->CreateZerocoinSpendTransactionV3(recipients, fee, selected, changes);

    BOOST_CHECK(tx.vin.size() == 2);

    // 2 outputs to recipients 5 + 10 xzc
    // 9 mints as changes, 1 * 4 + 0.5 * 1 + 0.1 * 4 xzc
    BOOST_CHECK(tx.vout.size() == 11);
    BOOST_CHECK(fee > 0);

    BOOST_CHECK(selected.size() == 2);
    BOOST_CHECK(selected[0].get_denomination() == sigma::CoinDenominationV3::SIGMA_DENOM_10);
    BOOST_CHECK(selected[1].get_denomination() == sigma::CoinDenominationV3::SIGMA_DENOM_10);

    BOOST_CHECK(CheckSpend(tx.vin[0], selected[0]));
    BOOST_CHECK(CheckSpend(tx.vin[1], selected[1]));

    BOOST_CHECK(ContainTxOut(tx.vout,
        make_pair(GetScriptForDestination(randomAddr1.Get()), 5 * COIN ), 1));
    BOOST_CHECK(ContainTxOut(tx.vout,
        make_pair(GetScriptForDestination(randomAddr2.Get()), 10 * COIN ), 1));

    CAmount remintsSum = std::accumulate(tx.vout.begin(), tx.vout.end(), 0, [](CAmount c, const CTxOut& v) {
        return c + (v.scriptPubKey.IsZerocoinMintV3() ? v.nValue : 0);
    });

    BOOST_CHECK(remintsSum == 49 * COIN / 10);

    // check walletdb
    std::list<CZerocoinEntryV3> coinList;
    std::list<CZerocoinSpendEntryV3> spends;
    CWalletDB db(pwalletMain->strWalletFile);

    db.ListPubCoinV3(coinList);
    BOOST_CHECK(coinList.size() == 2);

    db.ListCoinSpendSerial(spends);
    BOOST_CHECK(spends.empty());

    pwalletMain->SpendZerocoinV3(recipients, tx, fee);

    coinList.clear();
    db.ListPubCoinV3(coinList);
    BOOST_CHECK(coinList.size() == 11);
    BOOST_CHECK(std::count_if(coinList.begin(), coinList.end(),
        [](const CZerocoinEntryV3& coin){return !coin.IsUsed;}) == 9);

    spends.clear();
    db.ListCoinSpendSerial(spends);
    BOOST_CHECK(spends.size() == 2);
}

BOOST_AUTO_TEST_CASE(spend)
{
    CWalletTx tx;
    CAmount fee;
    std::vector<CRecipient> recipients;

    GenerateBlockWithCoins({ std::make_pair(sigma::CoinDenominationV3::SIGMA_DENOM_10, 2) });
    GenerateBlockWithCoins({});
    GenerateBlockWithCoins({});
    GenerateBlockWithCoins({});
    GenerateBlockWithCoins({});
    GenerateBlockWithCoins({});

    recipients.push_back(CRecipient{
        .scriptPubKey = GetScriptForDestination(randomAddr1.Get()),
        .nAmount = 5 * COIN,
        .fSubtractFeeFromAmount = false
    });

    auto selected = pwalletMain->SpendZerocoinV3(recipients, tx, fee);

    CWalletDB db(pwalletMain->strWalletFile);

    std::list<CZerocoinSpendEntryV3> spends;
    db.ListCoinSpendSerial(spends);

    std::list<CZerocoinEntryV3> coins;
    db.ListPubCoinV3(coins);

    BOOST_CHECK(selected.size() == 1);
    BOOST_CHECK(selected[0].get_denomination() == sigma::CoinDenominationV3::SIGMA_DENOM_10);
    BOOST_CHECK(selected[0].id == 1);
    BOOST_CHECK(selected[0].IsUsed);
    BOOST_CHECK(selected[0].nHeight == 1);

    BOOST_CHECK(spends.size() == 1);
    BOOST_CHECK(spends.front().coinSerial == selected[0].serialNumber);
    BOOST_CHECK((spends.front().hashTx == tx.GetHash()));
    BOOST_CHECK(spends.front().pubCoin == selected[0].value);
    BOOST_CHECK(spends.front().id == selected[0].id);
    BOOST_CHECK(spends.front().get_denomination() == selected[0].get_denomination());

    for (auto& coin : coins) {
        if (std::find_if(
            selected.begin(),
            selected.end(),
            [&coin](const CZerocoinEntryV3& e) { return e.serialNumber == coin.serialNumber; }) != selected.end()) {
            continue;
        }

        BOOST_CHECK(coin.IsUsed == false);
        BOOST_CHECK(coin.id == -1);
        BOOST_CHECK(coin.nHeight == -1);
    }
}

BOOST_AUTO_TEST_SUITE_END()
