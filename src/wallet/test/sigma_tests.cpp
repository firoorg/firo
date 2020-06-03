// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../wallet.h"
#include "../walletexcept.h"

#include "../../sigma/coinspend.h"
#include "../../validation.h"
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
#include "../../sigma.h"

#include <boost/test/unit_test.hpp>

static const CBitcoinAddress randomAddr1("aBydwLXzmGc7j4mr4CVf461NvBjBFk71U1");
static const CBitcoinAddress randomAddr2("aLTSv7QbTZbkgorYEhbNx2gH4hGYNLsoGv");
static const CBitcoinAddress randomAddr3("a6r15E8Q9gqgWZSLLxZRQs4CWNkaaP5Y5b");

static std::list<std::pair<uint256, CBlockIndex>> blocks;

struct WalletSigmaTestingSetup : WalletTestingSetup
{
    WalletSigmaTestingSetup()
        : sigmaState(sigma::CSigmaState::GetState())
    {
    }

    ~WalletSigmaTestingSetup()
    {
        blocks.clear();
    }
    sigma::CSigmaState *sigmaState;
};

static void AddSigmaCoin(const sigma::PrivateCoin& coin, const sigma::CoinDenomination denomination)
{
    CSigmaEntry zerocoinTx;

    zerocoinTx.IsUsed = false;
    zerocoinTx.set_denomination(denomination);
    zerocoinTx.value = coin.getPublicCoin().getValue();
    zerocoinTx.randomness = coin.getRandomness();
    zerocoinTx.serialNumber = coin.getSerialNumber();
    zerocoinTx.ecdsaSecretKey.resize(32);

    std::copy_n(coin.getEcdsaSeckey(), 32, zerocoinTx.ecdsaSecretKey.begin());

    if (!CWalletDB(pwalletMain->strWalletFile).WriteSigmaEntry(zerocoinTx)) {
        throw std::runtime_error("Failed to add zerocoin to wallet");
    }
}


static void GenerateBlockWithCoins(const std::vector<std::pair<sigma::CoinDenomination, int>>& coins, bool addToWallet = true)
{
    auto params = sigma::Params::get_default();
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    auto block = blocks.emplace(blocks.end());

    // setup block
    block->first = GetRandHash();
    block->second.phashBlock = &block->first;
    block->second.pprev = chainActive.Tip();
    block->second.nHeight = block->second.pprev->nHeight + 1;

    // generate coins
    CWalletDB walletdb(pwalletMain->strWalletFile);
    CHDMint dMint;
    for (auto& coin : coins) {
        for (int i = 0; i < coin.second; i++) {
            sigma::PrivateCoin priv(params, coin.first);

            // Generate and store secrets deterministically in the following function.
            dMint.SetNull();
            pwalletMain->zwallet->GenerateMint(walletdb, priv.getPublicCoin().getDenomination(), priv, dMint, boost::none, true);

            auto& pub = priv.getPublicCoin();

            block->second.sigmaMintedPubCoins[std::make_pair(coin.first, 1)].push_back(pub);

            if (addToWallet) {
                pwalletMain->zwallet->GetTracker().Add(walletdb, dMint, true);
            }
        }
    }

    // add block
    sigmaState->AddBlock(&block->second);
    chainActive.SetTip(&block->second);
}

static void GenerateEmptyBlocks(int number_of_blocks)
{
    for (int i = 0; i < number_of_blocks; ++i) {
        GenerateBlockWithCoins({});
   }
}

static bool CheckDenominationCoins(
        const std::vector<std::pair<sigma::CoinDenomination, int>>& expected,
        std::vector<sigma::CoinDenomination> actualDenominations)
{
    // Flatten expected.
    std::vector<sigma::CoinDenomination> expectedDenominations;

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
        const std::vector<std::pair<sigma::CoinDenomination, int>>& expected,
        const std::vector<CSigmaEntry>& actual)
{
    // Flatten expected.
    std::vector<sigma::CoinDenomination> expectedDenominations;

    for (auto& denominationExpected : expected) {
        for (int i = 0; i < denominationExpected.second; i++) {
            expectedDenominations.push_back(denominationExpected.first);
        }
    }

    // Get denominations set for `actual` vector
    std::vector<sigma::CoinDenomination> actualDenominations;
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

static bool CheckSpend(const CTxIn& vin, const CSigmaEntry& expected)
{
    // check vin properties
    if (!vin.IsSigmaSpend()) {
        return false;
    }

    if (vin.nSequence != CTxIn::SEQUENCE_FINAL) {
        return false;
    }

    if (!vin.prevout.IsSigmaMintGroup()) {
        return false;
    }

    // check spend script
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized.write(reinterpret_cast<const char *>(&vin.scriptSig[1]), vin.scriptSig.size() - 1);

    sigma::CoinSpend spend(sigma::Params::get_default(), serialized);

    if (!spend.HasValidSerial() || spend.getCoinSerialNumber() != expected.serialNumber) {
        return false;
    }

    if (spend.getDenomination() != expected.get_denomination()) {
        return false;
    }

    return true;
}

static CAmount GetCoinSetByDenominationAmount(
    std::vector<std::pair<sigma::CoinDenomination, int>>& coins,
    int D005 = 0,
    int D01 = 0,
    int D05 = 0,
    int D1 = 0,
    int D10 = 0,
    int D25 = 0,
    int D100 = 0)
{
    coins.clear();

    coins.push_back(std::pair<sigma::CoinDenomination, int>(sigma::CoinDenomination::SIGMA_DENOM_0_05, D005));
    coins.push_back(std::pair<sigma::CoinDenomination, int>(sigma::CoinDenomination::SIGMA_DENOM_0_1, D01));
    coins.push_back(std::pair<sigma::CoinDenomination, int>(sigma::CoinDenomination::SIGMA_DENOM_0_5, D05));
    coins.push_back(std::pair<sigma::CoinDenomination, int>(sigma::CoinDenomination::SIGMA_DENOM_1, D1));
    coins.push_back(std::pair<sigma::CoinDenomination, int>(sigma::CoinDenomination::SIGMA_DENOM_10, D10));
    coins.push_back(std::pair<sigma::CoinDenomination, int>(sigma::CoinDenomination::SIGMA_DENOM_25, D25));
    coins.push_back(std::pair<sigma::CoinDenomination, int>(sigma::CoinDenomination::SIGMA_DENOM_100, D100));

    CAmount sum(0);
    for (auto& coin : coins) {
        CAmount r;
        sigma::DenominationToInteger(coin.first, r);
        sum += r * coin.second;
    }

    return sum;
}

static void AddOneCoinForEachGroup()
{
    std::vector<std::pair<sigma::CoinDenomination, int>> coins;
    GetCoinSetByDenominationAmount(coins, 1, 1, 1, 1, 1, 1, 1);
    GenerateBlockWithCoins(coins, false);
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

    std::vector<CSigmaEntry> coins;
    std::vector<sigma::CoinDenomination> coinsToMint;
    BOOST_CHECK_THROW(pwalletMain->GetCoinsToSpend(require, coins, coinsToMint), InsufficientFunds);

    std::vector<std::pair<sigma::CoinDenomination, int>> needCoins;

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(needCoins, coins),
      "Expect no coin in group");
    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(get_coin_different_denomination)
{
    std::vector<std::pair<sigma::CoinDenomination, int>> newCoins;
    AddOneCoinForEachGroup();
    GetCoinSetByDenominationAmount(newCoins, 1, 2, 1, 1, 1, 1, 1);
    GenerateBlockWithCoins(newCoins);
    GenerateEmptyBlocks(5);

    CAmount require(13675 * CENT); // 136.75

    std::vector<CSigmaEntry> coins;
    std::vector<sigma::CoinDenomination> coinsToMint;
    BOOST_CHECK_NO_THROW(pwalletMain->GetCoinsToSpend(require, coins, coinsToMint));
    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(get_coin_round_up)
{
    std::vector<std::pair<sigma::CoinDenomination, int>> newCoins;
    AddOneCoinForEachGroup();
    GetCoinSetByDenominationAmount(newCoins, 5, 5, 5, 5, 5, 5, 5);
    GenerateBlockWithCoins(newCoins);
    GenerateEmptyBlocks(5);

    // This must get rounded up to 111.65
    CAmount require(11164 * CENT); // 111.64

    std::vector<CSigmaEntry> coinsToSpend;
    std::vector<sigma::CoinDenomination> coinsToMint;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coinsToSpend, coinsToMint),
      "Expect enough for requirement");

    // We would expect to spend 100 + 10 + 1 + 0.5 + 0.1 + 0.05
    std::vector<std::pair<sigma::CoinDenomination, int>> expectedToSpend;
    GetCoinSetByDenominationAmount(expectedToSpend, 1, 1, 1, 1, 1, 0, 1);

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(expectedToSpend, coinsToSpend),
      "Expected to get coins to spend with denominations 100 + 10 + 1 + 0.5 + 0.1 + 0.05.");

    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(get_coin_not_enough)
{
    AddOneCoinForEachGroup();
    std::vector<std::pair<sigma::CoinDenomination, int>> newCoins;
    GetCoinSetByDenominationAmount(newCoins, 1, 1, 1, 1, 1, 1, 1);
    GenerateBlockWithCoins(newCoins);
    GenerateEmptyBlocks(5);

    CAmount require(13666 * CENT); // 136.66

    std::vector<CSigmaEntry> coins;
    std::vector<sigma::CoinDenomination> coinsToMint;
    BOOST_CHECK_THROW(pwalletMain->GetCoinsToSpend(require, coins, coinsToMint), InsufficientFunds);
    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(get_coin_cannot_spend_unconfirmed_coins)
{
    AddOneCoinForEachGroup();
    std::vector<std::pair<sigma::CoinDenomination, int>> newCoins;
    GetCoinSetByDenominationAmount(newCoins, 1, 1, 1, 1, 1, 1, 1);
    GenerateBlockWithCoins(newCoins);
    // Intentionally do not create 5 more blocks after this one, so coins can not be spent.
    // GenerateEmptyBlocks(5);

    CAmount require(11150 * CENT); // 111.5

    std::vector<CSigmaEntry> coins;
    std::vector<sigma::CoinDenomination> coinsToMint;
    BOOST_CHECK_THROW(pwalletMain->GetCoinsToSpend(require, coins, coinsToMint), InsufficientFunds);
    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(get_coin_minimize_coins_spend_fit_amount)
{
    std::vector<std::pair<sigma::CoinDenomination, int>> newCoins;
    AddOneCoinForEachGroup();
    GetCoinSetByDenominationAmount(newCoins, 0, 0, 0, 0, 10, 0, 1);
    GenerateBlockWithCoins(newCoins);
    GenerateEmptyBlocks(5);

    CAmount require(100 * COIN);

    std::vector<CSigmaEntry> coins;
    std::vector<sigma::CoinDenomination> coinsToMint;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins,coinsToMint),
      "Expect enough coin and equal to one SIGMA_DENOM_100");

    std::vector<std::pair<sigma::CoinDenomination, int>> expectedCoins;
    GetCoinSetByDenominationAmount(expectedCoins, 0, 0, 0, 0, 0, 0, 1);

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(expectedCoins, coins),
      "Expect only one SIGMA_DENOM_100");
    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(get_coin_minimize_coins_spend)
{
    std::vector<std::pair<sigma::CoinDenomination, int>> newCoins;
    AddOneCoinForEachGroup();
    GetCoinSetByDenominationAmount(newCoins, 0, 1, 0, 2, 1, 0, 1);
    GenerateBlockWithCoins(newCoins);
    GenerateEmptyBlocks(5);

    CAmount require(12 * COIN);

    std::vector<CSigmaEntry> coins;
    std::vector<sigma::CoinDenomination> coinsToMint;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins, coinsToMint),
      "Coins to spend value is not equal to required amount.");

    std::vector<std::pair<sigma::CoinDenomination, int>> expectedCoins;
    GetCoinSetByDenominationAmount(expectedCoins, 0, 0, 0, 2, 1, 0, 0);

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(expectedCoins, coins),
      "Expect only one SIGMA_DENOM_10 and 2 SIGMA_DENOM_1");
    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(get_coin_choose_smallest_enough)
{
    std::vector<std::pair<sigma::CoinDenomination, int>> newCoins;
    AddOneCoinForEachGroup();
    GetCoinSetByDenominationAmount(newCoins, 1, 1, 1, 1, 1, 1, 1);
    GenerateBlockWithCoins(newCoins);
    GenerateEmptyBlocks(5);

    CAmount require(90 * CENT); // 0.9

    std::vector<CSigmaEntry> coins;
    std::vector<sigma::CoinDenomination> coinsToMint;
    BOOST_CHECK_MESSAGE(pwalletMain->GetCoinsToSpend(require, coins,coinsToMint),
      "Expect enough coin and equal one SIGMA_DENOM_1");

    std::vector<std::pair<sigma::CoinDenomination, int>> expectedCoins;
    GetCoinSetByDenominationAmount(expectedCoins, 0, 0, 0, 1, 0, 0, 0);

    BOOST_CHECK_MESSAGE(CheckDenominationCoins(expectedCoins, coins),
      "Expect only one SIGMA_DENOM_1");
    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(get_coin_by_limit_max_to_1)
{
    AddOneCoinForEachGroup();
    std::vector<std::pair<sigma::CoinDenomination, int>> newCoins;
    GetCoinSetByDenominationAmount(newCoins, 0, 0, 0, 2, 0, 0, 0);
    GenerateBlockWithCoins(newCoins);
    GenerateEmptyBlocks(5);

    CAmount require(110 * CENT); // 1.1

    std::vector<CSigmaEntry> coins;
    std::vector<sigma::CoinDenomination> coinsToMint;
    BOOST_CHECK_EXCEPTION(pwalletMain->GetCoinsToSpend(require, coins, coinsToMint, 1),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return e.what() == std::string("Can not choose coins within limit.");
        });
    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(create_spend_with_insufficient_coins)
{
    CAmount fee;
    CWalletTx tx;
    std::vector<CSigmaEntry> selected;
    std::vector<CHDMint> changes;
    std::vector<CRecipient> recipients;

    GenerateBlockWithCoins({ std::make_pair(sigma::CoinDenomination::SIGMA_DENOM_10, 1) });
    GenerateEmptyBlocks(5);

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

    bool fChangeAddedToFee;
    BOOST_CHECK_EXCEPTION(
        pwalletMain->CreateSigmaSpendTransaction(recipients, fee, selected, changes, fChangeAddedToFee),
        InsufficientFunds,
        [](const InsufficientFunds& e) { return e.what() == std::string("Insufficient funds"); });
    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(create_spend_with_confirmation_less_than_6)
{
    CAmount fee;
    std::vector<CSigmaEntry> selected;
    std::vector<CHDMint> changes;
    std::vector<CRecipient> recipients;

    GenerateBlockWithCoins({ std::make_pair(sigma::CoinDenomination::SIGMA_DENOM_10, 2) });

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

    bool fChangeAddedToFee;
    BOOST_CHECK_EXCEPTION(
        pwalletMain->CreateSigmaSpendTransaction(recipients, fee, selected, changes, fChangeAddedToFee),
        InsufficientFunds,
        [](const InsufficientFunds& e) { return e.what() == std::string("Insufficient funds"); });
    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(create_spend_with_coins_less_than_2)
{
    CAmount fee;
    std::vector<CSigmaEntry> selected;
    std::vector<CHDMint> changes;
    std::vector<CRecipient> recipients;

    GenerateBlockWithCoins({ std::make_pair(sigma::CoinDenomination::SIGMA_DENOM_10, 1) });
    GenerateEmptyBlocks(5);

    recipients.push_back(CRecipient{
        .scriptPubKey = GetScriptForDestination(randomAddr1.Get()),
        .nAmount = 5 * COIN,
        .fSubtractFeeFromAmount = false
    });

    bool fChangeAddedToFee;
    BOOST_CHECK_EXCEPTION(
        pwalletMain->CreateSigmaSpendTransaction(recipients, fee, selected, changes, fChangeAddedToFee),
        std::runtime_error,
        [](const std::runtime_error& e) {return e.what() == std::string("Insufficient funds");});
    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(create_spend_with_coins_more_than_1)
{
    CAmount fee;
    std::vector<CSigmaEntry> selected;
    std::vector<CHDMint> changes;
    std::vector<CRecipient> recipients;

    GenerateBlockWithCoins({ std::make_pair(sigma::CoinDenomination::SIGMA_DENOM_10, 2) });
    GenerateEmptyBlocks(5);

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

    bool fChangeAddedToFee;
    CWalletTx tx = pwalletMain->CreateSigmaSpendTransaction(recipients, fee, selected, changes, fChangeAddedToFee);

    BOOST_CHECK(tx.tx->vin.size() == 2);

    // 2 outputs to recipients 5 + 10 xzc
    // 10 mints as changes, 1 * 4 + 0.5 * 1 + 0.1 * 4 + 0.05 xzc
    BOOST_CHECK(tx.tx->vout.size() == 12);
    BOOST_CHECK(fee > 0);

    BOOST_CHECK(selected.size() == 2);
    BOOST_CHECK(selected[0].get_denomination() == sigma::CoinDenomination::SIGMA_DENOM_10);
    BOOST_CHECK(selected[1].get_denomination() == sigma::CoinDenomination::SIGMA_DENOM_10);

    BOOST_CHECK(CheckSpend(tx.tx->vin[0], selected[0]));
    BOOST_CHECK(CheckSpend(tx.tx->vin[1], selected[1]));

    BOOST_CHECK(ContainTxOut(tx.tx->vout,
        make_pair(GetScriptForDestination(randomAddr1.Get()), 5 * COIN ), 1));
    BOOST_CHECK(ContainTxOut(tx.tx->vout,
        make_pair(GetScriptForDestination(randomAddr2.Get()), 10 * COIN ), 1));

    CAmount remintsSum = std::accumulate(tx.tx->vout.begin(), tx.tx->vout.end(), 0, [](CAmount c, const CTxOut& v) {
        return c + (v.scriptPubKey.IsSigmaMint() ? v.nValue : 0);
    });

    BOOST_CHECK(remintsSum == 495 * CENT);

    // check walletdb
    std::list<CSigmaSpendEntry> spends;
    CWalletDB db(pwalletMain->strWalletFile);

    std::list<CHDMint> coinList = db.ListHDMints();
    BOOST_CHECK(coinList.size() == 2);

    db.ListCoinSpendSerial(spends);
    BOOST_CHECK(spends.empty());

    pwalletMain->SpendSigma(recipients, tx, fee);

    coinList.clear();
    coinList = db.ListHDMints();
    BOOST_CHECK(coinList.size() == 12);
    BOOST_CHECK(std::count_if(coinList.begin(), coinList.end(),
        [](const CHDMint& coin){return !coin.IsUsed();}) == 10);

    spends.clear();
    db.ListCoinSpendSerial(spends);
    BOOST_CHECK(spends.size() == 2);
    sigmaState->Reset();
}

BOOST_AUTO_TEST_CASE(spend)
{
    CWalletTx tx;
    CAmount fee;
    std::vector<CRecipient> recipients;

    GenerateBlockWithCoins({ std::make_pair(sigma::CoinDenomination::SIGMA_DENOM_10, 2) });
    GenerateEmptyBlocks(5);

    recipients.push_back(CRecipient{
        .scriptPubKey = GetScriptForDestination(randomAddr1.Get()),
        .nAmount = 5 * COIN,
        .fSubtractFeeFromAmount = false
    });

    auto selected = pwalletMain->SpendSigma(recipients, tx, fee);

    CWalletDB db(pwalletMain->strWalletFile);

    std::list<CSigmaSpendEntry> spends;
    db.ListCoinSpendSerial(spends);

    std::list<CHDMint> coins = db.ListHDMints();

    BOOST_CHECK(selected.size() == 1);
    BOOST_CHECK(selected[0].get_denomination() == sigma::CoinDenomination::SIGMA_DENOM_10);
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
            [&coin](const CSigmaEntry& e) { return e.value == coin.GetPubcoinValue(); }) != selected.end()) {
            continue;
        }

        BOOST_CHECK(coin.IsUsed() == false);
        BOOST_CHECK(coin.GetId() == -1);
        BOOST_CHECK(coin.GetHeight() == -1);
    }
    sigmaState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
