// Copyright (c) 2012-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"
#include "wallet/coincontrol.h"

#include "evo/deterministicmns.h"
#include "evo/evodb.h"
#include "evo/providertx.h"
#include "evo/specialtx.h"
#include "script/standard.h"

#include <set>
#include <stdint.h>
#include <utility>
#include <vector>

#include "rpc/server.h"
#include "policy/policy.h"
#include "test/test_bitcoin.h"
#include "validation.h"
#include "wallet/test/wallet_test_fixture.h"

#include <boost/foreach.hpp>
#include <boost/test/unit_test.hpp>
#include <univalue.h>

extern UniValue importmulti(const JSONRPCRequest& request);
extern UniValue dumpwallet(const JSONRPCRequest& request);
extern UniValue importwallet(const JSONRPCRequest& request);

// how many times to run all the tests to have a chance to catch errors that only show up with particular random shuffles
#define RUN_TESTS 100

// some tests fail 1% of the time due to bad luck.
// we repeat those tests this many times and only complain if all iterations of the test fail
#define RANDOM_REPEATS 5

using namespace std;

std::vector<std::unique_ptr<CWalletTx>> wtxn;

typedef set<pair<const CWalletTx*,unsigned int> > CoinSet;

BOOST_FIXTURE_TEST_SUITE(wallet_tests, WalletTestingSetup)

static const CWallet wallet;
static vector<COutput> vCoins;

BOOST_AUTO_TEST_CASE(consolidation_preserves_address_and_eligibility)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);
    CKey key, otherKey, watchKey;
    key.MakeNewKey(true);
    otherKey.MakeNewKey(true);
    watchKey.MakeNewKey(true);
    BOOST_REQUIRE(pwalletMain->AddKeyPubKey(key, key.GetPubKey()));
    BOOST_REQUIRE(pwalletMain->AddKeyPubKey(otherKey, otherKey.GetPubKey()));
    const CTxDestination address = key.GetPubKey().GetID();
    const CScript script = GetScriptForDestination(address);
    const CScript otherScript = GetScriptForDestination(otherKey.GetPubKey().GetID());
    const CScript watchScript = GetScriptForDestination(watchKey.GetPubKey().GetID());
    BOOST_REQUIRE(pwalletMain->AddWatchOnly(watchScript, 0));

    CMutableTransaction funding;
    funding.vin.emplace_back(COutPoint(uint256S("01"), 0));
    funding.vout = {{COIN, script}, {2 * COIN, script}, {3 * COIN, script}, {4 * COIN, otherScript},
                    {COIN, watchScript}, {0, script}, {COIN, GetScriptForRawPubKey(key.GetPubKey())}};
    CWalletTx received(pwalletMain, MakeTransactionRef(funding));
    received.hashBlock = chainActive.Tip()->GetBlockHash();
    received.nIndex = 1;
    BOOST_REQUIRE(pwalletMain->AddToWallet(received));
    const COutPoint locked(received.GetHash(), 2);
    pwalletMain->LockCoin(locked);
    auto groups = pwalletMain->GetConsolidationCoins();
    BOOST_REQUIRE_EQUAL(groups.size(), 2);
    BOOST_REQUIRE_EQUAL(groups.at(address).size(), 2);
    BOOST_CHECK_EQUAL(groups.at(otherKey.GetPubKey().GetID()).size(), 1);
    const auto plans = pwalletMain->GetConsolidationPlans();
    BOOST_REQUIRE_EQUAL(plans.at(address).inputs.size(), 2);
    BOOST_CHECK(!plans.at(address).sizeLimited);
    BOOST_CHECK(!plans.at(otherKey.GetPubKey().GetID()).error.empty());
    BOOST_CHECK_EQUAL(pwalletMain->GetConsolidationPlans(address).size(), 1);

    CWalletTx consolidated;
    CReserveKey reserveKey(pwalletMain);
    CAmount fee = 0;
    std::string error;
    BOOST_REQUIRE_MESSAGE(pwalletMain->CreateConsolidationTransaction(address, consolidated, reserveKey, fee, error), error);
    BOOST_REQUIRE_EQUAL(consolidated.tx->vin.size(), 2);
    BOOST_REQUIRE_EQUAL(consolidated.tx->vout.size(), 1);
    BOOST_CHECK(consolidated.tx->vout[0].scriptPubKey == script);
    BOOST_CHECK_EQUAL(consolidated.tx->vout[0].nValue + fee, 3 * COIN);
    BOOST_CHECK_EQUAL(fee, plans.at(address).fee);
    BOOST_CHECK_GT(fee, 0);
    BOOST_CHECK(!pwalletMain->IsSpent(received.GetHash(), 0)); // Preparation/cancellation does not spend.
    BOOST_CHECK(!pwalletMain->IsSpent(received.GetHash(), 1));
    for (size_t i = 0; i < consolidated.tx->vin.size(); ++i) {
        const auto& input = consolidated.tx->vin[i];
        BOOST_REQUIRE(input.prevout.hash == received.GetHash());
        BOOST_REQUIRE_LT(input.prevout.n, 2);
        const auto& prevout = received.tx->vout[input.prevout.n];
        BOOST_CHECK(VerifyScript(input.scriptSig, script, &input.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS,
            TransactionSignatureChecker(consolidated.tx.get(), i, prevout.nValue)));
    }

    // These wallet-only inputs are absent from the chain UTXO set. Rejection
    // must leave both the transaction history and its inputs untouched.
    CValidationState state;
    BOOST_CHECK(!pwalletMain->CommitTransaction(consolidated, reserveKey, nullptr, state, true));
    BOOST_CHECK(!pwalletMain->mapWallet.count(consolidated.GetHash()));
    BOOST_CHECK(!pwalletMain->IsSpent(received.GetHash(), 0));
    BOOST_CHECK(!pwalletMain->IsSpent(received.GetHash(), 1));

    // A same-wallet change output belongs to its actual address, not its ancestor's.
    CMutableTransaction change;
    change.vin.emplace_back(COutPoint(received.GetHash(), 0));
    change.vout.emplace_back(COIN / 2, otherScript);
    CWalletTx changed(pwalletMain, MakeTransactionRef(change));
    changed.hashBlock = received.hashBlock;
    changed.nIndex = 2;
    BOOST_REQUIRE(pwalletMain->AddToWallet(changed));
    groups = pwalletMain->GetConsolidationCoins();
    BOOST_CHECK_EQUAL(groups.at(address).size(), 1);
    BOOST_CHECK_EQUAL(groups.at(otherKey.GetPubKey().GetID()).size(), 2);
    BOOST_CHECK(!pwalletMain->CreateConsolidationTransaction(address, consolidated, reserveKey, fee, error));

    // Unconfirmed and immature outputs are not candidates, even at this address.
    CMutableTransaction pending;
    pending.vin.emplace_back(COutPoint(uint256S("02"), 0));
    pending.vout.assign(50, CTxOut(COIN, script));
    BOOST_REQUIRE(pwalletMain->AddToWallet(CWalletTx(pwalletMain, MakeTransactionRef(pending))));
    pending.vin[0].prevout.SetNull();
    CWalletTx immature(pwalletMain, MakeTransactionRef(pending));
    immature.hashBlock = received.hashBlock;
    immature.nIndex = 0;
    BOOST_REQUIRE(pwalletMain->AddToWallet(immature));
    BOOST_CHECK_EQUAL(pwalletMain->GetConsolidationCoins().at(address).size(), 1);
    BOOST_CHECK(!pwalletMain->CreateConsolidationTransaction(CNoDestination(), consolidated, reserveKey, fee, error));
}

BOOST_AUTO_TEST_CASE(consolidation_transaction_limits_and_fee_failure)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);
    // Compressed, uncompressed, exchange, multisig, and wrapped witness addresses need different
    // input sizes. Each batch must fit and the next maximum-size input must not.
    for (int kind = 0; kind < 5; ++kind) {
        CKey key;
        key.MakeNewKey(kind != 1);
        BOOST_REQUIRE(pwalletMain->AddKeyPubKey(key, key.GetPubKey()));
        CTxDestination address = key.GetPubKey().GetID();
        if (kind == 2)
            address = CExchangeKeyID(key.GetPubKey().GetID());
        if (kind == 3) {
            const CScript redeem = GetScriptForMultisig(1, std::vector<CPubKey>(15, key.GetPubKey()));
            BOOST_REQUIRE(pwalletMain->AddCScript(redeem));
            address = CScriptID(redeem);
        }
        if (kind == 4) {
            const CScript witness = GetScriptForWitness(GetScriptForRawPubKey(key.GetPubKey()));
            BOOST_REQUIRE(pwalletMain->AddCScript(witness));
            address = CScriptID(witness);
        }
        const CScript script = GetScriptForDestination(address);
        CMutableTransaction funding;
        funding.vin.emplace_back(COutPoint(uint256S("03"), kind));
        funding.vout.assign(kind == 4 ? 7000 : 2000, CTxOut(COIN, script));
        CWalletTx received(pwalletMain, MakeTransactionRef(funding));
        received.hashBlock = chainActive.Tip()->GetBlockHash();
        received.nIndex = 1;
        BOOST_REQUIRE(pwalletMain->AddToWallet(received));
        const auto plan = pwalletMain->GetConsolidationPlans(address).at(address);
        BOOST_CHECK_EQUAL(plan.eligibleCount, funding.vout.size());
        BOOST_CHECK(plan.sizeLimited);

        CWalletTx consolidated;
        CReserveKey reserveKey(pwalletMain);
        CAmount fee = 0;
        std::string error;
        BOOST_REQUIRE_MESSAGE(pwalletMain->CreateConsolidationTransaction(address, consolidated, reserveKey, fee, error), error);
        BOOST_REQUIRE_GT(consolidated.tx->vin.size(), 252);
        BOOST_REQUIRE_LT(consolidated.tx->vin.size(), funding.vout.size());
        BOOST_CHECK_EQUAL(consolidated.tx->vin.size(), plan.inputs.size());
        BOOST_CHECK_EQUAL(fee, plan.fee);
        BOOST_REQUIRE_EQUAL(consolidated.tx->vout.size(), 1);
        BOOST_CHECK(consolidated.tx->vout[0].scriptPubKey == script);
        BOOST_CHECK_EQUAL(consolidated.tx->vout[0].nValue + fee, CAmount(consolidated.tx->vin.size()) * COIN);
        BOOST_CHECK_LT(GetTransactionWeight(*consolidated.tx), MAX_NEW_TX_WEIGHT);
        BOOST_CHECK(IsStandardTx(*consolidated.tx, error));

        CCoinsView emptyView;
        CCoinsViewCache view(&emptyView);
        std::set<COutPoint> selected;
        std::vector<std::pair<const CWalletTx*, unsigned int>> inputs;
        for (const auto& input : consolidated.tx->vin) {
            BOOST_REQUIRE(input.prevout.hash == received.GetHash());
            BOOST_REQUIRE_LT(input.prevout.n, funding.vout.size());
            selected.insert(input.prevout);
            inputs.emplace_back(&received, input.prevout.n);
            view.AddCoin(input.prevout, Coin(funding.vout[input.prevout.n], 0, false), false);
        }
        BOOST_CHECK_EQUAL(selected.size(), consolidated.tx->vin.size());
        BOOST_CHECK_LE(GetTransactionSigOpCost(*consolidated.tx, view, STANDARD_SCRIPT_VERIFY_FLAGS), MAX_STANDARD_TX_SIGOPS_COST);
        CMutableTransaction sized(*consolidated.tx);
        BOOST_REQUIRE(pwalletMain->DummySignTx(sized, inputs));
        BOOST_CHECK_EQUAL(::GetSerializeSize(sized, SER_NETWORK, PROTOCOL_VERSION), plan.signedBytes);
        BOOST_CHECK_LT(GetTransactionWeight(sized), MAX_NEW_TX_WEIGHT);
        unsigned int next = 0;
        while (selected.count(COutPoint(received.GetHash(), next))) ++next;
        const COutPoint extra(received.GetHash(), next);
        sized.vin.emplace_back(extra);
        inputs.emplace_back(&received, next);
        view.AddCoin(extra, Coin(funding.vout[next], 0, false), false);
        BOOST_REQUIRE(pwalletMain->DummySignTx(sized, inputs));
        BOOST_CHECK(GetTransactionWeight(sized) >= MAX_NEW_TX_WEIGHT ||
            GetTransactionSigOpCost(CTransaction(sized), view, STANDARD_SCRIPT_VERIFY_FLAGS) > MAX_STANDARD_TX_SIGOPS_COST);

        if (kind == 0) {
            CCoinControl allInputs;
            for (unsigned int i = 0; i < funding.vout.size(); ++i)
                allInputs.Select(COutPoint(received.GetHash(), i));
            int changePosition = -1;
            BOOST_CHECK(!pwalletMain->CreateTransaction({{script, CAmount(funding.vout.size()) * COIN, true}},
                consolidated, reserveKey, fee, changePosition, error, &allInputs));
            BOOST_CHECK(error.find("File > Consolidate outputs") != std::string::npos);
            BOOST_CHECK(error.find("consolidateaddress") != std::string::npos);
        }
        if (kind == 3) {
            // Even two large inputs exceed this fee cap despite ample value.
            struct RestoreMaxFee {
                CAmount original;
                ~RestoreMaxFee() { maxTxFee = original; }
            } restoreMaxFee{maxTxFee};
            maxTxFee = ::minRelayTxFee.GetFee(1000);
            const auto capped = pwalletMain->GetConsolidationPlans(address).at(address);
            BOOST_CHECK(capped.inputs.empty());
            BOOST_CHECK_EQUAL(capped.error, "Transaction too large for fee policy");
        }
    }

    CKey dustKey;
    dustKey.MakeNewKey(true);
    BOOST_REQUIRE(pwalletMain->AddKeyPubKey(dustKey, dustKey.GetPubKey()));
    const CTxDestination dustAddress = dustKey.GetPubKey().GetID();
    CMutableTransaction dust;
    dust.vin.emplace_back(COutPoint(uint256S("04"), 0));
    dust.vout.assign(50, CTxOut(1, GetScriptForDestination(dustAddress)));
    CWalletTx receivedDust(pwalletMain, MakeTransactionRef(dust));
    receivedDust.hashBlock = chainActive.Tip()->GetBlockHash();
    receivedDust.nIndex = 1;
    BOOST_REQUIRE(pwalletMain->AddToWallet(receivedDust));
    CWalletTx failed;
    CReserveKey reserveKey(pwalletMain);
    CAmount fee = 0;
    std::string error;
    // Firo permits dust outputs, but their combined value cannot pay the fee.
    // Other addresses have ample funds, but must never subsidize this batch.
    BOOST_CHECK(!pwalletMain->CreateConsolidationTransaction(dustAddress, failed, reserveKey, fee, error));
    BOOST_CHECK_EQUAL(pwalletMain->GetConsolidationCoins().at(dustAddress).size(), 50);
    const auto plan = pwalletMain->GetConsolidationPlans(dustAddress).at(dustAddress);
    BOOST_CHECK_EQUAL(plan.eligibleCount, 50);
    BOOST_CHECK(plan.inputs.empty());
    BOOST_CHECK(!plan.error.empty());
    BOOST_CHECK(!plan.sizeLimited);
}

BOOST_AUTO_TEST_CASE(consolidation_plan_fee_boundary_and_collateral)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);
    struct RestorePayTxFee {
        CFeeRate original;
        ~RestorePayTxFee() { payTxFee = original; }
    } restorePayTxFee{payTxFee};
    payTxFee = CFeeRate(1000);

    CKey key;
    key.MakeNewKey(true);
    BOOST_REQUIRE(pwalletMain->AddKeyPubKey(key, key.GetPubKey()));
    const CTxDestination address = key.GetPubKey().GetID();
    const CScript script = GetScriptForDestination(address);
    CMutableTransaction funding;
    funding.vin.emplace_back(COutPoint(uint256S("05"), 0));
    funding.vout.assign(300, CTxOut(1, script));
    funding.vout[0].nValue = funding.vout[1].nValue = 18546;
    CWalletTx received(pwalletMain, MakeTransactionRef(funding));
    received.hashBlock = chainActive.Tip()->GetBlockHash();
    received.nIndex = 1;
    BOOST_REQUIRE(pwalletMain->AddToWallet(received));
    // Shrinking crosses the CompactSize boundary at 253 inputs.
    const auto plan = pwalletMain->GetConsolidationPlans(address).at(address);
    BOOST_REQUIRE_EQUAL(plan.inputs.size(), 252);
    BOOST_CHECK_EQUAL(plan.signedBytes, 37340);
    BOOST_CHECK_EQUAL(plan.fee, 37340);
    BOOST_CHECK_EQUAL(plan.total - plan.fee, 2);
    BOOST_CHECK(!plan.sizeLimited);
    CWalletTx consolidated;
    CReserveKey reserveKey(pwalletMain);
    CAmount fee = 0;
    std::string error;
    BOOST_REQUIRE_MESSAGE(pwalletMain->CreateConsolidationTransaction(address, consolidated, reserveKey, fee, error), error);
    BOOST_CHECK_EQUAL(consolidated.tx->vin.size(), plan.inputs.size());
    BOOST_CHECK_EQUAL(fee, plan.fee);

    const CScript witnessProgram = GetScriptForWitness(GetScriptForRawPubKey(key.GetPubKey()));
    BOOST_REQUIRE(pwalletMain->AddCScript(witnessProgram));
    const CTxDestination wrappedAddress = CScriptID(witnessProgram);
    funding.vin[0].prevout.n = 1;
    funding.vout.assign(300, CTxOut(1, GetScriptForDestination(wrappedAddress)));
    funding.vout[0].nValue = funding.vout[1].nValue = 21570;
    CWalletTx wrappedReceived(pwalletMain, MakeTransactionRef(funding));
    wrappedReceived.hashBlock = received.hashBlock;
    wrappedReceived.nIndex = 4;
    BOOST_REQUIRE(pwalletMain->AddToWallet(wrappedReceived));
    const auto wrappedPlan = pwalletMain->GetConsolidationPlans(wrappedAddress).at(wrappedAddress);
    BOOST_REQUIRE_EQUAL(wrappedPlan.inputs.size(), 252);
    BOOST_CHECK_EQUAL(wrappedPlan.signedBytes, 43388);
    BOOST_REQUIRE_MESSAGE(pwalletMain->CreateConsolidationTransaction(wrappedAddress, consolidated, reserveKey, fee, error), error);
    std::vector<std::pair<const CWalletTx*, unsigned int>> wrappedInputs;
    for (const auto& input : consolidated.tx->vin)
        wrappedInputs.emplace_back(&wrappedReceived, input.prevout.n);
    CMutableTransaction wrappedSized(*consolidated.tx);
    BOOST_REQUIRE(pwalletMain->DummySignTx(wrappedSized, wrappedInputs));
    BOOST_CHECK(wrappedSized.HasWitness());
    BOOST_CHECK_EQUAL(::GetSerializeSize(wrappedSized, SER_NETWORK, PROTOCOL_VERSION), wrappedPlan.signedBytes);
    BOOST_CHECK_EQUAL(fee, wrappedPlan.fee);

    // Known collateral stays excluded even if manually unlocked. Ordinary
    // 1000-FIRO outputs are still eligible for this same-address operation.
    CMutableTransaction collateral;
    collateral.nVersion = 3;
    collateral.nType = TRANSACTION_PROVIDER_REGISTER;
    collateral.vin.emplace_back(COutPoint(uint256S("06"), 0));
    collateral.vout.emplace_back(1000 * COIN, script);
    CProRegTx registration;
    registration.collateralOutpoint.n = 0;
    SetTxPayload(collateral, registration);
    CWalletTx collateralTx(pwalletMain, MakeTransactionRef(collateral));
    collateralTx.hashBlock = received.hashBlock;
    collateralTx.nIndex = 2;
    BOOST_REQUIRE(pwalletMain->AddToWallet(collateralTx));
    pwalletMain->UnlockCoin(COutPoint(collateralTx.GetHash(), 0));
    collateral.nType = TRANSACTION_NORMAL;
    collateral.vExtraPayload.clear();
    CWalletTx ordinary(pwalletMain, MakeTransactionRef(collateral));
    ordinary.hashBlock = received.hashBlock;
    ordinary.nIndex = 3;
    BOOST_REQUIRE(pwalletMain->AddToWallet(ordinary));
    const auto coins = pwalletMain->GetConsolidationCoins(address).at(address);
    BOOST_CHECK_EQUAL(coins.size(), 301);
    BOOST_CHECK(std::find(coins.begin(), coins.end(), COutPoint(collateralTx.GetHash(), 0)) == coins.end());
    BOOST_CHECK(std::find(coins.begin(), coins.end(), COutPoint(ordinary.GetHash(), 0)) != coins.end());
}

BOOST_FIXTURE_TEST_CASE(consolidation_affordable_batch_commit, TestChain100Setup)
{
    struct RestorePayTxFee {
        CFeeRate original;
        ~RestorePayTxFee() { payTxFee = original; }
    } restorePayTxFee{payTxFee};
    payTxFee = CFeeRate(1000);

    CKey key, otherKey;
    key.MakeNewKey(true);
    otherKey.MakeNewKey(true);
    {
        LOCK(pwalletMain->cs_wallet);
        BOOST_REQUIRE(pwalletMain->AddKeyPubKey(key, key.GetPubKey()));
        BOOST_REQUIRE(pwalletMain->AddKeyPubKey(otherKey, otherKey.GetPubKey()));
        BOOST_REQUIRE(pwalletMain->AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey()));
    }
    const CTxDestination address = key.GetPubKey().GetID();
    const CScript script = GetScriptForDestination(address);
    const CTxDestination otherAddress = otherKey.GetPubKey().GetID();

    // Fund real chain UTXOs. All 50 inputs together cannot pay the fee, but
    // a prefix of the largest outputs can. Another address must not subsidize it.
    CMutableTransaction funding;
    funding.vin.emplace_back(COutPoint(coinbaseTxns[0].GetHash(), 0));
    funding.vout.assign(50, CTxOut(1, script));
    funding.vout[0].nValue = funding.vout[1].nValue = 1000;
    funding.vout.emplace_back(coinbaseTxns[0].vout[0].nValue - 2048 - 10000,
        GetScriptForDestination(otherAddress));
    BOOST_REQUIRE(SignSignature(*pwalletMain, coinbaseTxns[0], funding, 0, SIGHASH_ALL));
    const auto fundingBlock = CreateAndProcessBlock({funding}, coinbaseKey);
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == fundingBlock.GetHash());
        pwalletMain->SyncTransaction(CTransaction(funding), chainActive.Tip(), 1);
        BOOST_REQUIRE_EQUAL(pwalletMain->GetConsolidationCoins().at(address).size(), 50);
    }

    CWalletTx consolidated;
    CReserveKey reserveKey(pwalletMain);
    CAmount fee = 0;
    std::string error;
    BOOST_REQUIRE_MESSAGE(pwalletMain->CreateConsolidationTransaction(address, consolidated, reserveKey, fee, error), error);
    const auto& tx = *consolidated.tx;
    // At 1 sat/byte, 13 maximum-size inputs cost 1968 of 2011 satoshis;
    // a 14th input would cost more than the selected value.
    BOOST_REQUIRE_EQUAL(tx.vin.size(), 13);
    BOOST_REQUIRE_EQUAL(tx.vout.size(), 1);
    BOOST_CHECK(tx.vout[0].scriptPubKey == script);
    BOOST_CHECK_GT(tx.vout[0].nValue, 0);
    CAmount selectedValue = 0;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        for (const auto& input : tx.vin) {
            BOOST_REQUIRE(input.prevout.hash == funding.GetHash());
            BOOST_REQUIRE_LT(input.prevout.n, 50);
            selectedValue += funding.vout[input.prevout.n].nValue;
            BOOST_CHECK(!pwalletMain->IsSpent(input.prevout.hash, input.prevout.n));
        }
    }
    BOOST_CHECK_EQUAL(tx.vout[0].nValue + fee, selectedValue);

    const size_t remaining = 50 - tx.vin.size();
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        CValidationState state;
        BOOST_REQUIRE_MESSAGE(pwalletMain->CommitTransaction(consolidated, reserveKey, nullptr, state, true), state.GetRejectReason());
        BOOST_CHECK(mempool.exists(tx.GetHash()));
        BOOST_REQUIRE(pwalletMain->GetWalletTx(tx.GetHash()));
        BOOST_CHECK_EQUAL(pwalletMain->GetWalletTx(tx.GetHash())->GetDepthInMainChain(), 0);
        for (const auto& input : tx.vin)
            BOOST_CHECK(pwalletMain->IsSpent(input.prevout.hash, input.prevout.n));
        const auto groups = pwalletMain->GetConsolidationCoins();
        BOOST_CHECK_EQUAL(groups.at(address).size(), remaining);
        BOOST_CHECK_EQUAL(groups.at(otherAddress).size(), 1);
        BOOST_CHECK(!pwalletMain->IsSpent(funding.GetHash(), 50));
    }

    const auto confirmedBlock = CreateAndProcessBlock({CMutableTransaction(tx)}, coinbaseKey);
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == confirmedBlock.GetHash());
        pwalletMain->SyncTransaction(tx, chainActive.Tip(), 1);
        BOOST_CHECK(!mempool.exists(tx.GetHash()));
        BOOST_CHECK_EQUAL(pwalletMain->GetWalletTx(tx.GetHash())->GetDepthInMainChain(), 1);
        const auto groups = pwalletMain->GetConsolidationCoins();
        BOOST_CHECK_EQUAL(groups.at(address).size(), remaining + 1);
        BOOST_CHECK(std::find(groups.at(address).begin(), groups.at(address).end(), COutPoint(tx.GetHash(), 0)) != groups.at(address).end());
        const auto remainder = pwalletMain->GetConsolidationPlans(address).at(address);
        BOOST_CHECK_EQUAL(remainder.eligibleCount, remaining + 1);
        BOOST_CHECK(remainder.inputs.empty());
        BOOST_CHECK(!remainder.error.empty());
    }
}

BOOST_AUTO_TEST_CASE(conflict_notifications_include_descendants)
{
    CMutableTransaction parent;
    parent.vin.emplace_back(COutPoint(uint256S("01"), 0));
    parent.vout.emplace_back(COIN, CScript());
    const auto parentTx = MakeTransactionRef(parent);
    CMutableTransaction child;
    child.vin.emplace_back(COutPoint(parentTx->GetHash(), 0));
    child.vout.emplace_back(COIN, CScript());
    const auto childTx = MakeTransactionRef(child);
    BOOST_REQUIRE(pwalletMain->AddToWallet(CWalletTx(pwalletMain, parentTx)));
    BOOST_REQUIRE(pwalletMain->AddToWallet(CWalletTx(pwalletMain, childTx)));

    std::vector<uint256> changed;
    boost::signals2::scoped_connection connection(pwalletMain->NotifyTransactionChanged.connect(
        [&](CWallet* changedWallet, const uint256& hash, ChangeType status) {
            BOOST_CHECK(changedWallet == pwalletMain);
            BOOST_CHECK(status == CT_UPDATED);
            changed.push_back(hash);
        }));
    CMutableTransaction conflicting(parent);
    conflicting.vout[0].nValue = COIN / 2;
    const CTransaction conflictingTx(conflicting);
    pwalletMain->SyncTransaction(conflictingTx, chainActive.Tip(), 0);
    BOOST_REQUIRE_EQUAL(changed.size(), 2);
    const std::set<uint256> expected{parentTx->GetHash(), childTx->GetHash()};
    BOOST_CHECK(std::set<uint256>(changed.begin(), changed.end()) == expected);

    pwalletMain->SyncTransaction(conflictingTx, chainActive.Tip(), 0);
    BOOST_CHECK_EQUAL(changed.size(), 2);
}

FIRO_UNUSED static void add_coin(const CAmount& nValue, int nAge = 6*24, bool fIsFromMe = false, int nInput=0)
{
    static int nextLockTime = 0;
    CMutableTransaction tx;
    tx.nLockTime = nextLockTime++;        // so all transactions get different hashes
    tx.vout.resize(nInput+1);
    tx.vout[nInput].nValue = nValue;
    if (fIsFromMe) {
        // IsFromMe() returns (GetDebit() > 0), and GetDebit() is 0 if vin.empty(),
        // so stop vin being empty, and cache a non-zero Debit to fake out IsFromMe()
        tx.vin.resize(1);
    }
    std::unique_ptr<CWalletTx> wtx(new CWalletTx(&wallet, MakeTransactionRef(std::move(tx))));
    if (fIsFromMe)
    {
        wtx->fDebitCached = true;
        wtx->nDebitCached = 1;
    }
    COutput output(wtx.get(), nInput, nAge, true, true);
    vCoins.push_back(output);
    wtxn.emplace_back(std::move(wtx));
}

FIRO_UNUSED static void empty_wallet(void)
{
    vCoins.clear();
    wtxn.clear();
}

FIRO_UNUSED static bool equal_sets(CoinSet a, CoinSet b)
{
    pair<CoinSet::iterator, CoinSet::iterator> ret = mismatch(a.begin(), a.end(), b.begin());
    return ret.first == a.end() && ret.second == b.end();
}

/*BOOST_AUTO_TEST_CASE(coin_selection_tests)
{
    CoinSet setCoinsRet, setCoinsRet2;
    CAmount nValueRet;

    LOCK(wallet.cs_wallet);

    // test multiple times to allow for differences in the shuffle order
    for (int i = 0; i < RUN_TESTS; i++)
    {
        empty_wallet();

        // with an empty wallet we can't even pay one cent
        BOOST_CHECK(!wallet.SelectCoinsMinConf( 1 * CENT, 1, 6, 0, vCoins, setCoinsRet, nValueRet));

        add_coin(1*CENT, 4);        // add a new 1 cent coin

        // with a new 1 cent coin, we still can't find a mature 1 cent
        BOOST_CHECK(!wallet.SelectCoinsMinConf( 1 * CENT, 1, 6, 0, vCoins, setCoinsRet, nValueRet));

        // but we can find a new 1 cent
        BOOST_CHECK( wallet.SelectCoinsMinConf( 1 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1 * CENT);

        add_coin(2*CENT);           // add a mature 2 cent coin

        // we can't make 3 cents of mature coins
        BOOST_CHECK(!wallet.SelectCoinsMinConf( 3 * CENT, 1, 6, 0, vCoins, setCoinsRet, nValueRet));

        // we can make 3 cents of new  coins
        BOOST_CHECK( wallet.SelectCoinsMinConf( 3 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 3 * CENT);

        add_coin(5*CENT);           // add a mature 5 cent coin,
        add_coin(10*CENT, 3, true); // a new 10 cent coin sent from one of our own addresses
        add_coin(20*CENT);          // and a mature 20 cent coin

        // now we have new: 1+10=11 (of which 10 was self-sent), and mature: 2+5+20=27.  total = 38

        // we can't make 38 cents only if we disallow new coins:
        BOOST_CHECK(!wallet.SelectCoinsMinConf(38 * CENT, 1, 6, 0, vCoins, setCoinsRet, nValueRet));
        // we can't even make 37 cents if we don't allow new coins even if they're from us
        BOOST_CHECK(!wallet.SelectCoinsMinConf(38 * CENT, 6, 6, 0, vCoins, setCoinsRet, nValueRet));
        // but we can make 37 cents if we accept new coins from ourself
        BOOST_CHECK( wallet.SelectCoinsMinConf(37 * CENT, 1, 6, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 37 * CENT);
        // and we can make 38 cents if we accept all new coins
        BOOST_CHECK( wallet.SelectCoinsMinConf(38 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 38 * CENT);

        // try making 34 cents from 1,2,5,10,20 - we can't do it exactly
        BOOST_CHECK( wallet.SelectCoinsMinConf(34 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 35 * CENT);       // but 35 cents is closest
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3U);     // the best should be 20+10+5.  it's incredibly unlikely the 1 or 2 got included (but possible)

        // when we try making 7 cents, the smaller coins (1,2,5) are enough.  We should see just 2+5
        BOOST_CHECK( wallet.SelectCoinsMinConf( 7 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 7 * CENT);
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2U);

        // when we try making 8 cents, the smaller coins (1,2,5) are exactly enough.
        BOOST_CHECK( wallet.SelectCoinsMinConf( 8 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK(nValueRet == 8 * CENT);
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3U);

        // when we try making 9 cents, no subset of smaller coins is enough, and we get the next bigger coin (10)
        BOOST_CHECK( wallet.SelectCoinsMinConf( 9 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 10 * CENT);
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);

        // now clear out the wallet and start again to test choosing between subsets of smaller coins and the next biggest coin
        empty_wallet();

        add_coin( 6*CENT);
        add_coin( 7*CENT);
        add_coin( 8*CENT);
        add_coin(20*CENT);
        add_coin(30*CENT); // now we have 6+7+8+20+30 = 71 cents total

        // check that we have 71 and not 72
        BOOST_CHECK( wallet.SelectCoinsMinConf(71 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK(!wallet.SelectCoinsMinConf(72 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));

        // now try making 16 cents.  the best smaller coins can do is 6+7+8 = 21; not as good at the next biggest coin, 20
        BOOST_CHECK( wallet.SelectCoinsMinConf(16 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 20 * CENT); // we should get 20 in one coin
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);

        add_coin( 5*CENT); // now we have 5+6+7+8+20+30 = 75 cents total

        // now if we try making 16 cents again, the smaller coins can make 5+6+7 = 18 cents, better than the next biggest coin, 20
        BOOST_CHECK( wallet.SelectCoinsMinConf(16 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 18 * CENT); // we should get 18 in 3 coins
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3U);

        add_coin( 18*CENT); // now we have 5+6+7+8+18+20+30

        // and now if we try making 16 cents again, the smaller coins can make 5+6+7 = 18 cents, the same as the next biggest coin, 18
        BOOST_CHECK( wallet.SelectCoinsMinConf(16 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 18 * CENT);  // we should get 18 in 1 coin
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U); // because in the event of a tie, the biggest coin wins

        // now try making 11 cents.  we should get 5+6
        BOOST_CHECK( wallet.SelectCoinsMinConf(11 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 11 * CENT);
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2U);

        // check that the smallest bigger coin is used
        add_coin( 1*COIN);
        add_coin( 2*COIN);
        add_coin( 3*COIN);
        add_coin( 4*COIN); // now we have 5+6+7+8+18+20+30+100+200+300+400 = 1094 cents
        BOOST_CHECK( wallet.SelectCoinsMinConf(95 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1 * COIN);  // we should get 1 BTC in 1 coin
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);

        BOOST_CHECK( wallet.SelectCoinsMinConf(195 * CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 2 * COIN);  // we should get 2 BTC in 1 coin
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);

        // empty the wallet and start again, now with fractions of a cent, to test small change avoidance

        empty_wallet();
        add_coin(MIN_CHANGE * 1 / 10);
        add_coin(MIN_CHANGE * 2 / 10);
        add_coin(MIN_CHANGE * 3 / 10);
        add_coin(MIN_CHANGE * 4 / 10);
        add_coin(MIN_CHANGE * 5 / 10);

        // try making 1 * MIN_CHANGE from the 1.5 * MIN_CHANGE
        // we'll get change smaller than MIN_CHANGE whatever happens, so can expect MIN_CHANGE exactly
        BOOST_CHECK( wallet.SelectCoinsMinConf(MIN_CHANGE, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, MIN_CHANGE);

        // but if we add a bigger coin, small change is avoided
        add_coin(1111*MIN_CHANGE);

        // try making 1 from 0.1 + 0.2 + 0.3 + 0.4 + 0.5 + 1111 = 1112.5
        BOOST_CHECK( wallet.SelectCoinsMinConf(1 * MIN_CHANGE, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1 * MIN_CHANGE); // we should get the exact amount

        // if we add more small coins:
        add_coin(MIN_CHANGE * 6 / 10);
        add_coin(MIN_CHANGE * 7 / 10);

        // and try again to make 1.0 * MIN_CHANGE
        BOOST_CHECK( wallet.SelectCoinsMinConf(1 * MIN_CHANGE, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1 * MIN_CHANGE); // we should get the exact amount

        // run the 'mtgox' test (see http://blockexplorer.com/tx/29a3efd3ef04f9153d47a990bd7b048a4b2d213daaa5fb8ed670fb85f13bdbcf)
        // they tried to consolidate 10 50k coins into one 500k coin, and ended up with 50k in change
        empty_wallet();
        for (int j = 0; j < 20; j++)
            add_coin(50000 * COIN);

        BOOST_CHECK( wallet.SelectCoinsMinConf(500000 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 500000 * COIN); // we should get the exact amount
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 10U); // in ten coins

        // if there's not enough in the smaller coins to make at least 1 * MIN_CHANGE change (0.5+0.6+0.7 < 1.0+1.0),
        // we need to try finding an exact subset anyway

        // sometimes it will fail, and so we use the next biggest coin:
        empty_wallet();
        add_coin(MIN_CHANGE * 5 / 10);
        add_coin(MIN_CHANGE * 6 / 10);
        add_coin(MIN_CHANGE * 7 / 10);
        add_coin(1111 * MIN_CHANGE);
        BOOST_CHECK( wallet.SelectCoinsMinConf(1 * MIN_CHANGE, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1111 * MIN_CHANGE); // we get the bigger coin
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);

        // but sometimes it's possible, and we use an exact subset (0.4 + 0.6 = 1.0)
        empty_wallet();
        add_coin(MIN_CHANGE * 4 / 10);
        add_coin(MIN_CHANGE * 6 / 10);
        add_coin(MIN_CHANGE * 8 / 10);
        add_coin(1111 * MIN_CHANGE);
        BOOST_CHECK( wallet.SelectCoinsMinConf(MIN_CHANGE, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, MIN_CHANGE);   // we should get the exact amount
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2U); // in two coins 0.4+0.6

        // test avoiding small change
        empty_wallet();
        add_coin(MIN_CHANGE * 5 / 100);
        add_coin(MIN_CHANGE * 1);
        add_coin(MIN_CHANGE * 100);

        // trying to make 100.01 from these three coins
        BOOST_CHECK(wallet.SelectCoinsMinConf(MIN_CHANGE * 10001 / 100, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, MIN_CHANGE * 10105 / 100); // we should get all coins
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3U);

        // but if we try to make 99.9, we should take the bigger of the two small coins to avoid small change
        BOOST_CHECK(wallet.SelectCoinsMinConf(MIN_CHANGE * 9990 / 100, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 101 * MIN_CHANGE);
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2U);

        // test with many inputs
        for (CAmount amt=1500; amt < COIN; amt*=10) {
             empty_wallet();
             // Create 676 inputs (=  (old MAX_STANDARD_TX_SIZE == 100000)  / 148 bytes per input)
             for (uint16_t j = 0; j < 676; j++)
                 add_coin(amt);
             BOOST_CHECK(wallet.SelectCoinsMinConf(2000, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
             if (amt - 2000 < MIN_CHANGE) {
                 // needs more than one input:
                 uint16_t returnSize = std::ceil((2000.0 + MIN_CHANGE)/amt);
                 CAmount returnValue = amt * returnSize;
                 BOOST_CHECK_EQUAL(nValueRet, returnValue);
                 BOOST_CHECK_EQUAL(setCoinsRet.size(), returnSize);
             } else {
                 // one input is sufficient:
                 BOOST_CHECK_EQUAL(nValueRet, amt);
                 BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);
             }
        }

        // test randomness
        {
            empty_wallet();
            for (int i2 = 0; i2 < 100; i2++)
                add_coin(COIN);

            // picking 50 from 100 coins doesn't depend on the shuffle,
            // but does depend on randomness in the stochastic approximation code
            BOOST_CHECK(wallet.SelectCoinsMinConf(50 * COIN, 1, 6, 0, vCoins, setCoinsRet , nValueRet));
            BOOST_CHECK(wallet.SelectCoinsMinConf(50 * COIN, 1, 6, 0, vCoins, setCoinsRet2, nValueRet));
            BOOST_CHECK(!equal_sets(setCoinsRet, setCoinsRet2));

            int fails = 0;
            for (int j = 0; j < RANDOM_REPEATS; j++)
            {
                // selecting 1 from 100 identical coins depends on the shuffle; this test will fail 1% of the time
                // run the test RANDOM_REPEATS times and only complain if all of them fail
                BOOST_CHECK(wallet.SelectCoinsMinConf(COIN, 1, 6, 0, vCoins, setCoinsRet , nValueRet));
                BOOST_CHECK(wallet.SelectCoinsMinConf(COIN, 1, 6, 0, vCoins, setCoinsRet2, nValueRet));
                if (equal_sets(setCoinsRet, setCoinsRet2))
                    fails++;
            }
            BOOST_CHECK_NE(fails, RANDOM_REPEATS);

            // add 75 cents in small change.  not enough to make 90 cents,
            // then try making 90 cents.  there are multiple competing "smallest bigger" coins,
            // one of which should be picked at random
            add_coin(5 * CENT);
            add_coin(10 * CENT);
            add_coin(15 * CENT);
            add_coin(20 * CENT);
            add_coin(25 * CENT);

            fails = 0;
            for (int j = 0; j < RANDOM_REPEATS; j++)
            {
                // selecting 1 from 100 identical coins depends on the shuffle; this test will fail 1% of the time
                // run the test RANDOM_REPEATS times and only complain if all of them fail
                BOOST_CHECK(wallet.SelectCoinsMinConf(90*CENT, 1, 6, 0, vCoins, setCoinsRet , nValueRet));
                BOOST_CHECK(wallet.SelectCoinsMinConf(90*CENT, 1, 6, 0, vCoins, setCoinsRet2, nValueRet));
                if (equal_sets(setCoinsRet, setCoinsRet2))
                    fails++;
            }
            BOOST_CHECK_NE(fails, RANDOM_REPEATS);
        }
    }
    empty_wallet();
}*/
/*
BOOST_AUTO_TEST_CASE(ApproximateBestSubset)
{
    CoinSet setCoinsRet;
    CAmount nValueRet;

    LOCK(wallet.cs_wallet);

    empty_wallet();

    // Test vValue sort order
    for (int i = 0; i < 1000; i++)
        add_coin(1000 * COIN);
    add_coin(3 * COIN);

    BOOST_CHECK(wallet.SelectCoinsMinConf(1003 * COIN, 1, 6, 0, vCoins, setCoinsRet, nValueRet));
    BOOST_CHECK_EQUAL(nValueRet, 1003 * COIN);
    BOOST_CHECK_EQUAL(setCoinsRet.size(), 2U);

    empty_wallet();
}*/

BOOST_AUTO_TEST_CASE(auto_lock_masternode_collaterals)
{
    CWallet testWallet;
    LOCK2(cs_main, testWallet.cs_wallet);

    CKey ownedKey, watchedKey, foreignKey;
    ownedKey.MakeNewKey(true);
    watchedKey.MakeNewKey(true);
    foreignKey.MakeNewKey(true);
    BOOST_REQUIRE(testWallet.AddKeyPubKey(ownedKey, ownedKey.GetPubKey()));
    const CScript ownedScript = GetScriptForDestination(ownedKey.GetPubKey().GetID());
    const CScript watchedScript = GetScriptForDestination(watchedKey.GetPubKey().GetID());
    const CScript foreignScript = GetScriptForDestination(foreignKey.GetPubKey().GetID());
    BOOST_REQUIRE(testWallet.AddWatchOnly(watchedScript, 0));

    uint32_t nonce = 0;
    const auto addOutput = [&](const CScript& script, CAmount amount, bool internal) {
        CMutableTransaction tx;
        tx.nLockTime = ++nonce;
        // The other output has the collateral amount too, but is not collateral.
        tx.vout.emplace_back(1000 * COIN, ownedScript);
        tx.vout.emplace_back(amount, script);
        if (internal) {
            tx.nVersion = 3;
            tx.nType = TRANSACTION_PROVIDER_REGISTER;
            CProRegTx proTx;
            proTx.collateralOutpoint.n = 1;
            SetTxPayload(tx, proTx);
        }
        const auto txRef = MakeTransactionRef(tx);
        // Exercise the startup scan, not AddToWallet's independent auto-locking.
        BOOST_REQUIRE(testWallet.LoadToWallet(CWalletTx(&testWallet, txRef)));
        return COutPoint(txRef->GetHash(), 1);
    };

    const auto internalOwned = addOutput(ownedScript, 1000 * COIN, true);
    const auto internalWatched = addOutput(watchedScript, 1000 * COIN, true);
    const auto internalForeign = addOutput(foreignScript, 1000 * COIN, true);
    const auto internalSpent = addOutput(ownedScript, 1000 * COIN, true);
    const auto wrongAmount = addOutput(ownedScript, 999 * COIN, true);
    const auto ordinary = addOutput(ownedScript, 1000 * COIN, false);
    const auto externalOwned = addOutput(ownedScript, 1000 * COIN, false);
    const auto externalForeign = addOutput(foreignScript, 1000 * COIN, false);
    const auto externalSpent = addOutput(ownedScript, 1000 * COIN, false);

    // Supply an MN-list snapshot in the fixture's in-memory EvoDB. These
    // ordinary transactions are collateral only through their registered MNs.
    const CBlockIndex* tip = chainActive.Tip();
    BOOST_REQUIRE(tip);
    CDeterministicMNList mnList(tip->GetBlockHash(), tip->nHeight, 3);
    for (const auto& collateral : {externalOwned, externalForeign, externalSpent}) {
        auto dmn = std::make_shared<CDeterministicMN>();
        dmn->proTxHash = SerializeHash(collateral);
        dmn->internalId = mnList.GetAllMNsCount();
        dmn->collateralOutpoint = collateral;
        dmn->nOperatorReward = 0;
        auto dmnState = std::make_shared<CDeterministicMNState>();
        CKey ownerKey;
        ownerKey.MakeNewKey(true);
        dmnState->keyIDOwner = ownerKey.GetPubKey().GetID();
        dmn->pdmnState = dmnState;
        mnList.AddMN(dmn);
    }
    evoDb->Write(std::make_pair(std::string("dmn_S"), tip->GetBlockHash()), mnList);
    deterministicMNManager->ClearCache();
    deterministicMNManager->UpdatedBlockTip(tip);
    BOOST_REQUIRE(deterministicMNManager->GetListAtChainTip().HasMNByCollateral(externalOwned));

    CMutableTransaction spend;
    spend.vin.emplace_back(internalSpent);
    spend.vin.emplace_back(externalSpent);
    spend.vout.emplace_back(1 * COIN, ownedScript);
    BOOST_REQUIRE(testWallet.LoadToWallet(CWalletTx(&testWallet, MakeTransactionRef(spend))));
    BOOST_REQUIRE(testWallet.IsSpent(internalSpent.hash, internalSpent.n));
    BOOST_REQUIRE(testWallet.IsSpent(externalSpent.hash, externalSpent.n));

    testWallet.LockCoin(ordinary); // Preserve existing manual locks as well.
    testWallet.AutoLockMasternodeCollaterals();
    std::vector<COutPoint> locked;
    testWallet.ListLockedCoins(locked);
    const std::set<COutPoint> expected{internalOwned, internalWatched, externalOwned, ordinary};
    BOOST_CHECK(std::set<COutPoint>(locked.begin(), locked.end()) == expected);
    BOOST_CHECK(!testWallet.IsLockedCoin(internalForeign.hash, internalForeign.n));
    BOOST_CHECK(!testWallet.IsLockedCoin(externalForeign.hash, externalForeign.n));
    BOOST_CHECK(!testWallet.IsLockedCoin(wrongAmount.hash, wrongAmount.n));

    testWallet.AutoLockMasternodeCollaterals();
    locked.clear();
    testWallet.ListLockedCoins(locked);
    BOOST_CHECK(std::set<COutPoint>(locked.begin(), locked.end()) == expected);
}

BOOST_FIXTURE_TEST_CASE(rescan, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex* oldTip;
    {
        LOCK(cs_main);
        oldTip = chainActive.Tip();
        GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE;
    }
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    LOCK(cs_main);
    CBlockIndex* newTip = chainActive.Tip();

    // Verify ScanForWalletTransactions picks up transactions in both the old
    // and new block files.
    {
        CWallet wallet;
        LOCK(wallet.cs_wallet);
        wallet.AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());
        BOOST_CHECK_EQUAL(oldTip, wallet.ScanForWalletTransactions(oldTip));
        BOOST_CHECK_EQUAL(wallet.GetImmatureBalance(), 80 * COIN);
    }

    // Prune the older block file.
    PruneOneBlockFile(oldTip->GetBlockPos().nFile);
    UnlinkPrunedFiles({oldTip->GetBlockPos().nFile});

    // Verify ScanForWalletTransactions only picks transactions in the new block
    // file.
    {
        CWallet wallet;
        LOCK(wallet.cs_wallet);
        wallet.AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());
        BOOST_CHECK_EQUAL(newTip, wallet.ScanForWalletTransactions(oldTip));
        BOOST_CHECK_EQUAL(wallet.GetImmatureBalance(), 40 * COIN);
    }

    // Verify importmulti RPC returns failure for a key whose creation time is
    // before the missing block, and success for a key whose creation time is
    // after.
    {
        CWallet wallet;
        CWallet *backup = ::pwalletMain;
        ::pwalletMain = &wallet;
        UniValue keys;
        keys.setArray();
        UniValue key;
        key.setObject();
        key.pushKV("scriptPubKey", HexStr(GetScriptForRawPubKey(coinbaseKey.GetPubKey())));
        key.pushKV("timestamp", 0);
        key.pushKV("internal", UniValue(true));
        keys.push_back(key);
        key.clear();
        key.setObject();
        CKey futureKey;
        futureKey.MakeNewKey(true);
        key.pushKV("scriptPubKey", HexStr(GetScriptForRawPubKey(futureKey.GetPubKey())));
        key.pushKV("timestamp", newTip->GetBlockTimeMax() + 7200);
        key.pushKV("internal", UniValue(true));
        keys.push_back(key);
        JSONRPCRequest request;
        request.params.setArray();
        request.params.push_back(keys);

        UniValue response = importmulti(request);
        BOOST_CHECK_EQUAL(response.write(), strprintf("[{\"success\":false,\"error\":{\"code\":-1,\"message\":\"Failed to rescan before time %d, transactions may be missing.\"}},{\"success\":true}]", newTip->GetBlockTimeMax()));
        ::pwalletMain = backup;
    }
}

// Verify importwallet RPC starts rescan at earliest block with timestamp
// greater or equal than key birthday. Previously there was a bug where
// importwallet RPC would start the scan at the latest block with timestamp less
// than or equal to key birthday.
BOOST_FIXTURE_TEST_CASE(importwallet_rescan, TestChain100Setup)
{
    CWallet *pwalletMainBackup = ::pwalletMain;

    // Create two blocks with same timestamp to verify that importwallet rescan
    // will pick up both blocks, not just the first.
    const int64_t BLOCK_TIME = chainActive.Tip()->GetBlockTimeMax() + 5;
    SetMockTime(BLOCK_TIME);
    coinbaseTxns.emplace_back(*CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    coinbaseTxns.emplace_back(*CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);

    // Set key birthday to block time increased by the timestamp window, so
    // rescan will start at the block time.
    const int64_t KEY_TIME = BLOCK_TIME + 7200;
    SetMockTime(KEY_TIME);
    coinbaseTxns.emplace_back(*CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);

    LOCK(cs_main);
    // Import key into wallet and call dumpwallet to create backup file.
    {
        CWallet wallet;
        CHDChain chain = wallet.GetHDChain();
        chain.nVersion = CHDChain::VERSION_WITH_BIP44;
        wallet.SetHDChain(chain, true);

        LOCK(wallet.cs_wallet);
        wallet.mapKeyMetadata[coinbaseKey.GetPubKey().GetID()].nCreateTime = KEY_TIME;
        wallet.AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());

        JSONRPCRequest request;
        request.params.setArray();
        request.params.push_back("wallet.backup");
        ::pwalletMain = &wallet;
        ::dumpwallet(request);
    }

    // Call importwallet RPC and verify all blocks with timestamps >= BLOCK_TIME
    // were scanned, and no prior blocks were scanned.
    {
        CWallet wallet;
        CHDChain chain = wallet.GetHDChain();
        chain.nVersion = CHDChain::VERSION_WITH_BIP44;
        wallet.SetHDChain(chain, true);

        JSONRPCRequest request;
        request.params.setArray();
        request.params.push_back("wallet.backup");
        ::pwalletMain = &wallet;
        ::importwallet(request);

        BOOST_CHECK_EQUAL(wallet.mapWallet.size(), 3);
        BOOST_CHECK_EQUAL(coinbaseTxns.size(), 103);
        for (size_t i = 0; i < coinbaseTxns.size(); ++i) {
            bool found = wallet.GetWalletTx(coinbaseTxns[i].GetHash());
            bool expected = i >= 100;
            BOOST_CHECK_EQUAL(found, expected);
        }
    }

    SetMockTime(0);
    ::pwalletMain = pwalletMainBackup;
}

BOOST_AUTO_TEST_SUITE_END()
