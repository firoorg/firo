// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "key.h"
#include "random.h"
#include "script/standard.h"
#include "validation.h"
#include "wallet/test/wallet_test_fixture.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

#include <boost/test/unit_test.hpp>

#include <map>
#include <set>
#include <vector>

struct WalletTxRemovalTestingSetup : public WalletTestingSetup
{
    WalletTxRemovalTestingSetup() : WalletTestingSetup(CBaseChainParams::REGTEST)
    {
        ownedScript = GetScriptForDestination(pwalletMain->vchDefaultKey.GetID());

        CKey externalKey;
        externalKey.MakeNewKey(true);
        externalScript = GetScriptForDestination(externalKey.GetPubKey().GetID());
    }

    uint256 AddWalletTx(const std::vector<COutPoint>& inputs, CAmount value, bool owned, size_t outputCount = 1)
    {
        CMutableTransaction tx;
        tx.nLockTime = nextLockTime++;
        if (inputs.empty()) {
            tx.vin.emplace_back(COutPoint(GetRandHash(), 0));
        } else {
            for (const COutPoint& input : inputs) {
                tx.vin.emplace_back(input);
            }
        }
        for (size_t i = 0; i < outputCount; ++i) {
            tx.vout.emplace_back(value, owned ? ownedScript : externalScript);
        }

        CWalletTx wtx(pwalletMain, MakeTransactionRef(std::move(tx)));
        wtx.SetMerkleBranch(chainActive.Tip(), 0);
        const uint256 hash = wtx.GetHash();
        BOOST_REQUIRE(pwalletMain->AddToWallet(wtx));
        return hash;
    }

    void RemoveWalletTx(const uint256& hash, bool zap)
    {
        if (!zap) {
            BOOST_REQUIRE(pwalletMain->EraseFromWallet(hash));
            return;
        }

        std::vector<uint256> requested{hash};
        std::vector<uint256> removed;
        BOOST_REQUIRE_EQUAL(pwalletMain->ZapSelectTx(requested, removed), DB_LOAD_OK);
        BOOST_REQUIRE_EQUAL(removed.size(), 1U);
        BOOST_CHECK(removed.front() == hash);
    }

    static bool IsAvailable(CWallet& wallet, const COutPoint& outpoint)
    {
        std::vector<COutput> coins;
        wallet.AvailableCoins(coins, true, nullptr, false, false);
        for (const COutput& coin : coins) {
            if (coin.tx->GetHash() == outpoint.hash && coin.i >= 0 && static_cast<uint32_t>(coin.i) == outpoint.n) {
                return true;
            }
        }
        return false;
    }

    bool IsAvailable(const COutPoint& outpoint) const
    {
        return IsAvailable(*pwalletMain, outpoint);
    }

    static bool HasWalletUTXO(const CWallet& wallet, const COutPoint& outpoint)
    {
        return wallet.setWalletUTXO.count(outpoint);
    }

    static void CheckOrderedIndex(const CWallet& wallet)
    {
        std::map<const CWalletTx*, size_t> references;
        size_t transactionEntries = 0;
        for (const auto& item : wallet.wtxOrdered) {
            if (item.second.first) {
                ++references[item.second.first];
                ++transactionEntries;
            }
        }

        BOOST_CHECK_EQUAL(transactionEntries, wallet.mapWallet.size());
        for (const auto& item : wallet.mapWallet) {
            BOOST_CHECK_EQUAL(references[&item.second], 1U);
        }
    }

    void CheckRemoval(bool zap)
    {
        uint256 deletedParent;
        uint256 survivingChild;
        uint256 grandparent;
        uint256 competingParent;
        uint256 historyReplacement;
        uint256 historyTx;
        uint256 onlyParent;
        uint256 secondOnlyParent;
        uint256 onlySpender;
        std::set<uint256> deleted;
        CAmount expectedBalance;

        {
            LOCK2(cs_main, pwalletMain->cs_wallet);

            onlyParent = AddWalletTx({}, 11 * COIN, true);
            secondOnlyParent = AddWalletTx({}, 13 * COIN, true);
            onlySpender = AddWalletTx({COutPoint(onlyParent, 0), COutPoint(secondOnlyParent, 0)}, 10 * COIN, false);
            BOOST_CHECK_EQUAL(pwalletMain->mapWallet.at(onlyParent).GetAvailableCredit(), 0);
            BOOST_CHECK_EQUAL(pwalletMain->mapWallet.at(secondOnlyParent).GetAvailableCredit(), 0);
            BOOST_CHECK(pwalletMain->HasWalletSpend(onlyParent));
            BOOST_CHECK(pwalletMain->HasWalletSpend(secondOnlyParent));
            BOOST_CHECK(!pwalletMain->setWalletUTXO.count(COutPoint(onlyParent, 0)));
            BOOST_CHECK(!pwalletMain->setWalletUTXO.count(COutPoint(secondOnlyParent, 0)));
        }

        RemoveWalletTx(onlySpender, zap);
        deleted.insert(onlySpender);

        {
            LOCK2(cs_main, pwalletMain->cs_wallet);

            BOOST_CHECK(!pwalletMain->HasWalletSpend(onlyParent));
            BOOST_CHECK(!pwalletMain->HasWalletSpend(secondOnlyParent));
            BOOST_CHECK_EQUAL(pwalletMain->mapWallet.at(onlyParent).GetAvailableCredit(), 11 * COIN);
            BOOST_CHECK_EQUAL(pwalletMain->mapWallet.at(secondOnlyParent).GetAvailableCredit(), 13 * COIN);
            BOOST_CHECK(pwalletMain->setWalletUTXO.count(COutPoint(onlyParent, 0)));
            BOOST_CHECK(pwalletMain->setWalletUTXO.count(COutPoint(secondOnlyParent, 0)));
            BOOST_CHECK(IsAvailable(COutPoint(onlyParent, 0)));
            BOOST_CHECK(IsAvailable(COutPoint(secondOnlyParent, 0)));

            competingParent = AddWalletTx({}, 20 * COIN, true);
            const uint256 firstSpender = AddWalletTx({COutPoint(competingParent, 0)}, 19 * COIN, false);
            const uint256 secondSpender = AddWalletTx({COutPoint(competingParent, 0)}, 18 * COIN, false);
            BOOST_CHECK(pwalletMain->GetConflicts(firstSpender) == (std::set<uint256>{firstSpender, secondSpender}));
            BOOST_CHECK_EQUAL(pwalletMain->mapWallet.at(competingParent).GetAvailableCredit(), 0);

            RemoveWalletTx(firstSpender, zap);
            deleted.insert(firstSpender);
            BOOST_CHECK(pwalletMain->HasWalletSpend(competingParent));
            BOOST_CHECK(pwalletMain->IsSpent(competingParent, 0));
            BOOST_CHECK(pwalletMain->GetConflicts(secondSpender).empty());
            BOOST_CHECK_EQUAL(pwalletMain->mapWallet.at(competingParent).GetAvailableCredit(), 0);
            BOOST_CHECK(!pwalletMain->setWalletUTXO.count(COutPoint(competingParent, 0)));

            RemoveWalletTx(secondSpender, zap);
            deleted.insert(secondSpender);
            BOOST_CHECK(!pwalletMain->HasWalletSpend(competingParent));
            BOOST_CHECK(!pwalletMain->IsSpent(competingParent, 0));
            BOOST_CHECK_EQUAL(pwalletMain->mapWallet.at(competingParent).GetAvailableCredit(), 20 * COIN);
            BOOST_CHECK(pwalletMain->setWalletUTXO.count(COutPoint(competingParent, 0)));
            BOOST_CHECK(IsAvailable(COutPoint(competingParent, 0)));

            grandparent = AddWalletTx({}, 30 * COIN, true);
            deletedParent = AddWalletTx({COutPoint(grandparent, 0)}, 29 * COIN, true);
            survivingChild = AddWalletTx({COutPoint(deletedParent, 0)}, 28 * COIN, false);
            BOOST_CHECK_EQUAL(pwalletMain->mapWallet.at(grandparent).GetAvailableCredit(), 0);

            RemoveWalletTx(deletedParent, zap);
            deleted.insert(deletedParent);
            BOOST_CHECK(!pwalletMain->HasWalletSpend(grandparent));
            BOOST_CHECK(pwalletMain->HasWalletSpend(deletedParent));
            BOOST_CHECK(pwalletMain->mapWallet.count(survivingChild));
            BOOST_CHECK_EQUAL(pwalletMain->mapWallet.at(grandparent).GetAvailableCredit(), 30 * COIN);
            BOOST_CHECK(pwalletMain->setWalletUTXO.count(COutPoint(grandparent, 0)));
            BOOST_CHECK(IsAvailable(COutPoint(grandparent, 0)));

            historyTx = AddWalletTx({}, 5 * COIN, true, 2);
            const CWalletTx* const historyPtr = &pwalletMain->mapWallet.at(historyTx);
            BOOST_CHECK(pwalletMain->setWalletUTXO.count(COutPoint(historyTx, 0)));
            BOOST_CHECK(pwalletMain->setWalletUTXO.count(COutPoint(historyTx, 1)));
            RemoveWalletTx(historyTx, zap);
            deleted.insert(historyTx);
            BOOST_CHECK(!pwalletMain->setWalletUTXO.count(COutPoint(historyTx, 0)));
            BOOST_CHECK(!pwalletMain->setWalletUTXO.count(COutPoint(historyTx, 1)));
            for (const auto& item : pwalletMain->wtxOrdered) {
                BOOST_CHECK(item.second.first != historyPtr);
            }

            historyReplacement = AddWalletTx({}, 7 * COIN, true);
            CheckOrderedIndex(*pwalletMain);
            expectedBalance = pwalletMain->GetBalance();
            BOOST_CHECK_EQUAL(expectedBalance, 81 * COIN);
        }

        CWallet reloaded(pwalletMain->strWalletFile);
        bool firstRun = false;
        BOOST_REQUIRE_EQUAL(reloaded.LoadWallet(firstRun), DB_LOAD_OK);
        {
            LOCK2(cs_main, reloaded.cs_wallet);
            for (const uint256& hash : deleted) {
                BOOST_CHECK(!reloaded.mapWallet.count(hash));
            }
            BOOST_CHECK(reloaded.mapWallet.count(survivingChild));
            BOOST_CHECK(reloaded.mapWallet.count(historyReplacement));
            BOOST_CHECK(reloaded.HasWalletSpend(deletedParent));
            BOOST_CHECK(!reloaded.HasWalletSpend(grandparent));
            BOOST_CHECK(!reloaded.HasWalletSpend(competingParent));
            BOOST_CHECK(HasWalletUTXO(reloaded, COutPoint(onlyParent, 0)));
            BOOST_CHECK(HasWalletUTXO(reloaded, COutPoint(secondOnlyParent, 0)));
            BOOST_CHECK(HasWalletUTXO(reloaded, COutPoint(competingParent, 0)));
            BOOST_CHECK(HasWalletUTXO(reloaded, COutPoint(grandparent, 0)));
            BOOST_CHECK(!HasWalletUTXO(reloaded, COutPoint(deletedParent, 0)));
            BOOST_CHECK(!HasWalletUTXO(reloaded, COutPoint(historyTx, 0)));
            BOOST_CHECK(!HasWalletUTXO(reloaded, COutPoint(historyTx, 1)));
            BOOST_CHECK(IsAvailable(reloaded, COutPoint(onlyParent, 0)));
            BOOST_CHECK(IsAvailable(reloaded, COutPoint(secondOnlyParent, 0)));
            BOOST_CHECK(IsAvailable(reloaded, COutPoint(competingParent, 0)));
            BOOST_CHECK(IsAvailable(reloaded, COutPoint(grandparent, 0)));
            BOOST_CHECK_EQUAL(reloaded.GetBalance(), expectedBalance);
            CheckOrderedIndex(reloaded);
        }
    }

    unsigned int nextLockTime{1};
    CScript ownedScript;
    CScript externalScript;
};

BOOST_FIXTURE_TEST_SUITE(wallet_tx_removal_tests, WalletTxRemovalTestingSetup)

BOOST_AUTO_TEST_CASE(erase_from_wallet_cleans_indexes)
{
    CheckRemoval(false);
}

BOOST_AUTO_TEST_CASE(zap_select_tx_cleans_indexes)
{
    CheckRemoval(true);
}

BOOST_AUTO_TEST_CASE(zap_select_tx_db_failure_keeps_memory)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    const uint256 hash = AddWalletTx({}, 5 * COIN, true);
    const uint256 secondHash = AddWalletTx({}, 7 * COIN, true);
    const COutPoint output(hash, 0);
    const COutPoint secondOutput(secondHash, 0);

    CWalletDB walletdb(pwalletMain->strWalletFile, "r+");
    BOOST_REQUIRE(walletdb.TxnBegin());
    std::vector<uint256> requested{hash, secondHash};
    const uint256 sentinel = GetRandHash();
    std::vector<uint256> removed{sentinel};
    const DBErrors result = walletdb.ZapSelectTx(pwalletMain, requested, removed);
    BOOST_REQUIRE(walletdb.TxnAbort());

    BOOST_CHECK_EQUAL(result, DB_CORRUPT);
    BOOST_REQUIRE_EQUAL(removed.size(), 1U);
    BOOST_CHECK(removed.front() == sentinel);
    BOOST_CHECK(pwalletMain->mapWallet.count(hash));
    BOOST_CHECK(pwalletMain->mapWallet.count(secondHash));
    BOOST_CHECK(HasWalletUTXO(*pwalletMain, output));
    BOOST_CHECK(HasWalletUTXO(*pwalletMain, secondOutput));
    BOOST_CHECK(!pwalletMain->HasWalletSpend(hash));
    BOOST_CHECK_EQUAL(pwalletMain->mapWallet.at(hash).GetAvailableCredit(), 5 * COIN);
    CheckOrderedIndex(*pwalletMain);
}

BOOST_AUTO_TEST_SUITE_END()
