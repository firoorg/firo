// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "wallet/wallet.h"

#include "amount.h"
#include "base58.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "txmempool.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "wallet/test/wallet_test_fixture.h"

#include <boost/lexical_cast.hpp>
#include <boost/test/unit_test.hpp>

#include <fstream>
#include <vector>

extern UniValue addmultisigaddress(const JSONRPCRequest& request);
extern UniValue importwallet(const JSONRPCRequest& request);

namespace
{

struct WalletBalancesTestingSetup : public WalletTestingSetup
{
    WalletBalancesTestingSetup() : WalletTestingSetup(CBaseChainParams::REGTEST)
    {
        LOCK(pwalletMain->cs_wallet);
        walletPubKey = pwalletMain->GenerateNewKey();
        walletScript = GetScriptForDestination(walletPubKey.GetID());
    }

    static COutPoint ForeignOutPoint(unsigned char tag)
    {
        return COutPoint(uint256S(strprintf("%02x", tag)), 0);
    }

    const CWalletTx& AddTx(const CMutableTransaction& tx, bool inChain, bool abandoned = false)
    {
        CWalletTx wtx(pwalletMain, MakeTransactionRef(tx));
        if (inChain) {
            wtx.SetMerkleBranch(chainActive.Tip(), 0);
        } else if (abandoned) {
            wtx.setAbandoned();
        }
        // Exercise the runtime path used by direct imports, not the
        // cache-empty LoadToWallet database-loading path.
        BOOST_REQUIRE(pwalletMain->AddToWallet(wtx, false));
        std::map<uint256, CWalletTx>::const_iterator it = pwalletMain->mapWallet.find(wtx.GetHash());
        BOOST_REQUIRE(it != pwalletMain->mapWallet.end());
        return it->second;
    }

    void AddToMempool(const CMutableTransaction& tx)
    {
        TestMemPoolEntryHelper entry;
        BOOST_REQUIRE(mempool.addUnchecked(tx.GetHash(), entry.FromTx(tx)));
    }

    void CheckBalances(CAmount expectedBalance,
                       CAmount expectedUnconfirmed,
                       CAmount expectedImmature,
                       CAmount expectedMintable)
    {
        CAmount balance = -1;
        CAmount unconfirmed = -1;
        CAmount immature = -1;
        CAmount mintable = -1;
        BOOST_REQUIRE(pwalletMain->TryGetBalances(balance, unconfirmed, immature, mintable));
        BOOST_CHECK_EQUAL(balance, expectedBalance);
        BOOST_CHECK_EQUAL(unconfirmed, expectedUnconfirmed);
        BOOST_CHECK_EQUAL(immature, expectedImmature);
        BOOST_CHECK_EQUAL(mintable, expectedMintable);
        BOOST_CHECK_EQUAL(balance, pwalletMain->GetBalance());
        BOOST_CHECK_EQUAL(unconfirmed, pwalletMain->GetUnconfirmedBalance());
        BOOST_CHECK_EQUAL(immature, pwalletMain->GetImmatureBalance());
        BOOST_CHECK_EQUAL(mintable, pwalletMain->GetBalance(true));
    }

    CPubKey walletPubKey;
    CScript walletScript;
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(wallet_balances_tests, WalletBalancesTestingSetup)

BOOST_AUTO_TEST_CASE(try_get_balances_matches_individual_getters)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    CheckBalances(0, 0, 0, 0);

    CMutableTransaction trusted;
    trusted.vin.resize(1);
    trusted.vin[0].prevout = ForeignOutPoint(1);
    trusted.vout.resize(2);
    trusted.vout[0] = CTxOut(10 * COIN, walletScript);
    trusted.vout[1] = CTxOut(5 * COIN, walletScript);
    AddTx(trusted, true);
    CheckBalances(15 * COIN, 0, 0, 15 * COIN);

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.resize(1);
    coinbase.vout[0] = CTxOut(25 * COIN, walletScript);
    AddTx(coinbase, true);
    CheckBalances(15 * COIN, 0, 25 * COIN, 15 * COIN);

    CMutableTransaction unconfirmed;
    unconfirmed.vin.resize(1);
    unconfirmed.vin[0].prevout = ForeignOutPoint(2);
    unconfirmed.vout.resize(1);
    unconfirmed.vout[0] = CTxOut(3 * COIN, walletScript);
    AddTx(unconfirmed, false);
    CheckBalances(15 * COIN, 0, 25 * COIN, 15 * COIN);

    AddToMempool(unconfirmed);
    CheckBalances(15 * COIN, 3 * COIN, 25 * COIN, 15 * COIN);

    const COutPoint lockedOutpoint(trusted.GetHash(), 1);
    pwalletMain->LockCoin(lockedOutpoint);
    CheckBalances(15 * COIN, 3 * COIN, 25 * COIN, 10 * COIN);

    pwalletMain->UnlockCoin(lockedOutpoint);
    CheckBalances(15 * COIN, 3 * COIN, 25 * COIN, 15 * COIN);
}

BOOST_AUTO_TEST_CASE(exclude_locked_credit_preserves_unfiltered_cache)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = ForeignOutPoint(1);
    tx.vout.resize(2);
    tx.vout[0] = CTxOut(10 * COIN, walletScript);
    tx.vout[1] = CTxOut(5 * COIN, walletScript);
    const CWalletTx& wtx = AddTx(tx, true);

    BOOST_CHECK_EQUAL(wtx.GetAvailableCredit(false, false), 15 * COIN);
    BOOST_REQUIRE(wtx.fAvailableCreditCached);
    BOOST_CHECK_EQUAL(wtx.GetAvailableCredit(true, false), 15 * COIN);

    pwalletMain->LockCoin(COutPoint(tx.GetHash(), 1));
    BOOST_CHECK_EQUAL(wtx.GetAvailableCredit(true, true), 10 * COIN);
    BOOST_CHECK(wtx.fAvailableCreditCached);
    BOOST_CHECK_EQUAL(wtx.nAvailableCreditCached, 15 * COIN);

    wtx.nAvailableCreditCached = 1;
    BOOST_CHECK_EQUAL(wtx.GetAvailableCredit(false, true), 10 * COIN);
    BOOST_CHECK(wtx.fAvailableCreditCached);
    BOOST_CHECK_EQUAL(wtx.nAvailableCreditCached, 1);

    BOOST_CHECK_EQUAL(wtx.GetAvailableCredit(false, false), 15 * COIN);
    BOOST_CHECK_EQUAL(wtx.GetAvailableCredit(true, false), 15 * COIN);
}

BOOST_AUTO_TEST_CASE(add_to_wallet_invalidates_input_credit)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    CMutableTransaction parent;
    parent.vin.resize(1);
    parent.vin[0].prevout = ForeignOutPoint(1);
    parent.vout.resize(1);
    parent.vout[0] = CTxOut(10 * COIN, walletScript);
    const CWalletTx& parentWtx = AddTx(parent, true);
    BOOST_CHECK_EQUAL(parentWtx.GetAvailableCredit(), 10 * COIN);

    CMutableTransaction child;
    child.vin.resize(1);
    child.vin[0].prevout = COutPoint(parent.GetHash(), 0);
    child.vout.resize(1);
    child.vout[0] = CTxOut(9 * COIN, walletScript);
    AddTx(child, true);

    BOOST_CHECK(pwalletMain->IsSpent(parent.GetHash(), 0));
    BOOST_CHECK(!parentWtx.fAvailableCreditCached);
    CheckBalances(9 * COIN, 0, 0, 9 * COIN);
}

BOOST_AUTO_TEST_CASE(add_to_wallet_update_invalidates_input_credit)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    CMutableTransaction parent;
    parent.vin.resize(1);
    parent.vin[0].prevout = ForeignOutPoint(1);
    parent.vout.resize(1);
    parent.vout[0] = CTxOut(10 * COIN, walletScript);
    const CWalletTx& parentWtx = AddTx(parent, true);

    CMutableTransaction child;
    child.vin.resize(1);
    child.vin[0].prevout = COutPoint(parent.GetHash(), 0);
    child.vout.resize(1);
    child.vout[0] = CTxOut(9 * COIN, walletScript);
    AddTx(child, false, true);
    BOOST_CHECK(!pwalletMain->IsSpent(parent.GetHash(), 0));
    BOOST_CHECK_EQUAL(parentWtx.GetAvailableCredit(), 10 * COIN);

    CWalletTx confirmedChild(pwalletMain, MakeTransactionRef(child));
    confirmedChild.SetMerkleBranch(chainActive.Tip(), 0);
    BOOST_REQUIRE(pwalletMain->AddToWallet(confirmedChild, false));

    BOOST_CHECK(pwalletMain->IsSpent(parent.GetHash(), 0));
    BOOST_CHECK(!parentWtx.fAvailableCreditCached);
    CheckBalances(9 * COIN, 0, 0, 9 * COIN);
}

BOOST_AUTO_TEST_CASE(erase_from_wallet_invalidates_cached_balances)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    CMutableTransaction parent;
    parent.vin.resize(1);
    parent.vin[0].prevout = ForeignOutPoint(1);
    parent.vout.resize(1);
    parent.vout[0] = CTxOut(10 * COIN, walletScript);
    const CWalletTx& parentWtx = AddTx(parent, true);

    CMutableTransaction child;
    child.vin.resize(1);
    child.vin[0].prevout = COutPoint(parent.GetHash(), 0);
    child.vout.resize(1);
    child.vout[0] = CTxOut(9 * COIN, walletScript);
    AddTx(child, true);
    BOOST_CHECK_EQUAL(parentWtx.GetAvailableCredit(), 0);

    BOOST_REQUIRE(pwalletMain->EraseFromWallet(child.GetHash()));
    BOOST_CHECK(!pwalletMain->IsSpent(parent.GetHash(), 0));
    BOOST_CHECK(!parentWtx.fAvailableCreditCached);
    CheckBalances(10 * COIN, 0, 0, 10 * COIN);
}

BOOST_AUTO_TEST_CASE(addmultisigaddress_invalidates_cached_ownership)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    const CScript redeemScript = GetScriptForMultisig(1, std::vector<CPubKey>{walletPubKey});
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = ForeignOutPoint(1);
    tx.vout.resize(2);
    tx.vout[0] = CTxOut(1 * COIN, walletScript);
    tx.vout[1] = CTxOut(7 * COIN, GetScriptForDestination(CScriptID(redeemScript)));
    const CWalletTx& wtx = AddTx(tx, true);
    BOOST_CHECK_EQUAL(wtx.GetAvailableCredit(), 1 * COIN);

    UniValue keys(UniValue::VARR);
    keys.push_back(HexStr(walletPubKey));
    JSONRPCRequest request;
    request.params = UniValue(UniValue::VARR);
    request.params.push_back(1);
    request.params.push_back(keys);
    addmultisigaddress(request);

    BOOST_CHECK(!wtx.fAvailableCreditCached);
    CheckBalances(8 * COIN, 0, 0, 8 * COIN);
}

BOOST_AUTO_TEST_CASE(keypool_generation_invalidates_cached_ownership)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    const CPubKey masterPubKey = pwalletMain->GenerateNewHDMasterKey();
    BOOST_REQUIRE(pwalletMain->SetHDMasterKey(masterPubKey, CHDChain::VERSION_WITH_BIP44));
    BOOST_REQUIRE(pwalletMain->NewKeyPool());

    CKey futureKey;
    const uint32_t nextChild = pwalletMain->GetHDChain().nExternalChainCounters[0];
    const CPubKey futurePubKey = pwalletMain->GetKeyFromKeypath(0, nextChild, futureKey);
    BOOST_REQUIRE(!pwalletMain->HaveKey(futurePubKey.GetID()));

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = ForeignOutPoint(1);
    tx.vout.resize(2);
    tx.vout[0] = CTxOut(1 * COIN, walletScript);
    tx.vout[1] = CTxOut(7 * COIN, GetScriptForDestination(futurePubKey.GetID()));
    const CWalletTx& wtx = AddTx(tx, true);
    BOOST_CHECK_EQUAL(wtx.GetAvailableCredit(), 1 * COIN);

    BOOST_REQUIRE(pwalletMain->TopUpKeyPool());
    BOOST_REQUIRE(pwalletMain->HaveKey(futurePubKey.GetID()));
    BOOST_CHECK(!wtx.fAvailableCreditCached);
    CheckBalances(8 * COIN, 0, 0, 8 * COIN);
}

BOOST_AUTO_TEST_CASE(importwallet_partial_failure_invalidates_cached_ownership)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    const CPubKey masterPubKey = pwalletMain->GenerateNewHDMasterKey();
    BOOST_REQUIRE(pwalletMain->SetHDMasterKey(masterPubKey, CHDChain::VERSION_WITH_BIP44));

    CKey importedKey;
    importedKey.MakeNewKey(true);
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = ForeignOutPoint(1);
    tx.vout.resize(2);
    tx.vout[0] = CTxOut(1 * COIN, walletScript);
    tx.vout[1] = CTxOut(7 * COIN, GetScriptForDestination(importedKey.GetPubKey().GetID()));
    const CWalletTx& wtx = AddTx(tx, true);
    BOOST_CHECK_EQUAL(wtx.GetAvailableCredit(), 1 * COIN);

    CKey malformedKey;
    malformedKey.MakeNewKey(true);
    const auto dumpPath = pathTemp / "partial-import.dump";
    {
        std::ofstream dump(dumpPath.string());
        BOOST_REQUIRE(dump.is_open());
        dump << CBitcoinSecret(importedKey).ToString() << " 1970-01-01T00:00:01Z\n";
        dump << CBitcoinSecret(malformedKey).ToString()
             << " 1970-01-01T00:00:01Z hdKeypath=m/44'/136'/0'/x/0\n";
    }

    JSONRPCRequest request;
    request.params = UniValue(UniValue::VARR);
    request.params.push_back(dumpPath.string());
    BOOST_CHECK_THROW(importwallet(request), boost::bad_lexical_cast);

    BOOST_REQUIRE(pwalletMain->HaveKey(importedKey.GetPubKey().GetID()));
    BOOST_CHECK(!wtx.fAvailableCreditCached);
    CheckBalances(8 * COIN, 0, 0, 8 * COIN);
}

BOOST_AUTO_TEST_SUITE_END()
