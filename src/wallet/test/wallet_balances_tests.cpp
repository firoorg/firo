// Regression tests for CWallet::TryGetBalances, which computes the four GUI
// balances (available, unconfirmed, immature, mintable) in a single scan of
// mapWallet. The single-scan results must stay identical to the individual
// getters (GetBalance, GetUnconfirmedBalance, GetImmatureBalance,
// GetBalance(true)), and the exclude-locked variant of
// CWalletTx::GetAvailableCredit must leave the cached unfiltered credit
// intact.

#include "wallet/wallet.h"

#include "amount.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "txmempool.h"
#include "uint256.h"
#include "util.h"
#include "validation.h"
#include "wallet/test/wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>

#include <string>

namespace
{

struct WalletBalancesTestingSetup : public WalletTestingSetup {
    WalletBalancesTestingSetup() : WalletTestingSetup(CBaseChainParams::REGTEST)
    {
        LOCK(pwalletMain->cs_wallet);
        walletScript = GetScriptForDestination(pwalletMain->GenerateNewKey().GetID());
    }

    //! Script paying a key of the test wallet (ISMINE_SPENDABLE).
    CScript walletScript;

    //! A prevout that does not belong to the wallet, so transactions spending
    //! it have no debit and are not considered "from me".
    static COutPoint ForeignOutPoint(unsigned char tag)
    {
        return COutPoint(uint256S(strprintf("%02x", tag)), 0);
    }

    //! Insert a fabricated transaction into the wallet. If fInChain is set,
    //! anchor it in the current tip (regtest genesis) so it has depth 1; the
    //! wallet only inspects hashBlock/nIndex, not actual block membership.
    //! Requires cs_main/cs_wallet to be held.
    const CWalletTx& AddTx(const CMutableTransaction& tx, bool fInChain)
    {
        CWalletTx wtx(pwalletMain, MakeTransactionRef(tx));
        if (fInChain) {
            wtx.SetMerkleBranch(chainActive.Tip(), 0);
        }
        BOOST_REQUIRE(pwalletMain->LoadToWallet(wtx));
        // Every production insert path (SyncTransaction, CommitTransaction,
        // AbandonTransaction, MarkConflicted) marks the transactions whose
        // outputs are spent here dirty, since their available credit changes.
        // LoadToWallet is the load-from-disk path and skips that (caches are
        // empty on load), so restore the invariant by hand.
        for (const CTxIn& txin : tx.vin) {
            std::map<uint256, CWalletTx>::iterator mi = pwalletMain->mapWallet.find(txin.prevout.hash);
            if (mi != pwalletMain->mapWallet.end()) {
                mi->second.MarkDirty();
            }
        }
        return pwalletMain->mapWallet.find(wtx.GetHash())->second;
    }

    //! Requires cs_main to be held (lock order cs_main -> mempool.cs).
    void AddToMempool(const CMutableTransaction& tx)
    {
        TestMemPoolEntryHelper entry;
        BOOST_REQUIRE(mempool.addUnchecked(tx.GetHash(), entry.FromTx(tx)));
    }

    //! The regression check: TryGetBalances must report exactly what the
    //! individual getters report.
    void CheckBalancesMatchGetters(const std::string& stage)
    {
        CAmount balance = -1, unconfirmed = -1, immature = -1, mintable = -1;
        BOOST_REQUIRE_MESSAGE(pwalletMain->TryGetBalances(balance, unconfirmed, immature, mintable),
                              stage + ": TryGetBalances failed to take the wallet locks");
        BOOST_CHECK_MESSAGE(balance == pwalletMain->GetBalance(),
                            stage + strprintf(": balance %d != GetBalance() %d", balance, pwalletMain->GetBalance()));
        BOOST_CHECK_MESSAGE(unconfirmed == pwalletMain->GetUnconfirmedBalance(),
                            stage + strprintf(": unconfirmed %d != GetUnconfirmedBalance() %d", unconfirmed, pwalletMain->GetUnconfirmedBalance()));
        BOOST_CHECK_MESSAGE(immature == pwalletMain->GetImmatureBalance(),
                            stage + strprintf(": immature %d != GetImmatureBalance() %d", immature, pwalletMain->GetImmatureBalance()));
        BOOST_CHECK_MESSAGE(mintable == pwalletMain->GetBalance(true),
                            stage + strprintf(": mintable %d != GetBalance(true) %d", mintable, pwalletMain->GetBalance(true)));
    }
};

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(wallet_balances_tests, WalletBalancesTestingSetup)

BOOST_AUTO_TEST_CASE(try_get_balances_matches_individual_getters)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    CAmount balance = -1, unconfirmed = -1, immature = -1, mintable = -1;

    // Empty wallet.
    CheckBalancesMatchGetters("empty wallet");
    BOOST_REQUIRE(pwalletMain->TryGetBalances(balance, unconfirmed, immature, mintable));
    BOOST_CHECK_EQUAL(balance, 0);
    BOOST_CHECK_EQUAL(unconfirmed, 0);
    BOOST_CHECK_EQUAL(immature, 0);
    BOOST_CHECK_EQUAL(mintable, 0);

    // A confirmed transaction with two spendable outputs: trusted, so it
    // funds the available and mintable balances.
    CMutableTransaction mtxTrusted;
    mtxTrusted.vin.resize(1);
    mtxTrusted.vin[0].prevout = ForeignOutPoint(0x01);
    mtxTrusted.vout.resize(2);
    mtxTrusted.vout[0].nValue = 10 * COIN;
    mtxTrusted.vout[0].scriptPubKey = walletScript;
    mtxTrusted.vout[1].nValue = 5 * COIN;
    mtxTrusted.vout[1].scriptPubKey = walletScript;
    AddTx(mtxTrusted, true);

    CheckBalancesMatchGetters("trusted transaction");
    BOOST_REQUIRE(pwalletMain->TryGetBalances(balance, unconfirmed, immature, mintable));
    BOOST_CHECK_EQUAL(balance, 15 * COIN);
    BOOST_CHECK_EQUAL(unconfirmed, 0);
    BOOST_CHECK_EQUAL(immature, 0);
    BOOST_CHECK_EQUAL(mintable, 15 * COIN);

    // A confirmed coinbase that has not matured yet: it must show up in the
    // immature balance only, and contribute nothing to the trusted balances.
    CMutableTransaction mtxCoinbase;
    mtxCoinbase.vin.resize(1);
    mtxCoinbase.vin[0].prevout.SetNull();
    mtxCoinbase.vout.resize(1);
    mtxCoinbase.vout[0].nValue = 25 * COIN;
    mtxCoinbase.vout[0].scriptPubKey = walletScript;
    AddTx(mtxCoinbase, true);

    CheckBalancesMatchGetters("immature coinbase");
    BOOST_REQUIRE(pwalletMain->TryGetBalances(balance, unconfirmed, immature, mintable));
    BOOST_CHECK_EQUAL(balance, 15 * COIN);
    BOOST_CHECK_EQUAL(unconfirmed, 0);
    BOOST_CHECK_EQUAL(immature, 25 * COIN);
    BOOST_CHECK_EQUAL(mintable, 15 * COIN);

    // An incoming (not from us) zero-conf transaction. While it is not in the
    // mempool it must not be counted at all; once it is, it belongs to the
    // unconfirmed balance.
    CMutableTransaction mtxUnconfirmed;
    mtxUnconfirmed.vin.resize(1);
    mtxUnconfirmed.vin[0].prevout = ForeignOutPoint(0x02);
    mtxUnconfirmed.vout.resize(1);
    mtxUnconfirmed.vout[0].nValue = 3 * COIN;
    mtxUnconfirmed.vout[0].scriptPubKey = walletScript;
    AddTx(mtxUnconfirmed, false);

    CheckBalancesMatchGetters("zero-conf transaction not in mempool");
    BOOST_REQUIRE(pwalletMain->TryGetBalances(balance, unconfirmed, immature, mintable));
    BOOST_CHECK_EQUAL(balance, 15 * COIN);
    BOOST_CHECK_EQUAL(unconfirmed, 0);
    BOOST_CHECK_EQUAL(immature, 25 * COIN);
    BOOST_CHECK_EQUAL(mintable, 15 * COIN);

    AddToMempool(mtxUnconfirmed);

    CheckBalancesMatchGetters("zero-conf transaction in mempool");
    BOOST_REQUIRE(pwalletMain->TryGetBalances(balance, unconfirmed, immature, mintable));
    BOOST_CHECK_EQUAL(balance, 15 * COIN);
    BOOST_CHECK_EQUAL(unconfirmed, 3 * COIN);
    BOOST_CHECK_EQUAL(immature, 25 * COIN);
    BOOST_CHECK_EQUAL(mintable, 15 * COIN);

    // A zero-conf self-send in the mempool spending the first trusted output:
    // it is from us, so it stays trusted and its outputs replace the spent
    // output in the available balance instead of counting as unconfirmed.
    CMutableTransaction mtxSelfSend;
    mtxSelfSend.vin.resize(1);
    mtxSelfSend.vin[0].prevout = COutPoint(mtxTrusted.GetHash(), 0);
    mtxSelfSend.vout.resize(2);
    mtxSelfSend.vout[0].nValue = 6 * COIN;
    mtxSelfSend.vout[0].scriptPubKey = walletScript;
    mtxSelfSend.vout[1].nValue = 39 * COIN / 10;
    mtxSelfSend.vout[1].scriptPubKey = walletScript;
    AddTx(mtxSelfSend, false);
    AddToMempool(mtxSelfSend);

    const CAmount nExpectedBalance = 5 * COIN + 6 * COIN + 39 * COIN / 10;
    CheckBalancesMatchGetters("zero-conf self-send in mempool");
    BOOST_REQUIRE(pwalletMain->TryGetBalances(balance, unconfirmed, immature, mintable));
    BOOST_CHECK_EQUAL(balance, nExpectedBalance);
    BOOST_CHECK_EQUAL(unconfirmed, 3 * COIN);
    BOOST_CHECK_EQUAL(immature, 25 * COIN);
    BOOST_CHECK_EQUAL(mintable, nExpectedBalance);

    // Locking a coin must only reduce the mintable balance, by exactly the
    // locked output's value.
    const COutPoint lockedOutPoint(mtxTrusted.GetHash(), 1);
    pwalletMain->LockCoin(lockedOutPoint);

    CheckBalancesMatchGetters("locked coin");
    BOOST_REQUIRE(pwalletMain->TryGetBalances(balance, unconfirmed, immature, mintable));
    BOOST_CHECK_EQUAL(balance, nExpectedBalance);
    BOOST_CHECK_EQUAL(unconfirmed, 3 * COIN);
    BOOST_CHECK_EQUAL(immature, 25 * COIN);
    BOOST_CHECK_EQUAL(mintable, nExpectedBalance - 5 * COIN);

    pwalletMain->UnlockCoin(lockedOutPoint);

    CheckBalancesMatchGetters("unlocked coin");
    BOOST_REQUIRE(pwalletMain->TryGetBalances(balance, unconfirmed, immature, mintable));
    BOOST_CHECK_EQUAL(mintable, nExpectedBalance);

    // Recompute everything from scratch in both directions to make sure the
    // equality does not depend on which side populated the credit caches.
    pwalletMain->MarkDirty();
    CheckBalancesMatchGetters("fresh computation after MarkDirty");
    pwalletMain->MarkDirty();
    const CAmount nFreshBalance = pwalletMain->GetBalance();
    const CAmount nFreshMintable = pwalletMain->GetBalance(true);
    BOOST_REQUIRE(pwalletMain->TryGetBalances(balance, unconfirmed, immature, mintable));
    BOOST_CHECK_EQUAL(balance, nFreshBalance);
    BOOST_CHECK_EQUAL(mintable, nFreshMintable);
}

BOOST_AUTO_TEST_CASE(exclude_locked_scan_preserves_unfiltered_credit_cache)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = ForeignOutPoint(0x01);
    mtx.vout.resize(2);
    mtx.vout[0].nValue = 10 * COIN;
    mtx.vout[0].scriptPubKey = walletScript;
    mtx.vout[1].nValue = 5 * COIN;
    mtx.vout[1].scriptPubKey = walletScript;
    const CWalletTx& wtx = AddTx(mtx, true);

    const CAmount nUnfiltered = wtx.GetAvailableCredit();
    BOOST_CHECK_EQUAL(nUnfiltered, 15 * COIN);
    BOOST_REQUIRE(wtx.fAvailableCreditCached);
    BOOST_CHECK_EQUAL(wtx.nAvailableCreditCached, nUnfiltered);

    pwalletMain->LockCoin(COutPoint(mtx.GetHash(), 1));

    // The exclude-locked computation must skip the locked output...
    const CAmount nExcludeLocked = wtx.GetAvailableCredit(true, true);
    BOOST_CHECK_EQUAL(nExcludeLocked, 10 * COIN);

    // ...and must neither overwrite nor invalidate the cached unfiltered
    // credit while doing so (it previously clobbered the cached value and
    // then flagged the cache invalid, forcing every subsequent unfiltered
    // call to recompute from scratch).
    BOOST_CHECK(wtx.fAvailableCreditCached);
    BOOST_CHECK_EQUAL(wtx.nAvailableCreditCached, nUnfiltered);
    BOOST_CHECK_EQUAL(wtx.GetAvailableCredit(), nUnfiltered);

    // The exclude-locked variant must never be served from the cache either:
    // poison the cached value and check the filtered amount is recomputed.
    wtx.nAvailableCreditCached = nUnfiltered + 1;
    BOOST_CHECK_EQUAL(wtx.GetAvailableCredit(true, true), nExcludeLocked);
    wtx.fAvailableCreditCached = false;

    // With no coins locked the exclude-locked credit equals the unfiltered
    // credit, which is what lets TryGetBalances reuse the available credit
    // for the mintable balance.
    pwalletMain->UnlockCoin(COutPoint(mtx.GetHash(), 1));
    BOOST_CHECK_EQUAL(wtx.GetAvailableCredit(true, true), wtx.GetAvailableCredit());
}

BOOST_AUTO_TEST_SUITE_END()
