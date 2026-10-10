#include "../batchproof_container.h"
#include "../spark/state.h"
#include "../validation.h"
#include "../wallet/wallet.h"
#include "fixtures.h"
#include "test_bitcoin.h"
#include "../ui_interface.h"
#include "../txdb.h"
#include "../warnings.h"

#include <boost/test/unit_test.hpp>
#include <atomic>
#include <chrono>
#include <future>

extern std::atomic<bool> fRequestShutdown;
extern std::string strMiscWarning;

BOOST_FIXTURE_TEST_SUITE(spark_batch_tests, SparkTestingSetup)

BOOST_AUTO_TEST_CASE(spark_batch_fail_closed)
{
    GenerateBlocks(501);

    std::vector<CMutableTransaction> mintTxs;
    GenerateMints({10 * COIN, 20 * COIN}, mintTxs);
    GenerateBlock(mintTxs);
    GenerateBlocks(6);

    std::vector<CRecipient> recipients = {{GetScriptForDestination(GenerateAddress().GetID()), 1 * COIN, false}};
    CAmount fee;
    auto result = pwalletMain->CreateSparkSpendTransaction(recipients, {}, fee, nullptr);
    CTransaction spendTx(*result.tx);

    // A second, larger spend selects the 20 FIRO mint instead of the 10 FIRO
    // mint used by the first spend, so its lTag set is guaranteed to differ.
    std::vector<CRecipient> recipientsB = {{GetScriptForDestination(GenerateAddress().GetID()), 15 * COIN, false}};
    CAmount feeB;
    auto resultB = pwalletMain->CreateSparkSpendTransaction(recipientsB, {}, feeB, nullptr);
    CTransaction spendTxB(*resultB.tx);

    BatchProofContainer* container = BatchProofContainer::get_instance();

    // An empty pending batch trivially verifies.
    BOOST_CHECK(container->verify_pending());

    // With batching active the spend must be deferred into the container
    // instead of being verified inline.
    auto collectSpend = [&]() {
        LOCK(cs_main);
        CValidationState state;
        spark::CSparkTxInfo info;
        container->init(BatchProofContainer::Mode::Deferred);
        BOOST_CHECK(spark::CheckSparkTransaction(
            spendTx, state, spendTx.GetHash(), false, chainActive.Height(), false, true, &info));
        container->finalize();
    };
    collectSpend();

    // The pending batch holds a valid proof and verifies successfully.
    BOOST_CHECK(container->verify_pending());
    // A successful batch is cleared; re-verification stays true.
    BOOST_CHECK(container->verify_pending());

    // A raw-parsed spend lacks the out-coin/cover-set/vout data the binding
    // hash commits to, so its Chaum proof can never verify: an invalid batch
    // member whose serialized lTags still identify it for removal.
    spark::SpendTransaction invalidSpend = spark::ParseSparkSpend(spendTxB);
    invalidSpend.setVout(0);
    BOOST_REQUIRE(invalidSpend.getUsedLTags() != spark::ParseSparkSpend(spendTx).getUsedLTags());

    collectSpend();
    container->init(BatchProofContainer::Mode::Deferred);
    container->add(invalidSpend, spendTxB.GetHash());
    container->finalize();

    // A batch holding a valid and an invalid proof fails and latches.
    BOOST_CHECK(!container->verify_pending());
    BOOST_CHECK(!container->verify_pending());

    // Removing only the offending spend (as a disconnect would) clears the
    // latch even though the batch stays non-empty: the remaining valid proof
    // must verify again.
    container->remove(invalidSpend);
    BOOST_CHECK(container->verify_pending());

    // Re-collect the same spend, then wipe the Spark state so the cover sets
    // it references can no longer be built: verification must fail closed.
    collectSpend();
    spark::CSparkState::GetState()->Reset();
    BOOST_CHECK(!container->verify_pending());

    // The failed batch is retained and keeps failing.
    BOOST_CHECK(!container->verify_pending());

    // Only removing the offending spend (as a disconnect would) empties the
    // batch and lets verification pass again.
    container->remove(spark::ParseSparkSpend(spendTx));
    BOOST_CHECK(container->verify_pending());
}

BOOST_AUTO_TEST_CASE(spark_batch_concurrent_verification)
{
    GenerateBlocks(501);
    std::vector<CMutableTransaction> mintTxs;
    GenerateMints({10 * COIN, 20 * COIN}, mintTxs);
    GenerateBlock(mintTxs);
    GenerateBlocks(6);

    CAmount fee;
    const CTransaction firstSpend(*pwalletMain->CreateSparkSpendTransaction(
        {{GetScriptForDestination(GenerateAddress().GetID()), COIN, false}}, {}, fee, nullptr).tx);
    const CTransaction secondSpend(*pwalletMain->CreateSparkSpendTransaction(
        {{GetScriptForDestination(GenerateAddress().GetID()), 15 * COIN, false}}, {}, fee, nullptr).tx);
    auto* container = BatchProofContainer::get_instance();
    auto collect = [&](const CTransaction& tx) {
        LOCK(cs_main);
        CValidationState state;
        spark::CSparkTxInfo info;
        container->init(BatchProofContainer::Mode::Deferred);
        const bool collected = spark::CheckSparkTransaction(
            tx, state, tx.GetHash(), false, chainActive.Height(), false, true, &info);
        container->finalize();
        return collected;
    };
    BOOST_REQUIRE(collect(firstSpend));

    std::promise<void> started, release, secondStarted;
    auto ready = started.get_future();
    auto released = release.get_future();
    auto secondReady = secondStarted.get_future();
    std::atomic<int> snapshots{0};
    std::atomic<int> clears{0};
    std::atomic<bool> timedOut{false};
    // Count only verification starts; each run also clears the label on exit.
    boost::signals2::scoped_connection pause = uiInterface.UpdateProgressBarLabel.connect(
        [&](const std::string& label) {
            if (label.empty()) {
                ++clears;
                return;
            }
            if (label != "Batch verifying Spark Proofs...") {
                return;
            }
            if (snapshots.fetch_add(1) == 0) {
                started.set_value();
                timedOut = released.wait_for(std::chrono::seconds(10)) != std::future_status::ready;
            }
        });
    auto first = std::async(std::launch::async, [&] { return container->verify_pending(); });
    const bool paused = ready.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
    BOOST_CHECK(paused);
    if (paused) {
        // A recent block can verify while the deferred batch is active, but
        // must not overwrite or clear its progress label.
        {
            LOCK(cs_main);
            CValidationState state;
            spark::CSparkTxInfo info;
            container->init(BatchProofContainer::Mode::Block);
            BOOST_CHECK(spark::CheckSparkTransaction(
                secondSpend, state, secondSpend.GetHash(), false, chainActive.Height(), false, true, &info));
            BOOST_CHECK(container->verify_block_batch());
        }
        BOOST_CHECK_EQUAL(snapshots.load(), 1);
        BOOST_CHECK_EQUAL(clears.load(), 0);

        // Verification releases cs_main, and a disconnect can still remove the
        // retained proof. Replace it with a different, equally-sized batch.
        container->remove(spark::ParseSparkSpend(firstSpend));
        BOOST_CHECK(collect(secondSpend));
    }
    auto second = std::async(std::launch::async, [&] {
        secondStarted.set_value();
        return container->verify_pending();
    });
    secondReady.wait();
    BOOST_CHECK(second.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout);
    BOOST_CHECK(BatchProofContainer::HasRecoveryMarker());
    release.set_value();
    BOOST_CHECK(first.get());
    BOOST_CHECK(second.get());
    BOOST_CHECK(!timedOut);
    BOOST_CHECK_EQUAL(snapshots.load(), 2);
    BOOST_CHECK_EQUAL(clears.load(), 2);
    pause.disconnect();
    BOOST_CHECK(!BatchProofContainer::HasRecoveryMarker());

    // An allocation failure must leave the pending batch available to retry.
    BOOST_REQUIRE(collect(secondSpend));
    snapshots = 0;
    clears = 0;
    boost::signals2::scoped_connection failOnce = uiInterface.UpdateProgressBarLabel.connect(
        [&](const std::string& label) {
            if (label.empty()) {
                ++clears;
                return;
            }
            if (label != "Batch verifying Spark Proofs...") {
                return;
            }
            if (snapshots.fetch_add(1) == 0)
                throw std::bad_alloc();
        });
    BOOST_CHECK_THROW(container->verify_pending(), std::bad_alloc);
    BOOST_CHECK_EQUAL(clears.load(), 1);
    BOOST_CHECK(BatchProofContainer::HasRecoveryMarker());
    BOOST_CHECK(container->verify_pending());
    BOOST_CHECK_EQUAL(snapshots.load(), 2);
    BOOST_CHECK_EQUAL(clears.load(), 2);
    BOOST_CHECK(!BatchProofContainer::HasRecoveryMarker());
}

BOOST_AUTO_TEST_CASE(reindex_shutdown_recovery_marker)
{
    GenerateBlocks(501);
    std::vector<CMutableTransaction> mintTxs;
    GenerateMints({10 * COIN, 20 * COIN}, mintTxs);
    GenerateBlock(mintTxs);
    GenerateBlocks(6);
    CAmount fee;
    const CTransaction spend(*pwalletMain->CreateSparkSpendTransaction(
        {{GetScriptForDestination(GenerateAddress().GetID()), COIN, false}}, {}, fee, nullptr).tx);
    auto* container = BatchProofContainer::get_instance();

    struct RestoreState
    {
        CCoinsView& backend;
        bool reindex = fReindex;
        bool shutdown = fRequestShutdown.load();
        std::string warning = strMiscWarning;
        ~RestoreState()
        {
            pcoinsTip->SetBackend(backend);
            pblocktree->WriteReindexing(false);
            fReindex = reindex;
            fRequestShutdown = shutdown;
            SetMiscWarning(warning);
        }
    } restore{*pcoinsdbview};
    const auto flushForShutdown = [](bool allowReindexResume) {
        BatchProofContainer::get_instance()->finalize();
        CValidationState state;
        const bool verified = VerifyPendingSparkBatch(state, "shutdown");
        LOCK(cs_main);
        const bool flushed = FlushStateToDiskForShutdown(allowReindexResume && verified);
        return verified && flushed;
    };
    fReindex = true;
    BOOST_REQUIRE(pblocktree->WriteReindexing(true));
    const auto tip = chainActive.Tip()->GetBlockHash();
    {
        LOCK(cs_main);
        container->init(BatchProofContainer::Mode::Deferred);
        CValidationState state;
        spark::CSparkTxInfo info;
        BOOST_REQUIRE(spark::CheckSparkTransaction(
            spend, state, spend.GetHash(), false, chainActive.Height(), false, true, &info));
        container->finalize();
    }
    BOOST_REQUIRE(BatchProofContainer::HasRecoveryMarker());
    BOOST_CHECK(container->verify_pending());
    BOOST_CHECK(BatchProofContainer::HasRecoveryMarker());
    // Early startup failure must not authorize resuming an unchecked import.
    BOOST_CHECK(flushForShutdown(false));
    BOOST_CHECK(BatchProofContainer::HasRecoveryMarker());
    // A marker-forced, unbatched recovery must stay unbatched across shutdown.
    {
        struct RestoreBatching
        {
            std::string value = GetArg("-batching", "1");
            ~RestoreBatching() { ForceSetArg("-batching", value); }
        } restoreBatching;
        ForceSetArg("-batching", "0");
        BOOST_CHECK(flushForShutdown(true));
        BOOST_CHECK(BatchProofContainer::HasRecoveryMarker());
        BOOST_CHECK(pcoinsdbview->GetBestBlock() == tip);
    }
    BOOST_CHECK(flushForShutdown(true));
    BOOST_CHECK(!BatchProofContainer::HasRecoveryMarker());
    BOOST_CHECK(pcoinsdbview->GetBestBlock() == tip);
    bool reindexing = false;
    BOOST_REQUIRE(pblocktree->ReadReindexing(reindexing));
    BOOST_CHECK(reindexing);
    BOOST_CHECK(fReindex);

    // A failed proof must keep recovery enabled even when the database flush works.
    auto invalidSpend = spark::ParseSparkSpend(spend);
    invalidSpend.setVout(0);
    container->init(BatchProofContainer::Mode::Deferred);
    container->add(invalidSpend, spend.GetHash());
    container->finalize();
    BOOST_CHECK(!flushForShutdown(true));
    BOOST_CHECK(BatchProofContainer::HasRecoveryMarker());
    container->remove(invalidSpend);
    BOOST_CHECK(flushForShutdown(true));
    BOOST_CHECK(!BatchProofContainer::HasRecoveryMarker());

    container->init(BatchProofContainer::Mode::Deferred);
    container->finalize();
    const COutPoint lostCoin(uint256S("01"), 0);
    BOOST_REQUIRE(!pcoinsdbview->HaveCoin(lostCoin));
    pcoinsTip->AddCoin(lostCoin, Coin(CTxOut(COIN, CScript() << OP_TRUE), chainActive.Height(), false), false);
    struct FailedFlush : CCoinsViewBacked
    {
        FailedFlush(CCoinsView* view) : CCoinsViewBacked(view) {}
        bool BatchWrite(CCoinsMap& coins, const uint256&) override
        {
            BOOST_CHECK(BatchProofContainer::HasRecoveryMarker());
            BOOST_CHECK(!coins.empty());
            // CCoinsViewDB consumes dirty entries before writing its batch.
            coins.clear();
            return false;
        }
    } failedFlush(pcoinsdbview);
    pcoinsTip->SetBackend(failedFlush);
    // A runtime flush failure must remain fatal to resume even if shutdown's
    // subsequent flush succeeds with the now-empty cache.
    FlushStateToDisk();
    BOOST_CHECK(BatchProofContainer::HasRecoveryMarker());
    pcoinsTip->SetBackend(*pcoinsdbview);

    BOOST_CHECK(container->verify_pending());
    BOOST_CHECK(BatchProofContainer::HasRecoveryMarker());
    BOOST_CHECK(flushForShutdown(true));
    BOOST_CHECK(BatchProofContainer::HasRecoveryMarker());
    BOOST_CHECK(!pcoinsdbview->HaveCoin(lostCoin));
}

BOOST_AUTO_TEST_SUITE_END()
