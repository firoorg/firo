#include "../batchproof_container.h"
#include "../spark/state.h"
#include "../validation.h"
#include "../wallet/wallet.h"
#include "fixtures.h"
#include "test_bitcoin.h"
#include "../ui_interface.h"

#include <boost/test/unit_test.hpp>
#include <atomic>
#include <chrono>
#include <future>

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
    std::atomic<bool> timedOut{false};
    boost::signals2::scoped_connection pause = uiInterface.UpdateProgressBarLabel.connect(
        [&](const std::string&) {
            if (snapshots.fetch_add(1) == 0) {
                started.set_value();
                timedOut = released.wait_for(std::chrono::seconds(10)) != std::future_status::ready;
            }
        });
    auto first = std::async(std::launch::async, [&] { return container->verify_pending(); });
    const bool paused = ready.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
    BOOST_CHECK(paused);
    if (paused) {
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
    pause.disconnect();
    BOOST_CHECK(!BatchProofContainer::HasRecoveryMarker());

    // An allocation failure must leave the pending batch available to retry.
    BOOST_REQUIRE(collect(secondSpend));
    snapshots = 0;
    boost::signals2::scoped_connection failOnce = uiInterface.UpdateProgressBarLabel.connect(
        [&](const std::string&) {
            if (snapshots.fetch_add(1) == 0)
                throw std::bad_alloc();
        });
    BOOST_CHECK_THROW(container->verify_pending(), std::bad_alloc);
    BOOST_CHECK(BatchProofContainer::HasRecoveryMarker());
    BOOST_CHECK(container->verify_pending());
    BOOST_CHECK_EQUAL(snapshots.load(), 2);
    BOOST_CHECK(!BatchProofContainer::HasRecoveryMarker());
}

BOOST_AUTO_TEST_SUITE_END()
