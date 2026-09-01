#include "../batchproof_container.h"
#include "../spark/state.h"
#include "../ui_interface.h"
#include "../validation.h"
#include "../wallet/wallet.h"
#include "fixtures.h"
#include "test_bitcoin.h"

#include <boost/test/unit_test.hpp>

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
    auto addValidSpend = [&]() {
        LOCK(cs_main);
        CValidationState state;
        spark::CSparkTxInfo info;
        BOOST_CHECK(spark::CheckSparkTransaction(
            spendTx, state, spendTx.GetHash(), false, chainActive.Height(), false, true, &info));
    };
    auto collectSpend = [&]() {
        container->init(true);
        addValidSpend();
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

    // Replacing the deferred batch while its snapshot is being verified must
    // retry and fail on the replacement, not clear or validate it from the
    // old snapshot's verdict.
    container->init(true);
    addValidSpend();
    container->finalize();
    bool fReplacementAdded = false;
    bool fReplaced = false;
    boost::signals2::scoped_connection replaceBatch(
        uiInterface.UpdateProgressBarLabel.connect(
            [&](const std::string&) {
                if (fReplaced)
                    return;
                fReplaced = true;
                container->init(true);
                fReplacementAdded = container->add(
                    invalidSpend, spendTxB.GetHash());
                container->finalize();
            }));
    BOOST_CHECK(!container->verify_pending());
    replaceBatch.disconnect();
    BOOST_REQUIRE(fReplaced);
    BOOST_REQUIRE(fReplacementAdded);
    container->remove(invalidSpend);
    BOOST_CHECK(container->verify_pending());

    // Recent blocks verify collected proofs per block without touching the
    // deferred cross-block batch.
    container->init(true, false);
    addValidSpend();
    BOOST_CHECK(container->verify_block_batch());
    BOOST_CHECK(container->verify_block_batch());
    BOOST_CHECK(container->verify_pending());

    container->init(true, false);
    BOOST_REQUIRE(container->add(invalidSpend, spendTxB.GetHash()));
    BOOST_CHECK(!container->verify_block_batch());
    BOOST_CHECK(container->verify_block_batch());
    BOOST_CHECK(container->verify_pending());

    // Checking a pending batch while collection is active must not close the
    // collection window. Otherwise a proof can be skipped without being
    // enqueued at the old-to-recent batching boundary.
    container->init(true);
    BOOST_CHECK(container->verify_pending());
    BOOST_CHECK(container->add(invalidSpend, spendTxB.GetHash()));
    container->finalize();
    BOOST_CHECK(!container->verify_pending());
    container->remove(invalidSpend);
    BOOST_CHECK(container->verify_pending());

    collectSpend();
    container->init(true);
    BOOST_REQUIRE(container->add(invalidSpend, spendTxB.GetHash()));
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

BOOST_AUTO_TEST_SUITE_END()
