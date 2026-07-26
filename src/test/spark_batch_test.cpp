#include "../batchproof_container.h"
#include "../spark/state.h"
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

    BatchProofContainer* container = BatchProofContainer::get_instance();

    // An empty pending batch trivially verifies.
    BOOST_CHECK(container->verify_pending());

    // With batching active the spend must be deferred into the container
    // instead of being verified inline.
    auto collectSpend = [&]() {
        LOCK(cs_main);
        CValidationState state;
        spark::CSparkTxInfo info;
        container->fCollectProofs = true;
        container->init();
        BOOST_CHECK(spark::CheckSparkTransaction(
            spendTx, state, spendTx.GetHash(), false, chainActive.Height(), false, true, &info));
        container->finalize();
    };
    collectSpend();

    // The pending batch holds a valid proof and verifies successfully.
    BOOST_CHECK(container->verify_pending());
    // A successful batch is cleared; re-verification stays true.
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
