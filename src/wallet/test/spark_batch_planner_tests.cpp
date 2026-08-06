// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "wallet/sparkbatchplanner.h"

#include <boost/test/unit_test.hpp>

namespace {

spark::BatchPlanLimits DefaultLimits()
{
    spark::BatchPlanLimits limits;
    limits.maxTransactions = 50;
    limits.maxPrivateOutputs = 14;
    limits.maxTransparentAmount = 10'000;
    limits.maxFee = 1'000;
    limits.maxMoney = MAX_MONEY;
    limits.maxWeight = 1'000'000;
    limits.weightScaleFactor = 4;
    return limits;
}

} // namespace

BOOST_AUTO_TEST_SUITE(spark_batch_planner_tests)

BOOST_AUTO_TEST_CASE(single_input_size_matches_wallet_model)
{
    BOOST_CHECK_EQUAL(spark::EstimateSingleInputSparkSize(0, 0), 3'049U);
    BOOST_CHECK_EQUAL(spark::EstimateSingleInputSparkSize(2, 3), 3'795U);
}

BOOST_AUTO_TEST_CASE(single_coin_funds_single_recipient)
{
    const spark::BatchPlanLimits limits = DefaultLimits();

    const std::vector<CAmount> coins{1'000};
    const std::vector<spark::BatchRecipient> recipients{{500, false, 100}};
    const auto result = spark::PlanSingleInputSpend(
        coins,
        recipients,
        limits,
        [](size_t, size_t) { return CAmount{10}; },
        [](size_t, size_t) { return 100U; });

    BOOST_CHECK(result.status == spark::BatchPlanStatus::OK);
    BOOST_REQUIRE_EQUAL(result.batches.size(), 1U);
    BOOST_CHECK_EQUAL(result.batches.front().coinIndex, 0U);
    BOOST_CHECK_EQUAL(result.batches.front().fee, 10);
    BOOST_REQUIRE_EQUAL(result.batches.front().fragments.size(), 1U);
    BOOST_CHECK_EQUAL(result.batches.front().fragments.front().recipientIndex, 0U);
    BOOST_CHECK_EQUAL(result.batches.front().fragments.front().amount, 500);
}

BOOST_AUTO_TEST_CASE(single_coin_funds_mixed_recipients_and_keeps_surplus)
{
    const spark::BatchPlanLimits limits = DefaultLimits();

    const std::vector<CAmount> coins{2'000};
    const std::vector<spark::BatchRecipient> recipients{
        {400, true, 1}, {500, false, 1}};
    const auto result = spark::PlanSingleInputSpend(
        coins,
        recipients,
        limits,
        [](size_t privateOutputs, size_t transparentOutputs) {
            return static_cast<CAmount>(10 * (privateOutputs + transparentOutputs));
        },
        spark::EstimateSingleInputSparkSize);

    BOOST_CHECK(result.status == spark::BatchPlanStatus::OK);
    BOOST_REQUIRE_EQUAL(result.batches.size(), 1U);
    const spark::SingleInputBatch& batch = result.batches.front();
    BOOST_CHECK_EQUAL(batch.coinIndex, 0U);
    BOOST_CHECK_EQUAL(batch.amount, 900);
    BOOST_CHECK_EQUAL(batch.fee, 20);
    BOOST_CHECK_EQUAL(batch.privateOutputs, 1U);
    BOOST_CHECK_EQUAL(batch.transparentOutputs, 1U);
    BOOST_REQUIRE_EQUAL(batch.fragments.size(), 2U);
}

BOOST_AUTO_TEST_CASE(insufficient_single_coin_returns_no_partial_plan)
{
    const spark::BatchPlanLimits limits = DefaultLimits();

    const std::vector<CAmount> coins{1'000};
    const std::vector<spark::BatchRecipient> recipients{{1'001, false, 1}};
    const auto result = spark::PlanSingleInputSpend(
        coins,
        recipients,
        limits,
        [](size_t, size_t) { return CAmount{10}; },
        [](size_t, size_t) { return 100U; });

    BOOST_CHECK(result.status == spark::BatchPlanStatus::INSUFFICIENT_FUNDS);
    BOOST_CHECK(result.batches.empty());
}

BOOST_AUTO_TEST_CASE(transparent_remainder_is_not_dust)
{
    const spark::BatchPlanLimits limits = DefaultLimits();

    const std::vector<CAmount> coins{1'000, 1'000};
    const std::vector<spark::BatchRecipient> recipients{{991, false, 100}};
    const auto result = spark::PlanSingleInputSpend(
        coins,
        recipients,
        limits,
        [](size_t, size_t) { return CAmount{10}; },
        [](size_t, size_t) { return 100U; });

    BOOST_CHECK(result.status == spark::BatchPlanStatus::OK);
    BOOST_REQUIRE_EQUAL(result.batches.size(), 2U);
    CAmount total = 0;
    for (const auto& batch : result.batches) {
        BOOST_REQUIRE_EQUAL(batch.fragments.size(), 1U);
        BOOST_CHECK_GE(batch.fragments.front().amount, 100);
        total += batch.fragments.front().amount;
    }
    BOOST_CHECK_EQUAL(total, 991);
}

BOOST_AUTO_TEST_CASE(private_remainder_respects_configured_minimum)
{
    const spark::BatchPlanLimits limits = DefaultLimits();
    const std::vector<CAmount> coins{1'000, 1'000};
    const std::vector<spark::BatchRecipient> recipients{{991, true, 100}};
    const auto result = spark::PlanSingleInputSpend(
        coins,
        recipients,
        limits,
        [](size_t, size_t) { return CAmount{10}; },
        [](size_t, size_t) { return 100U; });

    BOOST_CHECK(result.status == spark::BatchPlanStatus::OK);
    BOOST_REQUIRE_EQUAL(result.batches.size(), 2U);
    for (const auto& batch : result.batches) {
        BOOST_REQUIRE_EQUAL(batch.fragments.size(), 1U);
        BOOST_CHECK_GE(batch.fragments.front().amount, 100);
    }
}

BOOST_AUTO_TEST_CASE(transparent_limit_is_applied_per_transaction)
{
    spark::BatchPlanLimits limits = DefaultLimits();
    limits.maxTransparentAmount = 700;

    const std::vector<CAmount> coins{1'000, 1'000};
    const std::vector<spark::BatchRecipient> recipients{{1'200, false, 100}};
    const auto result = spark::PlanSingleInputSpend(
        coins,
        recipients,
        limits,
        [](size_t, size_t) { return CAmount{10}; },
        [](size_t, size_t) { return 100U; });

    BOOST_CHECK(result.status == spark::BatchPlanStatus::OK);
    BOOST_REQUIRE_EQUAL(result.batches.size(), 2U);
    CAmount total = 0;
    for (const auto& batch : result.batches) {
        BOOST_CHECK_LE(batch.transparentAmount, limits.maxTransparentAmount);
        total += batch.transparentAmount;
    }
    BOOST_CHECK_EQUAL(total, 1'200);
}

BOOST_AUTO_TEST_CASE(private_output_limit_starts_a_new_transaction)
{
    spark::BatchPlanLimits limits = DefaultLimits();
    limits.maxPrivateOutputs = 2;

    const std::vector<CAmount> coins{1'000, 1'000};
    const std::vector<spark::BatchRecipient> recipients{
        {100, true, 1}, {100, true, 1}, {100, true, 1}};
    const auto result = spark::PlanSingleInputSpend(
        coins,
        recipients,
        limits,
        [](size_t, size_t) { return CAmount{10}; },
        [](size_t, size_t) { return 100U; });

    BOOST_CHECK(result.status == spark::BatchPlanStatus::OK);
    BOOST_REQUIRE_EQUAL(result.batches.size(), 2U);
    BOOST_CHECK_EQUAL(result.batches[0].privateOutputs, 2U);
    BOOST_CHECK_EQUAL(result.batches[1].privateOutputs, 1U);
}

BOOST_AUTO_TEST_CASE(final_fee_is_repriced_for_every_output)
{
    const spark::BatchPlanLimits limits = DefaultLimits();
    const std::vector<CAmount> coins{1'000};
    const std::vector<spark::BatchRecipient> recipients{
        {400, false, 1}, {400, false, 1}};
    const auto result = spark::PlanSingleInputSpend(
        coins,
        recipients,
        limits,
        [](size_t privateOutputs, size_t transparentOutputs) {
            return static_cast<CAmount>(10 * (privateOutputs + transparentOutputs));
        },
        [](size_t, size_t) { return 100U; });

    BOOST_CHECK(result.status == spark::BatchPlanStatus::OK);
    BOOST_REQUIRE_EQUAL(result.batches.size(), 1U);
    BOOST_CHECK_EQUAL(result.batches.front().amount, 800);
    BOOST_CHECK_EQUAL(result.batches.front().fee, 20);
}

BOOST_AUTO_TEST_CASE(transaction_limit_fails_without_a_partial_plan)
{
    spark::BatchPlanLimits limits = DefaultLimits();
    limits.maxTransactions = 2;

    const std::vector<CAmount> coins{100, 100, 100};
    const std::vector<spark::BatchRecipient> recipients{{250, false, 1}};
    const auto result = spark::PlanSingleInputSpend(
        coins,
        recipients,
        limits,
        [](size_t, size_t) { return CAmount{10}; },
        [](size_t, size_t) { return 100U; });

    BOOST_CHECK(result.status == spark::BatchPlanStatus::TOO_MANY_TRANSACTIONS);
    BOOST_CHECK(result.batches.empty());
}

BOOST_AUTO_TEST_SUITE_END()
