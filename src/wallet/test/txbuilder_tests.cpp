#include "../txbuilder.h"
#include "../../amount.h"
#include "../../random.h"

#include "wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>

#include <functional>
#include <vector>

static const CBitcoinAddress randomAddr1("aHEog3QYDGa8wH4Go9igKLDFkpaMsi3btq");
static const CBitcoinAddress randomAddr2("aLTSv7QbTZbkgorYEhbNx2gH4hGYNLsoGv");

class TestInputSigner : public InputSigner
{
public:
    CScript signature;

public:
    TestInputSigner()
    {
    }

    explicit TestInputSigner(const CScript& sig, const COutPoint& output = COutPoint(), uint32_t seq = CTxIn::SEQUENCE_FINAL) :
        InputSigner(output, seq),
        signature(sig)
    {
    }

    CScript Sign(const CMutableTransaction& tx, const uint256& sig) override
    {
        return signature;
    }
};

class TestTxBuilder : public TxBuilder
{
public:
    std::vector<CAmount> amountsRequested;
    std::vector<CAmount> changesRequested;
    std::vector<std::pair<CAmount, unsigned>> adjustFeeRequested;

    std::function<CAmount(std::vector<std::unique_ptr<InputSigner>>& signers, CAmount required)> getInputs;
    std::function<CAmount(std::vector<CTxOut>& outputs, CAmount amount)> getChanges;
    std::function<CAmount(CAmount needed, unsigned txSize)> adjustFee;

public:
    explicit TestTxBuilder(CWallet& wallet) : TxBuilder(wallet)
    {
    }

protected:
    CAmount GetInputs(std::vector<std::unique_ptr<InputSigner>>& signers, CAmount required) override
    {
        amountsRequested.push_back(required);

        return getInputs ? getInputs(signers, required) : required;
    }

    CAmount GetChanges(std::vector<CTxOut>& outputs, CAmount amount) override
    {
        changesRequested.push_back(amount);

        return getChanges ? getChanges(outputs, amount) : amount;
    }

    CAmount AdjustFee(CAmount needed, unsigned txSize) override
    {
        adjustFeeRequested.push_back(std::make_pair(needed, txSize));

        return adjustFee ? adjustFee(needed, txSize) : TxBuilder::AdjustFee(needed, txSize);
    }
};

BOOST_FIXTURE_TEST_SUITE(wallet_txbuilder_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(build_with_empty_recipients)
{
    TestTxBuilder builder(*pwalletMain);
    CAmount fee;
    bool fChangeAddedToFee;
    BOOST_CHECK_EXCEPTION(
        builder.Build({}, fee, fChangeAddedToFee),
        std::invalid_argument,
        [](const std::invalid_argument& e) { return e.what() == std::string("No recipients"); }
    );
}

BOOST_AUTO_TEST_CASE(build_with_some_recipients_have_negative_amount)
{
    TestTxBuilder builder(*pwalletMain);
    CAmount fee;

    std::vector<CRecipient> recipients = {
        {.scriptPubKey = GetScriptForDestination(randomAddr1.Get()), .nAmount = 10, .fSubtractFeeFromAmount = false},
        {.scriptPubKey = GetScriptForDestination(randomAddr2.Get()), .nAmount = -5, .fSubtractFeeFromAmount = false}
    };
    bool fChangeAddedToFee;
    BOOST_CHECK_EXCEPTION(
        builder.Build(recipients, fee, fChangeAddedToFee),
        std::invalid_argument,
        [](const std::invalid_argument& e) { return e.what() == std::string("Recipient 1 has invalid amount"); }
    );
}

BOOST_AUTO_TEST_CASE(build_with_some_recipients_have_amount_exceed_limit)
{
    TestTxBuilder builder(*pwalletMain);
    CAmount fee;

    std::vector<CRecipient> recipients = {
        {.scriptPubKey = GetScriptForDestination(randomAddr1.Get()), .nAmount = MAX_MONEY + 1, .fSubtractFeeFromAmount = false},
        {.scriptPubKey = GetScriptForDestination(randomAddr2.Get()), .nAmount = 1, .fSubtractFeeFromAmount = false}
    };

    bool fChangeAddedToFee;
    BOOST_CHECK_EXCEPTION(
        builder.Build(recipients, fee, fChangeAddedToFee),
        std::invalid_argument,
        [](const std::invalid_argument& e) { return e.what() == std::string("Recipient 0 has invalid amount"); }
    );
}

BOOST_AUTO_TEST_CASE(build_with_no_subtract_fee)
{
    TestTxBuilder builder(*pwalletMain);
    CAmount fee;

    std::vector<CRecipient> recipients = {
        {.scriptPubKey = GetScriptForDestination(randomAddr1.Get()), .nAmount = 10, .fSubtractFeeFromAmount = false},
        {.scriptPubKey = GetScriptForDestination(randomAddr2.Get()), .nAmount = 20, .fSubtractFeeFromAmount = false}
    };
    bool fChangeAddedToFee;
    auto tx = builder.Build(recipients, fee, fChangeAddedToFee);

    BOOST_CHECK_GT(fee, 0);
    BOOST_CHECK_GT(builder.amountsRequested.size(), 0);
    BOOST_CHECK_EQUAL(builder.amountsRequested.back(), 30 + fee);

    BOOST_CHECK_EQUAL(tx.vout.size(), 2);
    BOOST_CHECK(tx.vout[0].scriptPubKey == GetScriptForDestination(randomAddr1.Get()));
    BOOST_CHECK_EQUAL(tx.vout[0].nValue, 10);
    BOOST_CHECK(tx.vout[1].scriptPubKey == GetScriptForDestination(randomAddr2.Get()));
    BOOST_CHECK_EQUAL(tx.vout[1].nValue, 20);
}

BOOST_AUTO_TEST_CASE(build_with_subtract_fee)
{
    TestTxBuilder builder(*pwalletMain);
    CAmount fee;

    std::vector<CRecipient> recipients = {
        {.scriptPubKey = GetScriptForDestination(randomAddr1.Get()), .nAmount = 10, .fSubtractFeeFromAmount = true},
        {.scriptPubKey = GetScriptForDestination(randomAddr2.Get()), .nAmount = 20, .fSubtractFeeFromAmount = true}
    };

    bool fChangeAddedToFee;
    auto tx = builder.Build(recipients, fee, fChangeAddedToFee);

    BOOST_CHECK_GT(fee, 0);
    BOOST_CHECK_GT(builder.amountsRequested.size(), 0);
    BOOST_CHECK_EQUAL(builder.amountsRequested.back(), 30);

    BOOST_CHECK_EQUAL(tx.vout.size(), 2);
    BOOST_CHECK(tx.vout[0].scriptPubKey == GetScriptForDestination(randomAddr1.Get()));
    BOOST_CHECK_EQUAL(tx.vout[0].nValue, 10 - (fee / 2 + fee % 2));
    BOOST_CHECK(tx.vout[1].scriptPubKey == GetScriptForDestination(randomAddr2.Get()));
    BOOST_CHECK_EQUAL(tx.vout[1].nValue, 20 - fee / 2);
}

BOOST_AUTO_TEST_CASE(build_with_changes)
{
    TestTxBuilder builder(*pwalletMain);
    CAmount fee;
    CScript in1, in2;
    COutPoint out1(GetRandHash(), 0), out2(GetRandHash(), 1);

    in1 << std::vector<unsigned char>({ 0x21, 0xe3, 0xad, 0x9a, 0xec, 0x5b, 0x70, 0xcb, 0x4c, 0xc1, 0xd8, 0xe2, 0x95, 0x27, 0xe3, 0x7c });
    in2 << std::vector<unsigned char>({ 0xac, 0xd9, 0x86, 0x7d, 0xd7, 0x6e, 0xc1, 0xb7, 0x9d, 0xde, 0xdc, 0xbd, 0x91, 0xc1, 0x8e, 0xed });

    builder.getInputs = [&in1, &in2, &out1, &out2](std::vector<std::unique_ptr<InputSigner>>& signers, CAmount required) {
        signers.push_back(std::unique_ptr<InputSigner>(new TestInputSigner(in1, out1, 1)));
        signers.push_back(std::unique_ptr<InputSigner>(new TestInputSigner(in2, out2, 2)));
        return required + 5;
    };

    builder.getChanges = [](std::vector<CTxOut>& outputs, CAmount amount) {
        outputs.emplace_back(amount - 1, CScript());
        return 1;
    };

    std::vector<CRecipient> recipients = {
        {.scriptPubKey = GetScriptForDestination(randomAddr1.Get()), .nAmount = 10, .fSubtractFeeFromAmount = false},
        {.scriptPubKey = GetScriptForDestination(randomAddr2.Get()), .nAmount = 20, .fSubtractFeeFromAmount = false}
    };
    bool fChangeAddedToFee;
    auto tx = builder.Build(recipients, fee, fChangeAddedToFee);

    BOOST_CHECK_GT(fee, 0);
    BOOST_CHECK_GT(builder.amountsRequested.size(), 0);
    BOOST_CHECK_EQUAL(builder.amountsRequested.back(), 30 + fee - 1);

    BOOST_CHECK_GT(builder.changesRequested.size(), 0);

    for (auto& call : builder.changesRequested) {
        BOOST_CHECK_EQUAL(call, 5);
    }

    BOOST_CHECK_GT(builder.adjustFeeRequested.size(), 0);

    for (auto& call : builder.adjustFeeRequested) {
        BOOST_CHECK_GT(call.first, 0);
        BOOST_CHECK_GT(call.second, 0);
    }

    BOOST_CHECK_EQUAL(tx.vin.size(), 2);
    BOOST_CHECK(tx.vin[0].scriptSig == in1);
    BOOST_CHECK(tx.vin[0].prevout == out1);
    BOOST_CHECK_EQUAL(tx.vin[0].nSequence, 1);
    BOOST_CHECK(tx.vin[1].scriptSig == in2);
    BOOST_CHECK(tx.vin[1].prevout == out2);
    BOOST_CHECK_EQUAL(tx.vin[1].nSequence, 2);

    BOOST_CHECK_EQUAL(tx.vout.size(), 3);
    BOOST_CHECK(std::find_if(tx.vout.begin(), tx.vout.end(), [](const CTxOut& o) { return o.nValue == 4; }) != tx.vout.end());
    BOOST_CHECK(std::find_if(tx.vout.begin(), tx.vout.end(), [](const CTxOut& o) { return o.nValue == 10; }) != tx.vout.end());
    BOOST_CHECK(std::find_if(tx.vout.begin(), tx.vout.end(), [](const CTxOut& o) { return o.nValue == 20; }) != tx.vout.end());
}

BOOST_AUTO_TEST_SUITE_END()

