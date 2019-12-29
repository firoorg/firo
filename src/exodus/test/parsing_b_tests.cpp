#include "utils_tx.h"

#include "../createpayload.h"
#include "../exodus.h"
#include "../script.h"
#include "../tx.h"

#include "../../base58.h"
#include "../../coins.h"

#include "../../primitives/transaction.h"

#include "../../script/script.h"
#include "../../script/standard.h"

#include "../../test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <limits>
#include <vector>

#include <inttypes.h>

namespace exodus {

BOOST_FIXTURE_TEST_SUITE(exodus_parsing_b_tests, BasicTestingSetup)

/** Creates a dummy transaction with the given inputs and outputs. */
static CTransaction TxClassB(const std::vector<CTxOut>& txInputs, const std::vector<CTxOut>& txOuts)
{
    CMutableTransaction mutableTx;

    // Inputs:
    for (std::vector<CTxOut>::const_iterator it = txInputs.begin(); it != txInputs.end(); ++it)
    {
        const CTxOut& txOut = *it;

        // Create transaction for input:
        CMutableTransaction inputTx;
        unsigned int nOut = 0;
        inputTx.vout.push_back(txOut);
        CTransaction tx(inputTx);

        // Populate transaction cache:
        CCoinsModifier coins = view.ModifyCoins(tx.GetHash());

        if (nOut >= coins->vout.size()) {
            coins->vout.resize(nOut+1);
        }
        coins->vout[nOut].scriptPubKey = txOut.scriptPubKey;
        coins->vout[nOut].nValue = txOut.nValue;

        // Add input:
        CTxIn txIn(tx.GetHash(), nOut);
        mutableTx.vin.push_back(txIn);
    }

    for (std::vector<CTxOut>::const_iterator it = txOuts.begin(); it != txOuts.end(); ++it)
    {
        const CTxOut& txOut = *it;
        mutableTx.vout.push_back(txOut);
    }

    return CTransaction(mutableTx);
}

/** Helper to create a CTxOut object. */
static CTxOut createTxOut(int64_t amount, const std::string& dest)
{
    return CTxOut(amount, GetScriptForDestination(CBitcoinAddress(dest).Get()));
}

static size_t getPayloadSize(unsigned int nPackets)
{
    return CLASS_B_CHUNK_PAYLOAD_SIZE * nPackets;
}

BOOST_AUTO_TEST_CASE(valid_common_class_b)
{
    int nBlock = 0;

    std::vector<CTxOut> txInputs;
    txInputs.push_back(createTxOut(1000000, "a1SNP5FDj2HykF2Yg2Jr3Kzu8vMbyuVoyV"));
    txInputs.push_back(createTxOut(1000000, "a1YSuZWb1vvWx5Fp6oHuCXRjPDmW4nSJ4N"));
    txInputs.push_back(createTxOut(2000001, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

    std::vector<CTxOut> txOutputs;
    txOutputs.push_back(PayToPubKeyHash_Exodus());
    txOutputs.push_back(PayToBareMultisig_1of3());
    txOutputs.push_back(PayToBareMultisig_3of5());
    txOutputs.push_back(PayToBareMultisig_3of5());
    txOutputs.push_back(PayToPubKeyHash_Unrelated());

    CTransaction dummyTx = TxClassB(txInputs, txOutputs);

    CMPTransaction metaTx;
    BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) == 0);
    BOOST_CHECK_EQUAL(metaTx.getSender(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
    BOOST_CHECK_EQUAL(metaTx.getRaw().size(), getPayloadSize(10));
}

BOOST_AUTO_TEST_CASE(valid_arbitrary_output_number_class_b)
{
    int nBlock = std::numeric_limits<int>::max();

    int nOutputs = 3000 * 8; // due to the junk

    std::vector<CTxOut> txInputs;
    txInputs.push_back(createTxOut(5550000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

    std::vector<CTxOut> txOutputs;
    for (int i = 0; i < nOutputs / 8; ++i) {
        txOutputs.push_back(PayToBareMultisig_1of2());
        txOutputs.push_back(PayToBareMultisig_1of3());
        txOutputs.push_back(PayToBareMultisig_3of5());
        txOutputs.push_back(OpReturn_Unrelated());
        txOutputs.push_back(NonStandardOutput());
        txOutputs.push_back(PayToPubKey_Unrelated());
        txOutputs.push_back(PayToScriptHash_Unrelated());
        txOutputs.push_back(PayToPubKeyHash_Exodus());
    }

    std::random_shuffle(txOutputs.begin(), txOutputs.end());

    CTransaction dummyTx = TxClassB(txInputs, txOutputs);
    BOOST_CHECK_EQUAL(dummyTx.vout.size(), nOutputs);

    CMPTransaction metaTx;
    BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) == 0);
    BOOST_CHECK_EQUAL(metaTx.getSender(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
    BOOST_CHECK_EQUAL(metaTx.getRaw().size(), getPayloadSize(CLASS_B_MAX_CHUNKS));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace exodus
