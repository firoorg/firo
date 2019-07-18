#include "exodus/createtx.h"
#include "exodus/errors.h"
#include "exodus/encoding.h"
#include "exodus/exodus.h"
#include "exodus/tx.h"
#include "exodus/wallettxs.h"

#include "base58.h"
#include "coins.h"
#include "core_io.h"
#include "main.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "test/fixtures.h"
#include "utilstrencodings.h"

#include "exodus/createpayload.h"
#include "exodus/convert.h"

#include "exodus/utilsbitcoin.h"

#include "wallet/wallet.h"

#include <boost/test/unit_test.hpp>

#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

/**
 * Pushes bytes to the end of a vector.
 */
#define PUSH_BACK_BYTES(vector, value)\
    vector.insert(vector.end(), reinterpret_cast<unsigned char *>(&(value)),\
    reinterpret_cast<unsigned char *>(&(value)) + sizeof((value)));

BOOST_FIXTURE_TEST_SUITE(exodus_handler_tx_tests, ZerocoinTestingSetup200)

static std::vector<unsigned char> createMockSpendPayload()
{
    std::vector<unsigned char> payload;

    uint16_t messageType = 1024;
    uint16_t messageVer = 0;
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder16(messageType);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);

    return payload;
}

CBlock getHeighestBlock()
{
    CBlock block;
    auto idx = chainActive.Tip();
    BOOST_CHECK(ReadBlockFromDisk(block, idx, Params().GetConsensus()));
    return block;
}

BOOST_AUTO_TEST_CASE(exodus_parse_normal_tx)
{
    pwalletMain->SetBroadcastTransactions(true);
    std::string fromAddress = CBitcoinAddress(pubkey.GetID()).ToString();

    auto ecosystem = 2; // test
    auto type = 1; // indivisible
    auto previousId = 0; // new token
    CAmount amount(1);

    std::vector<unsigned char> payload = CreatePayload_IssuanceFixed(
        ecosystem, type, previousId, "Companies", "", "non-sigma", "", "", amount
    );

    uint256 txid;
    std::string rawHex;
    BOOST_CHECK_EQUAL(
        0, // No error
        exodus::WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, true)
    );

    CreateAndProcessBlock({}, scriptPubKey);
    auto block = getHeighestBlock();
    BOOST_CHECK_EQUAL(2, block.vtx.size());

    CTransaction exodusTx = block.vtx[1];
    CMPTransaction mp_obj;

    BOOST_CHECK_EQUAL(0, ParseTransaction(exodusTx, chainActive.Height(), 1, mp_obj, block.GetBlockTime()));
}

BOOST_AUTO_TEST_CASE(exodus_parse_normal_tx_with_spend)
{
    pwalletMain->SetBroadcastTransactions(true);
    std::string fromAddress = CBitcoinAddress(pubkey.GetID()).ToString();

    auto ecosystem = 2; // test
    auto type = 1; // indivisible
    auto previousId = 0; // new token
    CAmount amount(1);

    std::vector<unsigned char> payload = createMockSpendPayload();

    uint256 txid;
    std::string rawHex;
    BOOST_CHECK_EQUAL(
        0, // No error
        exodus::WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, true)
    );

    CreateAndProcessBlock({}, scriptPubKey);

    auto block = getHeighestBlock();
    BOOST_CHECK_EQUAL(2, block.vtx.size());

    CTransaction exodusTx = block.vtx[1];
    CMPTransaction mp_obj;

    BOOST_CHECK_EQUAL(0, ParseTransaction(exodusTx, chainActive.Height(), 1, mp_obj, block.GetBlockTime()));
}

BOOST_AUTO_TEST_CASE(exodus_parse_sigma_tx_with_non_spend)
{
    pwalletMain->SetBroadcastTransactions(true);
    CreateAndProcessEmptyBlocks(200, scriptPubKey);

    string stringError;
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
            stringError, {{"1", 10}}, SIGMA), stringError + " - Create Mint failed");

    CreateAndProcessBlock({}, scriptPubKey);
    CreateAndProcessEmptyBlocks(5, scriptPubKey);

    auto ecosystem = 2; // test
    auto type = 1; // indivisible
    auto previousId = 0; // new token
    CAmount amount(1);

    std::vector<unsigned char> payload = CreatePayload_IssuanceFixed(
        ecosystem, type, previousId, "Companies", "", "non-sigma", "", "", amount
    );

    uint256 txid;
    std::string rawHex;
    BOOST_CHECK_EQUAL(
        0, // No error
        exodus::WalletTxBuilder("", "", "", 0, payload, txid, rawHex, true, exodus::InputMode::SIGMA)
    );

    CreateAndProcessBlock({}, scriptPubKey);

    auto block = getHeighestBlock();
    BOOST_CHECK_EQUAL(2, block.vtx.size());

    CTransaction sigmaTx = block.vtx[1];
    CMPTransaction mp_obj;

    BOOST_CHECK_EQUAL(0, ParseTransaction(sigmaTx, chainActive.Height(), 1, mp_obj, block.GetBlockTime()));
}

BOOST_AUTO_TEST_CASE(exodus_parse_sigma_tx_with_spend)
{
    pwalletMain->SetBroadcastTransactions(true);
    CreateAndProcessEmptyBlocks(200, scriptPubKey);

    string stringError;
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
            stringError, {{"1", 10}}, SIGMA), stringError + " - Create Mint failed");

    CreateAndProcessBlock({}, scriptPubKey);
    CreateAndProcessEmptyBlocks(5, scriptPubKey);

    std::vector<unsigned char> data = createMockSpendPayload();

    uint256 txid;
    std::string rawHex;
    BOOST_CHECK_EQUAL(
        0, // No error
        exodus::WalletTxBuilder("", "", "", 0, data, txid, rawHex, true, exodus::InputMode::SIGMA)
    );

    CreateAndProcessBlock({}, scriptPubKey);

    auto block = getHeighestBlock();
    BOOST_CHECK_EQUAL(2, block.vtx.size());

    CTransaction sigmaTx = block.vtx[1];
    CMPTransaction mp_obj;

    BOOST_CHECK_EQUAL(0, ParseTransaction(sigmaTx, chainActive.Height(), 1, mp_obj, block.GetBlockTime()));
}

BOOST_AUTO_TEST_SUITE_END()
