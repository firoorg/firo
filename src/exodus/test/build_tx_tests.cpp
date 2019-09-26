#include "exodus/createtx.h"
#include "exodus/errors.h"
#include "exodus/encoding.h"
#include "exodus/exodus.h"
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
#include "exodus/utilsbitcoin.h"

#include "wallet/wallet.h"

#include <boost/test/unit_test.hpp>

#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(exodus_build_tx_tests, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(wallettxbuilder_create_normal_b)
{
    std::vector<unsigned char> data(nMaxDatacarrierBytes + 1);

    std::string fromAddress = CBitcoinAddress(pubkey.GetID()).ToString();

    uint256 txid;
    std::string rawHex;
    BOOST_CHECK_EQUAL(
        0, // No error
        exodus::WalletTxBuilder(fromAddress, "", "", 0, data, txid, rawHex, false)
    );

    CTransaction decTx;
    BOOST_CHECK(DecodeHexTx(decTx, rawHex));

    BOOST_CHECK(!decTx.IsSigmaSpend());

    BOOST_CHECK_EQUAL(
        EXODUS_CLASS_B,
        exodus::GetEncodingClass(decTx, chainActive.Height())
    );
}

BOOST_AUTO_TEST_CASE(wallettxbuilder_create_normal_c)
{
    std::vector<unsigned char> data(80);

    std::string fromAddress = CBitcoinAddress(pubkey.GetID()).ToString();

    uint256 txid;
    std::string rawHex;
    BOOST_CHECK_EQUAL(
        0, // No error
        exodus::WalletTxBuilder(fromAddress, "", "", 0, data, txid, rawHex, false)
    );

    CTransaction decTx;
    BOOST_CHECK(DecodeHexTx(decTx, rawHex));

    BOOST_CHECK(!decTx.IsSigmaSpend());

    BOOST_CHECK_EQUAL(
        EXODUS_CLASS_C,
        exodus::GetEncodingClass(decTx, chainActive.Height())
    );
}

BOOST_AUTO_TEST_CASE(wallettxbuilder_create_sigma_without_mints)
{
    pwalletMain->SetBroadcastTransactions(true);
    CreateAndProcessEmptyBlocks(200, scriptPubKey);

    std::vector<unsigned char> data(80);

    uint256 txid;
    std::string rawHex;
    BOOST_CHECK_EQUAL(
        MPRPCErrorCode::MP_SIGMA_INPUTS_INVALID,
        exodus::WalletTxBuilder("", "", "", 0, data, txid, rawHex, false, exodus::InputMode::SIGMA)
    );
}

BOOST_AUTO_TEST_CASE(wallettxbuilder_create_sigma_with_toolarge_data)
{
    pwalletMain->SetBroadcastTransactions(true);
    CreateAndProcessEmptyBlocks(200, scriptPubKey);

    string stringError;
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
        stringError, {{"1", 10}}, SIGMA), stringError + " - Create Mint failed");

    CreateAndProcessBlock({}, scriptPubKey);
    CreateAndProcessEmptyBlocks(5, scriptPubKey);

    std::vector<unsigned char> data(nMaxDatacarrierBytes + 1);

    uint256 txid;
    std::string rawHex;
    BOOST_CHECK_EQUAL(
        MPRPCErrorCode::MP_ENCODING_ERROR,
        exodus::WalletTxBuilder("", "", "", 0, data, txid, rawHex, false, exodus::InputMode::SIGMA)
    );
}

BOOST_AUTO_TEST_CASE(wallettxbuilder_create_sigma_success)
{
    pwalletMain->SetBroadcastTransactions(true);
    CreateAndProcessEmptyBlocks(200, scriptPubKey);

    string stringError;
    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(
            stringError, {{"1", 10}}, SIGMA), stringError + " - Create Mint failed");

    CreateAndProcessBlock({}, scriptPubKey);
    CreateAndProcessEmptyBlocks(5, scriptPubKey);

    std::vector<unsigned char> data(80);

    uint256 txid;
    std::string rawHex;
    BOOST_CHECK_EQUAL(
        0, // No error
        exodus::WalletTxBuilder("", "", "", 0, data, txid, rawHex, false, exodus::InputMode::SIGMA)
    );

    CTransaction decTx;
    BOOST_CHECK(DecodeHexTx(decTx, rawHex));

    BOOST_CHECK(decTx.IsSigmaSpend());

    BOOST_CHECK_EQUAL(
        EXODUS_CLASS_C,
        exodus::GetEncodingClass(decTx, chainActive.Height())
    );
}

BOOST_AUTO_TEST_SUITE_END()
