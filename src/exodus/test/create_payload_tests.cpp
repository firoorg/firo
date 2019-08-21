#include "exodus/createpayload.h"

#include "test/test_bitcoin.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

#include <stdint.h>
#include <vector>
#include <string>

BOOST_FIXTURE_TEST_SUITE(exodus_create_payload_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(payload_simple_send)
{
    // Simple send [type 0, version 0]
    std::vector<unsigned char> vch = CreatePayload_SimpleSend(
        static_cast<uint32_t>(1),          // property: MSC
        static_cast<int64_t>(100000000));  // amount to transfer: 1.0 MSC (in willets)

    BOOST_CHECK_EQUAL(HexStr(vch), "00000000000000010000000005f5e100");
}

BOOST_AUTO_TEST_CASE(payload_send_to_owners)
{
    // Send to owners [type 3, version 0] (same property)
    std::vector<unsigned char> vch = CreatePayload_SendToOwners(
        static_cast<uint32_t>(1),          // property: OMNI
        static_cast<int64_t>(100000000),   // amount to transfer: 1.0 OMNI (in willets)
        static_cast<uint32_t>(1));         // property: OMNI

    BOOST_CHECK_EQUAL(HexStr(vch), "00000003000000010000000005f5e100");
}

BOOST_AUTO_TEST_CASE(payload_send_to_owners_v1)
{
    // Send to owners [type 3, version 1] (cross property)
    std::vector<unsigned char> vch = CreatePayload_SendToOwners(
        static_cast<uint32_t>(1),          // property: OMNI
        static_cast<int64_t>(100000000),   // amount to transfer: 1.0 OMNI (in willets)
        static_cast<uint32_t>(3));         // property: SP#3

    BOOST_CHECK_EQUAL(HexStr(vch), "00010003000000010000000005f5e10000000003");
}

BOOST_AUTO_TEST_CASE(payload_send_all)
{
    // Send to owners [type 4, version 0]
    std::vector<unsigned char> vch = CreatePayload_SendAll(
        static_cast<uint8_t>(2));          // ecosystem: Test

    BOOST_CHECK_EQUAL(HexStr(vch), "0000000402");
}

BOOST_AUTO_TEST_CASE(payload_dex_offer)
{
    // Sell tokens for bitcoins [type 20, version 1]
    std::vector<unsigned char> vch = CreatePayload_DExSell(
        static_cast<uint32_t>(1),         // property: MSC
        static_cast<int64_t>(100000000),  // amount to transfer: 1.0 MSC (in willets)
        static_cast<int64_t>(20000000),   // amount desired: 0.2 BTC (in satoshis)
        static_cast<uint8_t>(10),         // payment window in blocks
        static_cast<int64_t>(10000),      // commitment fee in satoshis
        static_cast<uint8_t>(1));         // sub-action: new offer

    BOOST_CHECK_EQUAL(HexStr(vch),
        "00010014000000010000000005f5e1000000000001312d000a000000000000271001");
}

BOOST_AUTO_TEST_CASE(payload_meta_dex_new_trade)
{
    // Trade tokens for tokens [type 25, version 0]
    std::vector<unsigned char> vch = CreatePayload_MetaDExTrade(
        static_cast<uint32_t>(1),          // property: MSC
        static_cast<int64_t>(250000000),   // amount for sale: 2.5 MSC
        static_cast<uint32_t>(31),         // property desired: TetherUS
        static_cast<int64_t>(5000000000)); // amount desired: 50.0 TetherUS

    BOOST_CHECK_EQUAL(HexStr(vch),
        "0000001900000001000000000ee6b2800000001f000000012a05f200");
}

BOOST_AUTO_TEST_CASE(payload_meta_dex_cancel_at_price)
{
    // Trade tokens for tokens [type 26, version 0]
    std::vector<unsigned char> vch = CreatePayload_MetaDExCancelPrice(
        static_cast<uint32_t>(1),          // property: MSC
        static_cast<int64_t>(250000000),   // amount for sale: 2.5 MSC
        static_cast<uint32_t>(31),         // property desired: TetherUS
        static_cast<int64_t>(5000000000)); // amount desired: 50.0 TetherUS

    BOOST_CHECK_EQUAL(HexStr(vch),
        "0000001a00000001000000000ee6b2800000001f000000012a05f200");
}

BOOST_AUTO_TEST_CASE(payload_meta_dex_cancel_pair)
{
    // Trade tokens for tokens [type 27, version 0]
    std::vector<unsigned char> vch = CreatePayload_MetaDExCancelPair(
        static_cast<uint32_t>(1),          // property: MSC
        static_cast<uint32_t>(31));        // property desired: TetherUS

    BOOST_CHECK_EQUAL(HexStr(vch),
        "0000001b000000010000001f");
}

BOOST_AUTO_TEST_CASE(payload_meta_dex_cancel_ecosystem)
{
    // Trade tokens for tokens [type 28, version 0]
    std::vector<unsigned char> vch = CreatePayload_MetaDExCancelEcosystem(
        static_cast<uint8_t>(1));          // ecosystem: Main

    BOOST_CHECK_EQUAL(HexStr(vch),
        "0000001c01");
}

BOOST_AUTO_TEST_CASE(payload_accept_dex_offer)
{
    // Purchase tokens with bitcoins [type 22, version 0]
    std::vector<unsigned char> vch = CreatePayload_DExAccept(
        static_cast<uint32_t>(1),          // property: MSC
        static_cast<int64_t>(130000000));  // amount to transfer: 1.3 MSC (in willets)

    BOOST_CHECK_EQUAL(HexStr(vch), "00000016000000010000000007bfa480");
}

BOOST_AUTO_TEST_CASE(payload_create_property)
{
    // Create property [type 50, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceFixed(
        static_cast<uint8_t>(1),             // ecosystem: main
        static_cast<uint16_t>(1),            // property type: indivisible tokens
        static_cast<uint32_t>(0),            // previous property: none
        std::string("Companies"),            // category
        std::string("Bitcoin Mining"),       // subcategory
        std::string("Quantum Miner"),        // label
        std::string("builder.bitwatch.co"),  // website
        std::string(""),                     // additional information
        static_cast<int64_t>(1000000));      // number of units to create

    BOOST_CHECK_EQUAL(HexStr(vch),
        "0000003201000100000000436f6d70616e69657300426974636f696e204d696e696e67"
        "005175616e74756d204d696e6572006275696c6465722e62697477617463682e636f00"
        "0000000000000f4240");
}

BOOST_AUTO_TEST_CASE(payload_create_property_empty)
{
    // Create property [type 50, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceFixed(
        static_cast<uint8_t>(1),         // ecosystem: main
        static_cast<uint16_t>(1),        // property type: indivisible tokens
        static_cast<uint32_t>(0),        // previous property: none
        std::string(""),                 // category
        std::string(""),                 // subcategory
        std::string(""),                 // label
        std::string(""),                 // website
        std::string(""),                 // additional information
        static_cast<int64_t>(1000000));  // number of units to create

    BOOST_CHECK_EQUAL(vch.size(), 24);
}

BOOST_AUTO_TEST_CASE(payload_create_property_full)
{
    // Create property [type 50, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceFixed(
        static_cast<uint8_t>(1),         // ecosystem: main
        static_cast<uint16_t>(1),        // property type: indivisible tokens
        static_cast<uint32_t>(0),        // previous property: none
        std::string(700, 'x'),           // category
        std::string(700, 'x'),           // subcategory
        std::string(700, 'x'),           // label
        std::string(700, 'x'),           // website
        std::string(700, 'x'),           // additional information
        static_cast<int64_t>(1000000));  // number of units to create

    BOOST_CHECK_EQUAL(vch.size(), 1299);
}

BOOST_AUTO_TEST_CASE(payload_create_crowdsale)
{
    // Create crowdsale [type 51, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceVariable(
        static_cast<uint8_t>(1),             // ecosystem: main
        static_cast<uint16_t>(1),            // property type: indivisible tokens
        static_cast<uint32_t>(0),            // previous property: none
        std::string("Companies"),            // category
        std::string("Bitcoin Mining"),       // subcategory
        std::string("Quantum Miner"),        // label
        std::string("builder.bitwatch.co"),  // website
        std::string(""),                     // additional information
        static_cast<uint32_t>(1),            // property desired: MSC
        static_cast<int64_t>(100),           // tokens per unit vested
        static_cast<uint64_t>(7731414000L),  // deadline: 31 Dec 2214 23:00:00 UTC
        static_cast<uint8_t>(10),            // early bird bonus: 10 % per week
        static_cast<uint8_t>(12));           // issuer bonus: 12 %

    BOOST_CHECK_EQUAL(HexStr(vch),
        "0000003301000100000000436f6d70616e69657300426974636f696e204d696e696e67"
        "005175616e74756d204d696e6572006275696c6465722e62697477617463682e636f00"
        "0000000001000000000000006400000001ccd403f00a0c");
}

BOOST_AUTO_TEST_CASE(payload_create_crowdsale_empty)
{
    // Create crowdsale [type 51, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceVariable(
        static_cast<uint8_t>(1),            // ecosystem: main
        static_cast<uint16_t>(1),           // property type: indivisible tokens
        static_cast<uint32_t>(0),           // previous property: none
        std::string(""),                    // category
        std::string(""),                    // subcategory
        std::string(""),                    // label
        std::string(""),                    // website
        std::string(""),                    // additional information
        static_cast<uint32_t>(1),           // property desired: MSC
        static_cast<int64_t>(100),          // tokens per unit vested
        static_cast<uint64_t>(7731414000L), // deadline: 31 Dec 2214 23:00:00 UTC
        static_cast<uint8_t>(10),           // early bird bonus: 10 % per week
        static_cast<uint8_t>(12));          // issuer bonus: 12 %

    BOOST_CHECK_EQUAL(vch.size(), 38);
}

BOOST_AUTO_TEST_CASE(payload_create_crowdsale_full)
{
    // Create crowdsale [type 51, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceVariable(
        static_cast<uint8_t>(1),            // ecosystem: main
        static_cast<uint16_t>(1),           // property type: indivisible tokens
        static_cast<uint32_t>(0),           // previous property: none
        std::string(700, 'x'),              // category
        std::string(700, 'x'),              // subcategory
        std::string(700, 'x'),              // label
        std::string(700, 'x'),              // website
        std::string(700, 'x'),              // additional information
        static_cast<uint32_t>(1),           // property desired: MSC
        static_cast<int64_t>(100),          // tokens per unit vested
        static_cast<uint64_t>(7731414000L), // deadline: 31 Dec 2214 23:00:00 UTC
        static_cast<uint8_t>(10),           // early bird bonus: 10 % per week
        static_cast<uint8_t>(12));          // issuer bonus: 12 %

    BOOST_CHECK_EQUAL(vch.size(), 1313);
}

BOOST_AUTO_TEST_CASE(payload_close_crowdsale)
{
    // Close crowdsale [type 53, version 0]
    std::vector<unsigned char> vch = CreatePayload_CloseCrowdsale(
        static_cast<uint32_t>(9));  // property: SP #9

    BOOST_CHECK_EQUAL(HexStr(vch), "0000003500000009");
}

BOOST_AUTO_TEST_CASE(payload_create_managed_property)
{
    // create managed property [type 54, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceManaged(
        static_cast<uint8_t>(1),             // ecosystem: main
        static_cast<uint16_t>(1),            // property type: indivisible tokens
        static_cast<uint32_t>(0),            // previous property: none
        std::string("Companies"),            // category
        std::string("Bitcoin Mining"),       // subcategory
        std::string("Quantum Miner"),        // label
        std::string("builder.bitwatch.co"),  // website
        std::string(""));                    // additional information

    BOOST_CHECK_EQUAL(HexStr(vch),
        "0000003601000100000000436f6d70616e69657300426974636f696e204d696e696e67"
        "005175616e74756d204d696e6572006275696c6465722e62697477617463682e636f00"
        "00");
}

BOOST_AUTO_TEST_CASE(payload_create_managed_property_empty)
{
    // create managed property [type 54, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceManaged(
        static_cast<uint8_t>(1),   // ecosystem: main
        static_cast<uint16_t>(1),  // property type: indivisible tokens
        static_cast<uint32_t>(0),  // previous property: none
        std::string(""),           // category
        std::string(""),           // subcategory
        std::string(""),           // label
        std::string(""),           // website
        std::string(""));          // additional information

    BOOST_CHECK_EQUAL(vch.size(), 16);
}

BOOST_AUTO_TEST_CASE(payload_create_managed_property_full)
{
    // create managed property [type 54, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceManaged(
        static_cast<uint8_t>(1),   // ecosystem: main
        static_cast<uint16_t>(1),  // property type: indivisible tokens
        static_cast<uint32_t>(0),  // previous property: none
        std::string(700, 'x'),     // category
        std::string(700, 'x'),     // subcategory
        std::string(700, 'x'),     // label
        std::string(700, 'x'),     // website
        std::string(700, 'x'));    // additional information

    BOOST_CHECK_EQUAL(vch.size(), 1291);
}

BOOST_AUTO_TEST_CASE(payload_grant_tokens)
{
    // Grant tokens [type 55, version 0]
    std::vector<unsigned char> vch = CreatePayload_Grant(
        static_cast<uint32_t>(8),                  // property: SP #8
        static_cast<int64_t>(1000),                // number of units to issue
        std::string("First Milestone Reached!"));  // additional information

    BOOST_CHECK_EQUAL(HexStr(vch),
        "000000370000000800000000000003e84669727374204d696c6573746f6e6520526561"
        "636865642100");
}

BOOST_AUTO_TEST_CASE(payload_grant_tokens_empty)
{
    // Grant tokens [type 55, version 0]
    std::vector<unsigned char> vch = CreatePayload_Grant(
        static_cast<uint32_t>(8),                  // property: SP #8
        static_cast<int64_t>(1000),                // number of units to issue
        std::string(""));                          // additional information

    BOOST_CHECK_EQUAL(vch.size(), 17);
}

BOOST_AUTO_TEST_CASE(payload_grant_tokens_full)
{
    // Grant tokens [type 55, version 0]
    std::vector<unsigned char> vch = CreatePayload_Grant(
        static_cast<uint32_t>(8),                  // property: SP #8
        static_cast<int64_t>(1000),                // number of units to issue
        std::string(700, 'x'));                    // additional information

    BOOST_CHECK_EQUAL(vch.size(), 272);
}

BOOST_AUTO_TEST_CASE(payload_revoke_tokens)
{
    // Revoke tokens [type 56, version 0]
    std::vector<unsigned char> vch = CreatePayload_Revoke(
        static_cast<uint32_t>(8),                                   // property: SP #8
        static_cast<int64_t>(1000),                                 // number of units to revoke
        std::string("Redemption of tokens for Bob, Thanks Bob!"));  // additional information

    BOOST_CHECK_EQUAL(HexStr(vch),
        "000000380000000800000000000003e8526564656d7074696f6e206f6620746f6b656e"
        "7320666f7220426f622c205468616e6b7320426f622100");
}

BOOST_AUTO_TEST_CASE(payload_revoke_tokens_empty)
{
    // Revoke tokens [type 56, version 0]
    std::vector<unsigned char> vch = CreatePayload_Revoke(
        static_cast<uint32_t>(8),    // property: SP #8
        static_cast<int64_t>(1000),  // number of units to revoke
        std::string(""));            // additional information

    BOOST_CHECK_EQUAL(vch.size(), 17);
}

BOOST_AUTO_TEST_CASE(payload_revoke_tokens_full)
{
    // Revoke tokens [type 56, version 0]
    std::vector<unsigned char> vch = CreatePayload_Revoke(
        static_cast<uint32_t>(8),    // property: SP #8
        static_cast<int64_t>(1000),  // number of units to revoke
        std::string(700, 'x'));      // additional information

    BOOST_CHECK_EQUAL(vch.size(), 272);
}

BOOST_AUTO_TEST_CASE(payload_change_property_manager)
{
    // Change property manager [type 70, version 0]
    std::vector<unsigned char> vch = CreatePayload_ChangeIssuer(
        static_cast<uint32_t>(13));  // property: SP #13

    BOOST_CHECK_EQUAL(HexStr(vch), "000000460000000d");
}

BOOST_AUTO_TEST_CASE(payload_enable_freezing)
{
    // Enable freezing [type 71, version 0]
    std::vector<unsigned char> vch = CreatePayload_EnableFreezing(
        static_cast<uint32_t>(4));                 // property: SP #4

    BOOST_CHECK_EQUAL(HexStr(vch), "0000004700000004");
}

BOOST_AUTO_TEST_CASE(payload_disable_freezing)
{
    // Disable freezing [type 72, version 0]
    std::vector<unsigned char> vch = CreatePayload_DisableFreezing(
        static_cast<uint32_t>(4));                 // property: SP #4

    BOOST_CHECK_EQUAL(HexStr(vch), "0000004800000004");
}

BOOST_AUTO_TEST_CASE(payload_freeze_tokens)
{
    // Freeze tokens [type 185, version 0]
    std::vector<unsigned char> vch = CreatePayload_FreezeTokens(
        static_cast<uint32_t>(4),                                   // property: SP #4
        static_cast<int64_t>(1000),                                 // amount to freeze (unused)
        std::string("1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P"));         // reference address

    BOOST_CHECK_EQUAL(HexStr(vch),
        "000000b90000000400000000000003e800946cb2e08075bcbaf157e47bcb67eb2b2339d242");
}

BOOST_AUTO_TEST_CASE(payload_unfreeze_tokens)
{
    // Freeze tokens [type 186, version 0]
    std::vector<unsigned char> vch = CreatePayload_UnfreezeTokens(
        static_cast<uint32_t>(4),                                   // property: SP #4
        static_cast<int64_t>(1000),                                 // amount to freeze (unused)
        std::string("1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P"));         // reference address

    BOOST_CHECK_EQUAL(HexStr(vch),
        "000000ba0000000400000000000003e800946cb2e08075bcbaf157e47bcb67eb2b2339d242");
}

BOOST_AUTO_TEST_CASE(payload_feature_deactivation)
{
    // Exodus Core feature activation [type 65533, version 65535]
    std::vector<unsigned char> vch = CreatePayload_DeactivateFeature(
        static_cast<uint16_t>(1));        // feature identifier: 1 (OP_RETURN)

    BOOST_CHECK_EQUAL(HexStr(vch), "fffffffd0001");
}

BOOST_AUTO_TEST_CASE(payload_feature_activation)
{
    // Exodus Core feature activation [type 65534, version 65535]
    std::vector<unsigned char> vch = CreatePayload_ActivateFeature(
        static_cast<uint16_t>(1),        // feature identifier: 1 (OP_RETURN)
        static_cast<uint32_t>(370000),   // activation block
        static_cast<uint32_t>(999));     // min client version

    BOOST_CHECK_EQUAL(HexStr(vch), "fffffffe00010005a550000003e7");
}

BOOST_AUTO_TEST_CASE(payload_exodus_alert_block)
{
    // Exodus Core client notification [type 65535, version 65535]
    std::vector<unsigned char> vch = CreatePayload_ExodusAlert(
        static_cast<int32_t>(1),            // alert target: by block number
        static_cast<uint64_t>(300000),      // expiry value: 300000
        static_cast<std::string>("test"));  // alert message: test

    BOOST_CHECK_EQUAL(HexStr(vch), "ffffffff0001000493e07465737400");
}

BOOST_AUTO_TEST_CASE(payload_exodus_alert_blockexpiry)
{
    // Exodus Core client notification [type 65535, version 65535]
    std::vector<unsigned char> vch = CreatePayload_ExodusAlert(
        static_cast<int32_t>(2),            // alert target: by block time
        static_cast<uint64_t>(1439528630),  // expiry value: 1439528630
        static_cast<std::string>("test"));  // alert message: test

    BOOST_CHECK_EQUAL(HexStr(vch), "ffffffff000255cd76b67465737400");
}

BOOST_AUTO_TEST_CASE(payload_exodus_alert_minclient)
{
    // Exodus Core client notification [type 65535, version 65535]
    std::vector<unsigned char> vch = CreatePayload_ExodusAlert(
        static_cast<int32_t>(3),            // alert target: by client version
        static_cast<uint64_t>(900100),      // expiry value: v0.0.9.1
        static_cast<std::string>("test"));  // alert message: test

    BOOST_CHECK_EQUAL(HexStr(vch), "ffffffff0003000dbc047465737400");
}

BOOST_AUTO_TEST_CASE(payload_create_denomination)
{
    // Simple send [type 1025, version 0]
    std::vector<unsigned char> vch = CreatePayload_CreateDenomination(
        static_cast<uint32_t>(1),          // property: MSC
        static_cast<int64_t>(100000000));  // value of denomination: 1.0 MSC (in willets)

    BOOST_CHECK_EQUAL(HexStr(vch), "00000401000000010000000005f5e100");
}

BOOST_AUTO_TEST_CASE(payload_create_simple_mint)
{
    std::string data = "40a2bc96cfd3911902843529cd674472b423164756eef7f7845fdfdc3a548f620100";
    std::string data2 = "7cbfec8ffd9b56c607c94975f90f95b3aaa84422357ceb293b6b0c42d2d7bb920000";

    exodus::SigmaPublicKey publicKey, publicKey2;
    CDataStream(ParseHex(data), SER_NETWORK, CLIENT_VERSION) >> publicKey;
    CDataStream(ParseHex(data2), SER_NETWORK, CLIENT_VERSION) >> publicKey2;

    // Simple mint [type 1026, version 0]
    std::vector<unsigned char> vch = CreatePayload_SimpleMint(
        static_cast<uint32_t>(1),          // property: MSC
        {
            std::make_pair(0, publicKey),
            std::make_pair(1, publicKey2)
        }
    );

    BOOST_CHECK_EQUAL(HexStr(vch),
        "0000040200000001020040a2bc96cfd3911902843529cd674472b423164756eef7f7845fdfdc3a548f620100" \
        "017cbfec8ffd9b56c607c94975f90f95b3aaa84422357ceb293b6b0c42d2d7bb920000"
    );
}

BOOST_AUTO_TEST_CASE(payload_create_simple_mint_no_mints)
{
    // Simple mint [type 1026, version 0]
    BOOST_CHECK_EXCEPTION(
        CreatePayload_SimpleMint(
            static_cast<uint32_t>(1),
            {}
        ),
        std::invalid_argument,
        [](const std::invalid_argument& e) {
            return std::string("no mints provided") == e.what();
        }
    );
}

BOOST_AUTO_TEST_CASE(payload_create_simple_mint_exceed_limit)
{
    std::vector<std::pair<uint8_t, exodus::SigmaPublicKey>> pubs;
    pubs.resize(EXODUS_MAX_SIMPLE_MINTS + 1);

    // Simple mint [type 1026, version 0]
    BOOST_CHECK_EXCEPTION(
        CreatePayload_SimpleMint(
            static_cast<uint32_t>(1),
            pubs
        ),
        std::invalid_argument,
        [](const std::invalid_argument& e) {
            return std::string("amount of mints exceeded limit") == e.what();
        }
    );
}

BOOST_AUTO_TEST_CASE(payload_create_simple_spend)
{
    std::string proofData = "14fb0a84ab9ae05784bf46234331b5af31080a0fac2d1ac2fed0794153afd6534e3d36460739902ad79beabd3a8fc3e2278a0141bd1e683fa324b027d8a7307a01004060b69743907ca7e431c6fbd93a516551a501b6b8921b874b8e9367a82dd37601000d00d0699f6615520625b1a7edbc5d36cd5a058755de15c8f3f684651d6df50701002d6edaa6ee71d7c4c1a6f49cc4751468f1d9a6064b47be71450fbd053e448d1600001563aa2e9bc754d68080804f425ed1509f9f7abb522db31383944c891dd8c5e740cd2ade64de4f0917cd9020bb90049e7fa8cf77fdafafc408ad273b49fd0b29671b8cbd8506f316d82fc2ec51a2f650845e39ff212638fdaf2dc4fad2daf6e3527a404e83132648b593e1bcea8bbcb9a37dd215ed9b4b7856b72e79c8d74a9ae91ac992b85c23c080e0ff2b1772eac904f49fd690beb2c955c732603c8da33c79d2787c759b5724a29f5cc9390dd85c2facbf963ede11fdf89674db104c301f4ac43039fac9157ad2ee86a46d3926fd5d4838c008c09197f9faa3e88458b1314bdbd13719de900e7978a73ee82aad0811e21f4190927f503956d5f1b6de08feeef840672060cce5c84f9fdf181dd98bbbb905a978c4c14e7cdb5c96c23c7f2297c49f3dc231f4be5607878029c3c2e33a97a1fe9c75bda6bc1b782ead1489a1d9087107e14f7a96234b7c7df47ece95ce5b20c2f9cec3c8e678971f95ed58591182b42b2a3484e0779a3848e1a340777dc98dde29d05c6412d58bfd98a43c90301d86d0c038852a8fc917363edef47458ea3d8df48d58e40d453c8550e3ac2d1854102920bfe39fcb66e0cf1bdb387488aa392476da4ff5397a59274430aed3187f8bbeb0d3656d6e8e28b50ff3770103a42e157a06349251b5f9b17dcdfca8ff87f8d823d9202c611d4752b9ee1c77bf253718937261ba9f08c07438b13a007c9e7aa233d158f76db2ee4515f4aaeea38130c6288f153a671e759f4fd67857da60ac0e331ce383cc8bc734dcf45146c88586b41a75c873b2a4a329bc7b436b5a0945ef445c61891b2d61400691afef1ca99acaf3db7537b43d4002f80a46de5bb8ce3805394f2fa32d391ba611b501b3c389422b94adf491ba69abf3a993d85c94cd54b8a2dbdd9486a4bffd79b55d4d73978a5fdeb9f46f66be622e98c8cc9c7d3803d28003c176839e6a6209877c5e01ada0e418a08a5117088d8ce218b557e825571711b77cda2f549c4c4aef791964abfb9a21368e4e80fb30ba4b0b4dec075b011456e75aa6ae2e8e7981c9c0306671237cadd005113a7e532d9c3aa72303000044bf1698884f2a5753ebb9a73d5fc2ae0578e76d2035ed39afccdc918f9e0df7010020ddc9ff18999e30f29823f8c546513dcf0477a47f1b2325b5a4094f54c9a9f00000ebdb8fa236ae223508dff92c2f9fb01d5c2a5f4a2d1b212409ea71d7d5bc2cd801008a9aca57d8a505fbb020b4003099d2e04781fcc8eb29b22d195a6f9ac2fde22e0100b15b24e620669b4b3421d28b24528ee3cb30f84b5d6a772fbeed71aa0a315ead0100b13ab7aea21b0c2f1d194040265b92d0ff101a1f82973d644ebc9ddb16ecd81101006b99b6f5a96c805a728ee479d1c2b05b9b67e3e84517bccb25f577afcfee582c";

    exodus::SigmaProof spend;
    CDataStream(ParseHex(proofData), SER_NETWORK, CLIENT_VERSION) >> spend;
    uint8_t denomination = 1;
    uint32_t group = 2;
    uint16_t coinsInAnonimityGroup = 3;

    std::vector<unsigned char> payload;
    BOOST_CHECK_NO_THROW(
        payload = CreatePayload_SimpleSpend(1, denomination, group, coinsInAnonimityGroup, spend)
    );

    // denom group index
    BOOST_CHECK_EQUAL(
        HexStr(payload),
        "00000403000000010100000002000314fb0a84ab9ae05784bf46234331b5af31080a0fac2d1ac2fed0794153afd6534e3d36460739902ad79beabd3a8fc3e2278a0141bd1e683fa324b027d8a7307a01004060b69743907ca7e431c6fbd93a516551a501b6b8921b874b8e9367a82dd37601000d00d0699f6615520625b1a7edbc5d36cd5a058755de15c8f3f684651d6df50701002d6edaa6ee71d7c4c1a6f49cc4751468f1d9a6064b47be71450fbd053e448d1600001563aa2e9bc754d68080804f425ed1509f9f7abb522db31383944c891dd8c5e740cd2ade64de4f0917cd9020bb90049e7fa8cf77fdafafc408ad273b49fd0b29671b8cbd8506f316d82fc2ec51a2f650845e39ff212638fdaf2dc4fad2daf6e3527a404e83132648b593e1bcea8bbcb9a37dd215ed9b4b7856b72e79c8d74a9ae91ac992b85c23c080e0ff2b1772eac904f49fd690beb2c955c732603c8da33c79d2787c759b5724a29f5cc9390dd85c2facbf963ede11fdf89674db104c301f4ac43039fac9157ad2ee86a46d3926fd5d4838c008c09197f9faa3e88458b1314bdbd13719de900e7978a73ee82aad0811e21f4190927f503956d5f1b6de08feeef840672060cce5c84f9fdf181dd98bbbb905a978c4c14e7cdb5c96c23c7f2297c49f3dc231f4be5607878029c3c2e33a97a1fe9c75bda6bc1b782ead1489a1d9087107e14f7a96234b7c7df47ece95ce5b20c2f9cec3c8e678971f95ed58591182b42b2a3484e0779a3848e1a340777dc98dde29d05c6412d58bfd98a43c90301d86d0c038852a8fc917363edef47458ea3d8df48d58e40d453c8550e3ac2d1854102920bfe39fcb66e0cf1bdb387488aa392476da4ff5397a59274430aed3187f8bbeb0d3656d6e8e28b50ff3770103a42e157a06349251b5f9b17dcdfca8ff87f8d823d9202c611d4752b9ee1c77bf253718937261ba9f08c07438b13a007c9e7aa233d158f76db2ee4515f4aaeea38130c6288f153a671e759f4fd67857da60ac0e331ce383cc8bc734dcf45146c88586b41a75c873b2a4a329bc7b436b5a0945ef445c61891b2d61400691afef1ca99acaf3db7537b43d4002f80a46de5bb8ce3805394f2fa32d391ba611b501b3c389422b94adf491ba69abf3a993d85c94cd54b8a2dbdd9486a4bffd79b55d4d73978a5fdeb9f46f66be622e98c8cc9c7d3803d28003c176839e6a6209877c5e01ada0e418a08a5117088d8ce218b557e825571711b77cda2f549c4c4aef791964abfb9a21368e4e80fb30ba4b0b4dec075b011456e75aa6ae2e8e7981c9c0306671237cadd005113a7e532d9c3aa72303000044bf1698884f2a5753ebb9a73d5fc2ae0578e76d2035ed39afccdc918f9e0df7010020ddc9ff18999e30f29823f8c546513dcf0477a47f1b2325b5a4094f54c9a9f00000ebdb8fa236ae223508dff92c2f9fb01d5c2a5f4a2d1b212409ea71d7d5bc2cd801008a9aca57d8a505fbb020b4003099d2e04781fcc8eb29b22d195a6f9ac2fde22e0100b15b24e620669b4b3421d28b24528ee3cb30f84b5d6a772fbeed71aa0a315ead0100b13ab7aea21b0c2f1d194040265b92d0ff101a1f82973d644ebc9ddb16ecd81101006b99b6f5a96c805a728ee479d1c2b05b9b67e3e84517bccb25f577afcfee582c"
    );
}

BOOST_AUTO_TEST_SUITE_END()
