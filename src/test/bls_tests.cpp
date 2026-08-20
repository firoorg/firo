// Copyright (c) 2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bls/bls.h"
#include "bls/bls_batchverifier.h"
#include "chainparams.h"
#include "llmq/quorums_commitment.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bls_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bls_sethexstr_tests)
{
    CBLSSecretKey sk;
    std::string strValidSecret = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    // Note: invalid string passed to SetHexStr() should cause it to fail and reset key internal data
    BOOST_CHECK(sk.SetHexStr(strValidSecret));
    BOOST_CHECK(!sk.SetHexStr("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1g")); // non-hex
    BOOST_CHECK(!sk.IsValid());
    BOOST_CHECK(sk == CBLSSecretKey());
    // Try few more invalid strings
    BOOST_CHECK(sk.SetHexStr(strValidSecret));
    BOOST_CHECK(!sk.SetHexStr("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e")); // hex but too short
    BOOST_CHECK(!sk.IsValid());
    BOOST_CHECK(sk.SetHexStr(strValidSecret));
    BOOST_CHECK(!sk.SetHexStr("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")); // hex but too long
    BOOST_CHECK(!sk.IsValid());
}

BOOST_AUTO_TEST_CASE(bls_reject_invalid_elements_tests)
{
    std::vector<uint8_t> g1Identity(BLS_CURVE_PUBKEY_SIZE, 0);
    std::vector<uint8_t> g2Identity(BLS_CURVE_SIG_SIZE, 0);
    g1Identity[0] = 0xc0;
    g2Identity[0] = 0xc0;
    const std::vector<uint8_t> g1OrderThree = ParseHex("800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    const std::vector<uint8_t> mixedG1 = ParseHex("8e9277968cb92c78d15a2a2ed855d55061c3929db43d1e53d6d13bee755ff9a91b3f577bbb2f15c6ba8206a6a81c4afd");
    const std::vector<uint8_t> invalidG1 = ParseHex("11df3a748b713460f9b21083315c0dca1742b7962ca98685be4094d302e84b0884a04c1a55beb0ed921dae1dd66c0a11");
    const std::vector<uint8_t> invalidG2 = ParseHex("0888879c99852460912fd28c7a9138926c1e87fd6609fd2d3d307764e49feb85702fd8f9b3b836bc11f7ce151b769dc70b760879d26f8c33a29e24f69297f45ef028f0794e63ddb0610db7de1a608b6d6a2129ada62b845004a408f651fd44a6");
    const std::vector<uint8_t> secretKeyGroupOrder = ParseHex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const std::vector<uint8_t> secretKeyGroupOrderPlusOne = ParseHex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002");

    const CBLSPublicKey identityPublicKey(g1Identity);
    const CBLSSignature identitySignature(g2Identity);
    const CBLSPublicKey orderThreePublicKey(g1OrderThree);
    const CBLSPublicKey mixedPublicKey(mixedG1);
    const CBLSPublicKey invalidPublicKey(invalidG1);
    const CBLSSignature invalidSignature(invalidG2);

    BOOST_CHECK(identityPublicKey.IsValid(false));
    BOOST_CHECK(identitySignature.IsValid(false));
    BOOST_CHECK(orderThreePublicKey.IsValid(false));
    BOOST_CHECK(mixedPublicKey.IsValid(false));
    BOOST_CHECK(invalidPublicKey.IsValid(false));
    BOOST_CHECK(invalidSignature.IsValid(false));

    BOOST_CHECK(!identityPublicKey.IsValid());
    BOOST_CHECK(!identitySignature.IsValid());
    BOOST_CHECK(!orderThreePublicKey.IsValid());
    BOOST_CHECK(!mixedPublicKey.IsValid());
    BOOST_CHECK(!invalidPublicKey.IsValid());
    BOOST_CHECK(!invalidSignature.IsValid());

    CBLSPublicKey hexPublicKey;
    BOOST_CHECK(!hexPublicKey.SetHexStr(HexStr(g1Identity)));
    BOOST_CHECK(!hexPublicKey.IsValid(false));

    BOOST_CHECK(identityPublicKey.ToByteVector() == g1Identity);
    BOOST_CHECK(identitySignature.ToByteVector() == g2Identity);
    BOOST_CHECK(orderThreePublicKey.ToByteVector() == g1OrderThree);
    BOOST_CHECK(mixedPublicKey.ToByteVector() == mixedG1);
    BOOST_CHECK(invalidPublicKey.ToByteVector() == invalidG1);
    BOOST_CHECK(invalidSignature.ToByteVector() == invalidG2);

    const uint256 identityMessageHash = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    BOOST_CHECK(identitySignature.VerifyInsecure(identityPublicKey, identityMessageHash, false));
    BOOST_CHECK(!identitySignature.VerifyInsecure(identityPublicKey, identityMessageHash));
    BOOST_CHECK(!CBLSSecretKey(secretKeyGroupOrder).IsValid());
    BOOST_CHECK(!CBLSSecretKey(secretKeyGroupOrder, false).IsValid());
    BOOST_CHECK(!CBLSSecretKey(secretKeyGroupOrderPlusOne).IsValid());

    const uint256 idValue = uint256S("0000000000000000000000000000000000000000000000000000000000000002");
    const CBLSId id(idValue);
    const CBLSId parsedId(id.ToByteVector());
    BOOST_CHECK(parsedId.IsValid());
    BOOST_CHECK(parsedId.ToByteVector() == id.ToByteVector());

    CBLSSecretKey sk;
    sk.MakeNewKey();
    const uint256 msgHash = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    const CBLSPublicKey pubKey(sk.GetPublicKey().ToByteVector());
    const CBLSSignature sig(sk.Sign(msgHash).ToByteVector());
    BOOST_CHECK(pubKey.IsValid());
    BOOST_CHECK(sig.IsValid());
    BOOST_CHECK(sig.VerifyInsecure(pubKey, msgHash));

    CBLSSignature cancelledSig = sig;
    cancelledSig.SubInsecure(sig);
    BOOST_CHECK(cancelledSig.IsValid(false));
    BOOST_CHECK(!cancelledSig.IsValid());
}

BOOST_AUTO_TEST_CASE(bls_final_commitment_strict_validation_tests)
{
    const auto& params = Params().GetConsensus().llmqs.at(Consensus::LLMQ_50_60);
    const uint256 quorumHash = uint256S("01");
    llmq::CFinalCommitment commitment(params, quorumHash);
    for (int i = 0; i < params.minSize; ++i) {
        commitment.signers[i] = true;
        commitment.validMembers[i] = true;
    }
    commitment.quorumVvecHash = uint256S("02");

    std::vector<CDeterministicMNCPtr> members;
    members.reserve(params.minSize);
    for (int i = 0; i < params.minSize; ++i) {
        CBLSSecretKey memberKey;
        memberKey.MakeNewKey();
        auto state = std::make_shared<CDeterministicMNState>();
        state->pubKeyOperator.Set(memberKey.GetPublicKey());
        auto dmn = std::make_shared<CDeterministicMN>();
        dmn->pdmnState = state;
        members.emplace_back(std::move(dmn));
    }

    std::vector<uint8_t> g1Identity(BLS_CURVE_PUBKEY_SIZE, 0);
    std::vector<uint8_t> g2Identity(BLS_CURVE_SIG_SIZE, 0);
    g1Identity[0] = 0xc0;
    g2Identity[0] = 0xc0;
    commitment.quorumPublicKey = CBLSPublicKey(g1Identity);
    commitment.quorumSig = CBLSSignature(g2Identity);
    commitment.membersSig = CBLSSignature(g2Identity);
    BOOST_CHECK(!commitment.IsNull());
    BOOST_CHECK(commitment.Verify(members, false, false));
    BOOST_CHECK(!commitment.Verify(members, false, true));

    CBLSSecretKey validKey;
    validKey.MakeNewKey();
    const uint256 hash;
    commitment.quorumPublicKey = validKey.GetPublicKey();
    commitment.quorumSig = validKey.Sign(hash);
    commitment.membersSig = validKey.Sign(hash);
    auto oversizedMembers = members;
    oversizedMembers.resize(params.size + 1, members.front());
    BOOST_CHECK(!commitment.Verify(oversizedMembers, false, false));

    auto invalidMemberState = std::make_shared<CDeterministicMNState>(*members[0]->pdmnState);
    invalidMemberState->pubKeyOperator.Set(CBLSPublicKey(g1Identity));
    auto invalidMember = std::make_shared<CDeterministicMN>(*members[0]);
    invalidMember->pdmnState = invalidMemberState;
    members[0] = invalidMember;
    BOOST_CHECK(commitment.Verify(members, false, false));
    BOOST_CHECK(!commitment.Verify(members, false, true));
}

BOOST_AUTO_TEST_CASE(bls_sig_tests)
{
    CBLSSecretKey sk1, sk2;
    sk1.MakeNewKey();
    sk2.MakeNewKey();

    uint256 msgHash1 = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    uint256 msgHash2 = uint256S("0000000000000000000000000000000000000000000000000000000000000002");

    auto sig1 = sk1.Sign(msgHash1);
    auto sig2 = sk2.Sign(msgHash1);
    BOOST_CHECK(sig1.VerifyInsecure(sk1.GetPublicKey(), msgHash1));
    BOOST_CHECK(!sig1.VerifyInsecure(sk1.GetPublicKey(), msgHash2));
    BOOST_CHECK(!sig2.VerifyInsecure(sk1.GetPublicKey(), msgHash1));
    BOOST_CHECK(!sig2.VerifyInsecure(sk2.GetPublicKey(), msgHash2));
    BOOST_CHECK(sig2.VerifyInsecure(sk2.GetPublicKey(), msgHash1));
}

struct Message
{
    uint32_t sourceId;
    uint32_t msgId;
    uint256 msgHash;
    CBLSSecretKey sk;
    CBLSPublicKey pk;
    CBLSSignature sig;
    bool valid;
};

static void AddMessage(std::vector<Message>& vec, uint32_t sourceId, uint32_t msgId, uint32_t msgHash, bool valid)
{
    Message m;
    m.sourceId = sourceId;
    m.msgId = msgId;
    *((uint32_t*)m.msgHash.begin()) = msgHash;
    m.sk.MakeNewKey();
    m.pk = m.sk.GetPublicKey();
    m.sig = m.sk.Sign(m.msgHash);
    m.valid = valid;

    if (!valid) {
        CBLSSecretKey tmp;
        tmp.MakeNewKey();
        m.sig = tmp.Sign(m.msgHash);
    }

    vec.emplace_back(m);
}

static void Verify(std::vector<Message>& vec, bool secureVerification, bool perMessageFallback)
{
    CBLSBatchVerifier<uint32_t, uint32_t> batchVerifier(secureVerification, perMessageFallback);

    std::set<uint32_t> expectedBadMessages;
    std::set<uint32_t> expectedBadSources;
    for (auto& m : vec) {
        if (!m.valid) {
            expectedBadMessages.emplace(m.msgId);
            expectedBadSources.emplace(m.sourceId);
        }

        batchVerifier.PushMessage(m.sourceId, m.msgId, m.msgHash, m.sig, m.pk);
    }

    batchVerifier.Verify();

    BOOST_CHECK(batchVerifier.badSources == expectedBadSources);

    if (perMessageFallback) {
        BOOST_CHECK(batchVerifier.badMessages == expectedBadMessages);
    } else {
        BOOST_CHECK(batchVerifier.badMessages.empty());
    }
}

static void Verify(std::vector<Message>& vec)
{
    Verify(vec, false, false);
    Verify(vec, true, false);
    Verify(vec, false, true);
    Verify(vec, true, true);
}

BOOST_AUTO_TEST_CASE(batch_verifier_tests)
{
    std::vector<Message> msgs;

    // distinct messages from distinct sources
    AddMessage(msgs, 1, 1, 1, true);
    AddMessage(msgs, 2, 2, 2, true);
    AddMessage(msgs, 3, 3, 3, true);
    Verify(msgs);

    // distinct messages from same source
    AddMessage(msgs, 4, 4, 4, true);
    AddMessage(msgs, 4, 5, 5, true);
    AddMessage(msgs, 4, 6, 6, true);
    Verify(msgs);

    // invalid sig
    AddMessage(msgs, 7, 7, 7, false);
    Verify(msgs);

    // same message as before, but from another source and with valid sig
    AddMessage(msgs, 8, 8, 7, true);
    Verify(msgs);

    // same message as before, but from another source and signed with another key
    AddMessage(msgs, 9, 9, 7, true);
    Verify(msgs);

    msgs.clear();
    // same message, signed by multiple keys
    AddMessage(msgs, 1, 1, 1, true);
    AddMessage(msgs, 1, 2, 1, true);
    AddMessage(msgs, 1, 3, 1, true);
    AddMessage(msgs, 2, 4, 1, true);
    AddMessage(msgs, 2, 5, 1, true);
    AddMessage(msgs, 2, 6, 1, true);
    Verify(msgs);

    // last message invalid from one source
    AddMessage(msgs, 1, 7, 1, false);
    Verify(msgs);
}

BOOST_AUTO_TEST_SUITE_END()
