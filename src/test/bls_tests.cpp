// Copyright (c) 2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bls/bls.h"
#include "bls/bls_batchverifier.h"
#include "test/test_bitcoin.h"
#include "streams.h"

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

static std::vector<uint8_t> MakeCanonicalIdentityBytes(size_t size)
{
    std::vector<uint8_t> identity(size, 0);
    identity[0] = 0xc0;
    return identity;
}

BOOST_AUTO_TEST_CASE(bls_identity_elements_rejected)
{
    const auto pubKeyIdentity = MakeCanonicalIdentityBytes(BLS_CURVE_PUBKEY_SIZE);
    const auto sigIdentity = MakeCanonicalIdentityBytes(BLS_CURVE_SIG_SIZE);

    CBLSPublicKey pubKey(pubKeyIdentity);
    CBLSSignature sig(sigIdentity);

    BOOST_CHECK(!pubKey.IsValid());
    BOOST_CHECK(!sig.IsValid());
    BOOST_CHECK(pubKey == CBLSPublicKey());
    BOOST_CHECK(sig == CBLSSignature());
}

BOOST_AUTO_TEST_CASE(bls_identity_deserialization_rejected)
{
    const auto pubKeyIdentity = MakeCanonicalIdentityBytes(BLS_CURVE_PUBKEY_SIZE);
    const auto sigIdentity = MakeCanonicalIdentityBytes(BLS_CURVE_SIG_SIZE);

    CDataStream pubKeyStream(SER_DISK, PROTOCOL_VERSION);
    pubKeyStream.write((const char*)pubKeyIdentity.data(), pubKeyIdentity.size());

    CDataStream sigStream(SER_DISK, PROTOCOL_VERSION);
    sigStream.write((const char*)sigIdentity.data(), sigIdentity.size());

    CBLSPublicKey pubKey;
    CBLSSignature sig;

    BOOST_CHECK_THROW(pubKeyStream >> pubKey, std::ios_base::failure);
    BOOST_CHECK_THROW(sigStream >> sig, std::ios_base::failure);
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

// ---------------------------------------------------------------------------
// Lazy-wrapper identity rejection tests
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(lazy_pubkey_rejects_identity)
{
    // Construct a stream containing all-zero (identity) public-key bytes.
    std::vector<uint8_t> identityBytes(CBLSPublicKey::SerSize, 0);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss.write((const char*)identityBytes.data(), identityBytes.size());

    CBLSLazyPublicKey lazy;
    lazy.Unserialize(ss);

    // Get() must return an invalid object.
    const CBLSPublicKey& pk = lazy.Get();
    BOOST_CHECK(!pk.IsValid());

    // GetHash() must return a null hash – identity bytes must not influence hashes.
    BOOST_CHECK(lazy.GetHash().IsNull());
}

BOOST_AUTO_TEST_CASE(lazy_signature_rejects_identity)
{
    std::vector<uint8_t> identityBytes(CBLSSignature::SerSize, 0);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss.write((const char*)identityBytes.data(), identityBytes.size());

    CBLSLazySignature lazy;
    lazy.Unserialize(ss);

    const CBLSSignature& sig = lazy.Get();
    BOOST_CHECK(!sig.IsValid());
    BOOST_CHECK(lazy.GetHash().IsNull());
}

BOOST_AUTO_TEST_CASE(lazy_wrapper_valid_roundtrip)
{
    // A valid key must survive the lazy path and produce a non-null hash.
    CBLSSecretKey sk;
    sk.MakeNewKey();
    CBLSPublicKey pk = sk.GetPublicKey();
    BOOST_CHECK(pk.IsValid());

    // Serialize the valid key, then deserialize through the lazy wrapper.
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss.write((const char*)pk.ToByteVector().data(), CBLSPublicKey::SerSize);

    CBLSLazyPublicKey lazy;
    lazy.Unserialize(ss);

    const CBLSPublicKey& recovered = lazy.Get();
    BOOST_CHECK(recovered.IsValid());
    BOOST_CHECK(recovered == pk);
    BOOST_CHECK(!lazy.GetHash().IsNull());
}

BOOST_AUTO_TEST_CASE(lazy_identity_cannot_influence_serialization)
{
    // After deserializing identity bytes, Serialize() must throw because the
    // wrapper is in an uninitialised state (neither buf nor obj is valid).
    std::vector<uint8_t> identityBytes(CBLSPublicKey::SerSize, 0);
    CDataStream ssIn(SER_NETWORK, PROTOCOL_VERSION);
    ssIn.write((const char*)identityBytes.data(), identityBytes.size());

    CBLSLazyPublicKey lazy;
    lazy.Unserialize(ssIn);

    CDataStream ssOut(SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK_THROW(lazy.Serialize(ssOut), std::ios_base::failure);
}

BOOST_AUTO_TEST_SUITE_END()
