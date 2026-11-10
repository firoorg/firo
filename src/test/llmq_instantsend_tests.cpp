// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/quorums_instantsend.h"

#include "bls/bls.h"
#include "dbwrapper.h"
#include "hash.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "version.h"

#include <boost/test/unit_test.hpp>

namespace
{

llmq::CInstantSendLock MakeLock(uint8_t nVersion)
{
    CBLSSecretKey sk;
    sk.MakeNewKey();

    llmq::CInstantSendLock islock(nVersion);
    islock.inputs.emplace_back(uint256S("11"), 1);
    islock.inputs.emplace_back(uint256S("12"), 0);
    islock.txid = uint256S("21");
    if (islock.IsDeterministic()) {
        islock.cycleHash = uint256S("31");
    }
    islock.sig.Set(sk.Sign(islock.txid));
    return islock;
}

std::vector<unsigned char> Serialize(const llmq::CInstantSendLock& islock)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << islock;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(llmq_instantsend_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(legacy_lock_keeps_its_wire_format)
{
    const llmq::CInstantSendLock islock = MakeLock(llmq::CInstantSendLock::LEGACY_VERSION);
    BOOST_CHECK(!islock.IsDeterministic());

    // inputs, txid, sig and nothing else
    CDataStream expected(SER_NETWORK, PROTOCOL_VERSION);
    expected << islock.inputs << islock.txid << islock.sig;
    const std::vector<unsigned char> bytes = Serialize(islock);
    BOOST_CHECK(bytes == std::vector<unsigned char>(expected.begin(), expected.end()));

    llmq::CInstantSendLock decoded;
    CDataStream ss(bytes, SER_NETWORK, PROTOCOL_VERSION);
    ss >> decoded;
    BOOST_CHECK(ss.empty());
    BOOST_CHECK(!decoded.IsDeterministic());
    BOOST_CHECK(decoded.inputs == islock.inputs);
    BOOST_CHECK(decoded.txid == islock.txid);
    BOOST_CHECK(decoded.cycleHash.IsNull());
    BOOST_CHECK(decoded.sig == islock.sig);
}

BOOST_AUTO_TEST_CASE(deterministic_lock_wire_format)
{
    const llmq::CInstantSendLock islock = MakeLock(llmq::CInstantSendLock::DETERMINISTIC_VERSION);
    BOOST_CHECK(islock.IsDeterministic());

    // DIP22: version, inputs, txid, cycleHash, sig
    CDataStream expected(SER_NETWORK, PROTOCOL_VERSION);
    expected << islock.nVersion << islock.inputs << islock.txid << islock.cycleHash << islock.sig;
    const std::vector<unsigned char> bytes = Serialize(islock);
    BOOST_CHECK(bytes == std::vector<unsigned char>(expected.begin(), expected.end()));
    BOOST_CHECK_EQUAL(bytes.front(), llmq::CInstantSendLock::DETERMINISTIC_VERSION);

    llmq::CInstantSendLock decoded(llmq::CInstantSendLock::DETERMINISTIC_VERSION);
    CDataStream ss(bytes, SER_NETWORK, PROTOCOL_VERSION);
    ss >> decoded;
    BOOST_CHECK(ss.empty());
    BOOST_CHECK_EQUAL(decoded.nVersion, llmq::CInstantSendLock::DETERMINISTIC_VERSION);
    BOOST_CHECK(decoded.inputs == islock.inputs);
    BOOST_CHECK(decoded.txid == islock.txid);
    BOOST_CHECK(decoded.cycleHash == islock.cycleHash);
    BOOST_CHECK(decoded.sig == islock.sig);

    // The cycleHash is part of the lock's identity, the request id is not affected by the format
    llmq::CInstantSendLock legacy = MakeLock(llmq::CInstantSendLock::LEGACY_VERSION);
    BOOST_CHECK(islock.GetRequestId() == legacy.GetRequestId());
    llmq::CInstantSendLock otherCycle = islock;
    otherCycle.cycleHash = uint256S("32");
    BOOST_CHECK(::SerializeHash(otherCycle) != ::SerializeHash(islock));
}

BOOST_AUTO_TEST_CASE(deterministic_reader_reports_the_version_it_read)
{
    // A reader that expects a deterministic lock still consumes the whole message when the version byte is unknown,
    // and is left with that version so that it can reject the lock.
    for (uint8_t nVersion : {uint8_t(0), uint8_t(2)}) {
        llmq::CInstantSendLock islock = MakeLock(llmq::CInstantSendLock::DETERMINISTIC_VERSION);
        std::vector<unsigned char> bytes = Serialize(islock);
        bytes[0] = nVersion;

        llmq::CInstantSendLock decoded(llmq::CInstantSendLock::DETERMINISTIC_VERSION);
        CDataStream ss(bytes, SER_NETWORK, PROTOCOL_VERSION);
        ss >> decoded;
        BOOST_CHECK(ss.empty());
        BOOST_CHECK_EQUAL(decoded.nVersion, nVersion);
        BOOST_CHECK(decoded.nVersion != llmq::CInstantSendLock::DETERMINISTIC_VERSION);
    }
}

BOOST_AUTO_TEST_CASE(db_reads_both_formats)
{
    CDBWrapper db("", 1 << 20, true, true);

    // A legacy lock with a single input starts with the byte 0x01, like a deterministic lock does
    llmq::CInstantSendLock legacy = MakeLock(llmq::CInstantSendLock::LEGACY_VERSION);
    legacy.inputs.resize(1);
    BOOST_CHECK_EQUAL(Serialize(legacy).front(), llmq::CInstantSendLock::DETERMINISTIC_VERSION);
    llmq::CInstantSendLock deterministic = MakeLock(llmq::CInstantSendLock::DETERMINISTIC_VERSION);
    deterministic.txid = uint256S("22");
    deterministic.inputs = {COutPoint(uint256S("13"), 0)};
    const uint256 legacyHash = ::SerializeHash(legacy);
    const uint256 deterministicHash = ::SerializeHash(deterministic);

    {
        llmq::CInstantSendDb writer(db);
        writer.WriteNewInstantSendLock(legacyHash, legacy);
        writer.WriteNewInstantSendLock(deterministicHash, deterministic);
    }

    // a new instance has empty caches, so everything is read from disk
    llmq::CInstantSendDb reader(db);
    BOOST_CHECK_EQUAL(reader.GetInstantSendLockCount(), 2U);

    llmq::CInstantSendLockPtr readLegacy = reader.GetInstantSendLockByHash(legacyHash);
    BOOST_REQUIRE(readLegacy);
    BOOST_CHECK(!readLegacy->IsDeterministic());
    BOOST_CHECK(::SerializeHash(*readLegacy) == legacyHash);
    BOOST_CHECK(readLegacy->sig == legacy.sig);

    llmq::CInstantSendLockPtr readDeterministic = reader.GetInstantSendLockByTxid(deterministic.txid);
    BOOST_REQUIRE(readDeterministic);
    BOOST_CHECK(readDeterministic->IsDeterministic());
    BOOST_CHECK(readDeterministic->cycleHash == deterministic.cycleHash);
    BOOST_CHECK(::SerializeHash(*readDeterministic) == deterministicHash);

    llmq::CInstantSendLockPtr byInput = reader.GetInstantSendLockByInput(deterministic.inputs[0]);
    BOOST_REQUIRE(byInput);
    BOOST_CHECK(::SerializeHash(*byInput) == deterministicHash);

    BOOST_CHECK(!reader.GetInstantSendLockByHash(uint256S("99")));

    // Deterministic locks have their own prefix, so software that only knows legacy locks does not find them
    llmq::CInstantSendLock misread;
    BOOST_CHECK(db.Read(std::make_tuple(std::string("is_i"), legacyHash), misread));
    BOOST_CHECK(!db.Exists(std::make_tuple(std::string("is_i"), deterministicHash)));
    BOOST_CHECK(db.Exists(std::make_tuple(std::string("is_d"), deterministicHash)));

    CDBBatch batch(db);
    reader.RemoveInstantSendLock(batch, legacyHash, nullptr);
    reader.RemoveInstantSendLock(batch, deterministicHash, nullptr);
    db.WriteBatch(batch);
    llmq::CInstantSendDb afterRemoval(db);
    BOOST_CHECK_EQUAL(afterRemoval.GetInstantSendLockCount(), 0U);
    BOOST_CHECK(!afterRemoval.GetInstantSendLockByTxid(legacy.txid));
    BOOST_CHECK(!afterRemoval.GetInstantSendLockByInput(deterministic.inputs[0]));
}

BOOST_AUTO_TEST_SUITE_END()
