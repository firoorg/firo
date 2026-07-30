// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/db.h"
#include "wallet/test/wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace
{
using RawRecord = std::pair<std::string, std::string>;

class BerkeleyBatchForTest final : public CDB
{
public:
    BerkeleyBatchForTest(const std::string& filename, const char* mode)
        : CDB(filename, mode)
    {
    }

    ~BerkeleyBatchForTest() override = default;

    static bool RewriteWithRenameFailure(const std::string& filename)
    {
        return RewriteInternal(filename, nullptr, true);
    }
};

template <typename T>
std::string SerializeToString(const T& value)
{
    CDataStream stream(SER_DISK, CLIENT_VERSION);
    stream << value;
    return {stream.begin(), stream.end()};
}

std::vector<RawRecord> ReadRawRecords(DatabaseBatch& batch)
{
    auto cursor = batch.GetCursor();
    BOOST_REQUIRE(cursor);

    std::vector<RawRecord> records;
    while (true) {
        CDataStream keyStream(SER_DISK, CLIENT_VERSION);
        CDataStream valueStream(SER_DISK, CLIENT_VERSION);
        const DatabaseCursor::Status status = cursor->Next(keyStream, valueStream);
        if (status == DatabaseCursor::Status::DONE) {
            break;
        }
        BOOST_REQUIRE(status == DatabaseCursor::Status::MORE);
        records.emplace_back(
            std::string(keyStream.begin(), keyStream.end()),
            std::string(valueStream.begin(), valueStream.end()));
    }
    return records;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(wallet_database_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(berkeley_batch_contract)
{
    const std::string filename{"database_batch_test.dat"};
    const std::string binaryKey{"key\0\xff", 5};
    const std::string binaryValue{"value\0\xff", 7};

    {
        BerkeleyBatchForTest batch(filename, "cr+");
        BOOST_CHECK(batch.Write(binaryKey, binaryValue, false));
        BOOST_CHECK(!batch.Write(binaryKey, std::string("replacement"), false));

        std::string value;
        BOOST_CHECK(batch.Read(binaryKey, value));
        BOOST_CHECK_EQUAL(value, binaryValue);
        BOOST_CHECK(batch.Exists(binaryKey));

        BOOST_CHECK(batch.Write(binaryKey, std::string("replacement")));
        BOOST_CHECK(batch.Read(binaryKey, value));
        BOOST_CHECK_EQUAL(value, "replacement");

        BOOST_CHECK(batch.Write(std::string("erase-me"), std::string("temporary")));
        BOOST_CHECK(batch.Exists(std::string("erase-me")));
        BOOST_CHECK(batch.Erase(std::string("erase-me")));
        BOOST_CHECK(!batch.Exists(std::string("erase-me")));
        BOOST_CHECK(batch.Erase(std::string("erase-me")));
        BOOST_CHECK(batch.Erase(std::string("missing")));
        BOOST_CHECK(batch.Write(std::string("z"), std::string("length-first")));
        BOOST_CHECK(batch.Write(std::string("aa"), std::string("first")));
        BOOST_CHECK(batch.Write(std::string("bb"), std::string("second")));
        BOOST_CHECK(batch.Write(std::string("cc"), std::string("third")));

        auto cursor = batch.GetCursor();
        BOOST_REQUIRE(cursor);
        std::vector<std::string> orderedRawKeys;
        while (true) {
            CDataStream keyStream(SER_DISK, CLIENT_VERSION);
            CDataStream valueStream(SER_DISK, CLIENT_VERSION);
            const DatabaseCursor::Status status = cursor->Next(keyStream, valueStream);
            if (status == DatabaseCursor::Status::DONE) {
                break;
            }
            BOOST_REQUIRE(status == DatabaseCursor::Status::MORE);
            orderedRawKeys.emplace_back(keyStream.begin(), keyStream.end());
        }
        std::vector<std::string> expectedRawKeys{
            SerializeToString(binaryKey),
            SerializeToString(std::string("z")),
            SerializeToString(std::string("aa")),
            SerializeToString(std::string("bb")),
            SerializeToString(std::string("cc")),
            SerializeToString(std::string("version")),
        };
        std::sort(expectedRawKeys.begin(), expectedRawKeys.end());
        BOOST_CHECK(orderedRawKeys == expectedRawKeys);
        cursor.reset();

        BOOST_CHECK(batch.Write(std::make_pair(std::string("rangd"), uint32_t{0}), std::string("before")));
        BOOST_CHECK(batch.Write(std::make_pair(std::string("range"), uint32_t{2}), std::string("first-range")));
        BOOST_CHECK(batch.Write(std::make_pair(std::string("range"), uint32_t{4}), std::string("second-range")));
        BOOST_CHECK(batch.Write(std::make_pair(std::string("rangf"), uint32_t{0}), std::string("after")));
        CDataStream startKey(SER_DISK, CLIENT_VERSION);
        startKey << std::make_pair(std::string("range"), uint32_t{1});
        cursor = batch.GetCursor(startKey);
        BOOST_REQUIRE(cursor);

        std::vector<uint32_t> rangeKeys;
        while (true) {
            CDataStream keyStream(SER_DISK, CLIENT_VERSION);
            CDataStream valueStream(SER_DISK, CLIENT_VERSION);
            const DatabaseCursor::Status status = cursor->Next(keyStream, valueStream);
            BOOST_REQUIRE(status == DatabaseCursor::Status::MORE);

            std::string prefix;
            uint32_t key;
            keyStream >> prefix >> key;
            if (prefix != "range") {
                break;
            }
            rangeKeys.push_back(key);
        }
        const std::vector<uint32_t> expectedRangeKeys{2, 4};
        BOOST_CHECK(rangeKeys == expectedRangeKeys);
        cursor.reset();

        BOOST_CHECK(batch.TxnBegin());
        BOOST_CHECK(batch.HasActiveTxn());
        BOOST_CHECK(!batch.TxnBegin());
        BOOST_CHECK(batch.Write(std::string("aborted"), std::string("hidden")));
        BOOST_CHECK(batch.Exists(std::string("aborted")));
        BOOST_CHECK(batch.TxnAbort());
        BOOST_CHECK(!batch.HasActiveTxn());
        BOOST_CHECK(!batch.Exists(std::string("aborted")));
        BOOST_CHECK(!batch.TxnAbort());
        BOOST_CHECK(!batch.TxnCommit());

        BOOST_CHECK(batch.TxnBegin());
        BOOST_CHECK(batch.Write(std::string("committed"), std::string("visible")));
        BOOST_CHECK(batch.TxnCommit());
        BOOST_CHECK(!batch.HasActiveTxn());
        BOOST_CHECK(batch.Write(std::string("version"), 1));
        BOOST_CHECK(batch.Write(std::make_pair(std::string("version"), uint32_t{1}), std::string("opaque")));
        BOOST_CHECK(batch.Write(std::make_pair(std::string("pool"), int64_t{1}), std::string("skipped")));

        BOOST_CHECK(batch.TxnBegin());
        BOOST_CHECK(batch.Write(std::string("rolled-back"), std::string("temporary")));
        BOOST_CHECK(!batch.Write(binaryKey, std::string("duplicate"), false));
        BOOST_CHECK(batch.TxnAbort());
        BOOST_CHECK(!batch.Exists(std::string("rolled-back")));
    }

    {
        BerkeleyBatchForTest batch(filename, "r+");
        std::string value;
        BOOST_CHECK(batch.Read(std::string("committed"), value));
        BOOST_CHECK_EQUAL(value, "visible");
        BOOST_CHECK(!batch.Exists(std::string("aborted")));
        BOOST_CHECK(!batch.Exists(std::string("rolled-back")));

        BOOST_CHECK(batch.TxnBegin());
        BOOST_CHECK(batch.Write(std::string("destructor-abort"), std::string("hidden")));
    }

    {
        BerkeleyBatchForTest batch(filename, "r+");
        BOOST_CHECK(!batch.Exists(std::string("destructor-abort")));
    }

    std::vector<RawRecord> expectedRecords;
    {
        BerkeleyBatchForTest batch(filename, "r+");
        expectedRecords = ReadRawRecords(batch);
    }

    const std::string staleRewriteFilename = filename + ".rewrite";
    {
        BerkeleyBatchForTest staleRewrite(staleRewriteFilename, "cr+");
        BOOST_CHECK(staleRewrite.Write(std::string("stale"), std::string("candidate")));
    }
    bitdb.CloseDb(staleRewriteFilename);
    BOOST_CHECK(!CDB::Rewrite(filename));
    {
        BerkeleyBatchForTest batch(filename, "r+");
        BOOST_CHECK(ReadRawRecords(batch) == expectedRecords);
    }
    BOOST_CHECK(bitdb.RemoveDb(staleRewriteFilename));

    BOOST_CHECK(!BerkeleyBatchForTest::RewriteWithRenameFailure(filename));
    {
        BerkeleyBatchForTest batch(filename, "r+");
        BOOST_CHECK(ReadRawRecords(batch) == expectedRecords);
    }
    BOOST_CHECK(bitdb.RemoveDb(staleRewriteFilename));

    const std::string versionKey = SerializeToString(std::string("version"));
    const auto versionRecord = std::find_if(expectedRecords.begin(), expectedRecords.end(), [&](const RawRecord& record) {
        return record.first == versionKey;
    });
    BOOST_REQUIRE(versionRecord != expectedRecords.end());
    versionRecord->second = SerializeToString(CLIENT_VERSION);

    BOOST_CHECK(CDB::Rewrite(filename));

    {
        BerkeleyBatchForTest batch(filename, "r+");
        BOOST_CHECK(ReadRawRecords(batch) == expectedRecords);

        std::string value;
        BOOST_CHECK(batch.Read(binaryKey, value));
        BOOST_CHECK_EQUAL(value, "replacement");
        BOOST_CHECK(batch.Read(std::string("committed"), value));
        BOOST_CHECK_EQUAL(value, "visible");
        int version;
        BOOST_CHECK(batch.ReadVersion(version));
        BOOST_CHECK_EQUAL(version, CLIENT_VERSION);
        BOOST_CHECK(batch.Read(std::make_pair(std::string("version"), uint32_t{1}), value));
        BOOST_CHECK_EQUAL(value, "opaque");
    }

    const std::string poolPrefix{"\x04pool", 5};
    expectedRecords.erase(std::remove_if(expectedRecords.begin(), expectedRecords.end(), [&](const RawRecord& record) {
        return record.first.size() >= poolPrefix.size() &&
               record.first.compare(0, poolPrefix.size(), poolPrefix) == 0;
    }),
        expectedRecords.end());
    BOOST_CHECK(CDB::Rewrite(filename, poolPrefix.c_str()));

    {
        BerkeleyBatchForTest batch(filename, "r+");
        BOOST_CHECK(ReadRawRecords(batch) == expectedRecords);
        BOOST_CHECK(!batch.Exists(std::make_pair(std::string("pool"), int64_t{1})));
    }

    BOOST_CHECK(bitdb.RemoveDb(filename));
}

BOOST_AUTO_TEST_SUITE_END()
