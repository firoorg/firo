// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/db.h"
#include "wallet/test/wallet_test_fixture.h"
#include "wallet/wallet.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace
{
using RawRecord = std::pair<std::string, std::string>;

class BerkeleyBatchForTest final : public CDB
{
public:
    BerkeleyBatchForTest(BerkeleyDatabase& database, const char* mode)
        : CDB(database, mode)
    {
    }

    ~BerkeleyBatchForTest() override = default;

    static bool RewriteWithRenameFailure(BerkeleyDatabase& database)
    {
        return RewriteInternal(database, nullptr, true);
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

BOOST_AUTO_TEST_CASE(berkeley_owner_contract)
{
    BerkeleyDatabase dummy;
    {
        BerkeleyBatchForTest batch(dummy, "r+");
        BOOST_CHECK(!batch.Write(std::string("key"), std::string("value")));
        batch.Flush();
        batch.Close();
        batch.Close();
    }
    BOOST_CHECK(!dummy.Backup("unused"));
    BOOST_CHECK(!dummy.PeriodicFlush());
    BOOST_CHECK(dummy.Rewrite());
    dummy.Flush(false);
    {
        LOCK(bitdb.cs_db);
        BOOST_CHECK(bitdb.mapFileUseCount.count("") == 0);
    }

    const std::string filename{"database_owner_test.dat"};
    BerkeleyDatabase database(bitdb, filename);
    {
        LOCK(bitdb.cs_db);
        BOOST_CHECK(bitdb.mapFileUseCount.count(filename) == 0);
    }

    auto first = std::make_unique<BerkeleyBatchForTest>(database, "cr+");
    BOOST_CHECK(first->Write(std::string("shared"), std::string("visible")));
    auto second = std::make_unique<BerkeleyBatchForTest>(database, "r+");
    std::string value;
    BOOST_CHECK(second->Read(std::string("shared"), value));
    BOOST_CHECK_EQUAL(value, "visible");
    {
        LOCK(bitdb.cs_db);
        BOOST_REQUIRE(bitdb.mapFileUseCount.count(filename) == 1);
        BOOST_CHECK_EQUAL(bitdb.mapFileUseCount.at(filename), 2);
    }
    BOOST_CHECK(!database.PeriodicFlush());

    first->Close();
    first->Close();
    {
        LOCK(bitdb.cs_db);
        BOOST_CHECK_EQUAL(bitdb.mapFileUseCount.at(filename), 1);
    }
    first.reset();
    {
        LOCK(bitdb.cs_db);
        BOOST_CHECK_EQUAL(bitdb.mapFileUseCount.at(filename), 1);
    }

    second.reset();
    {
        LOCK(bitdb.cs_db);
        BOOST_CHECK_EQUAL(bitdb.mapFileUseCount.at(filename), 0);
    }
    BOOST_CHECK(database.PeriodicFlush());
    {
        LOCK(bitdb.cs_db);
        BOOST_CHECK(bitdb.mapFileUseCount.count(filename) == 0);
    }

    {
        BerkeleyBatchForTest reopened(database, "r+");
        BOOST_CHECK(reopened.Read(std::string("shared"), value));
        BOOST_CHECK_EQUAL(value, "visible");
    }
    BOOST_CHECK(database.PeriodicFlush());
    BOOST_CHECK(bitdb.RemoveDb(filename));
}

BOOST_AUTO_TEST_CASE(berkeley_batch_contract)
{
    const std::string filename{"database_batch_test.dat"};
    const std::string binaryKey{"key\0\xff", 5};
    const std::string binaryValue{"value\0\xff", 7};
    BerkeleyDatabase database(bitdb, filename);

    {
        BerkeleyBatchForTest batch(database, "cr+");
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
        BerkeleyBatchForTest batch(database, "r+");
        std::string value;
        BOOST_CHECK(batch.Read(std::string("committed"), value));
        BOOST_CHECK_EQUAL(value, "visible");
        BOOST_CHECK(!batch.Exists(std::string("aborted")));
        BOOST_CHECK(!batch.Exists(std::string("rolled-back")));

        BOOST_CHECK(batch.TxnBegin());
        BOOST_CHECK(batch.Write(std::string("destructor-abort"), std::string("hidden")));
    }

    {
        BerkeleyBatchForTest batch(database, "r+");
        BOOST_CHECK(!batch.Exists(std::string("destructor-abort")));
    }

    std::vector<RawRecord> expectedRecords;
    {
        BerkeleyBatchForTest batch(database, "r+");
        expectedRecords = ReadRawRecords(batch);
    }

    const std::string staleRewriteFilename = filename + ".rewrite";
    {
        BerkeleyDatabase staleDatabase(bitdb, staleRewriteFilename);
        BerkeleyBatchForTest staleRewrite(staleDatabase, "cr+");
        BOOST_CHECK(staleRewrite.Write(std::string("stale"), std::string("candidate")));
    }
    bitdb.CloseDb(staleRewriteFilename);
    BOOST_CHECK(!database.Rewrite());
    {
        BerkeleyBatchForTest batch(database, "r+");
        BOOST_CHECK(ReadRawRecords(batch) == expectedRecords);
    }
    BOOST_CHECK(bitdb.RemoveDb(staleRewriteFilename));

    BOOST_CHECK(!BerkeleyBatchForTest::RewriteWithRenameFailure(database));
    {
        BerkeleyBatchForTest batch(database, "r+");
        BOOST_CHECK(ReadRawRecords(batch) == expectedRecords);
    }
    BOOST_CHECK(bitdb.RemoveDb(staleRewriteFilename));

    const std::string versionKey = SerializeToString(std::string("version"));
    const auto versionRecord = std::find_if(expectedRecords.begin(), expectedRecords.end(), [&](const RawRecord& record) {
        return record.first == versionKey;
    });
    BOOST_REQUIRE(versionRecord != expectedRecords.end());
    versionRecord->second = SerializeToString(CLIENT_VERSION);

    BOOST_CHECK(database.Rewrite());

    {
        BerkeleyBatchForTest batch(database, "r+");
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
    BOOST_CHECK(database.Rewrite(poolPrefix.c_str()));

    {
        BerkeleyBatchForTest batch(database, "r+");
        BOOST_CHECK(ReadRawRecords(batch) == expectedRecords);
        BOOST_CHECK(!batch.Exists(std::make_pair(std::string("pool"), int64_t{1})));
    }

    BOOST_CHECK(bitdb.RemoveDb(filename));
}

BOOST_AUTO_TEST_CASE(wallet_mnemonic_encryption_persists)
{
    const std::string filename{"wallet_mnemonic_encryption_test.dat"};
    const SecureString passphrase{"test passphrase"};
    const SecureString newPassphrase{"new test passphrase"};
    const SecureString finalPassphrase{"final test passphrase"};
    const SecureString wrongPassphrase{"wrong test passphrase"};
    SecureString expectedMnemonic;
    SecureVector expectedSeed;

    {
        CWallet wallet(std::make_unique<BerkeleyDatabase>(bitdb, filename));
        bool firstRun;
        BOOST_REQUIRE(wallet.LoadWallet(firstRun) == DB_LOAD_OK);
        BOOST_REQUIRE(firstRun);

        wallet.GenerateNewMnemonic();
        CPubKey defaultKey;
        {
            LOCK(wallet.cs_wallet);
            defaultKey = wallet.GenerateNewKey();
        }
        BOOST_REQUIRE(wallet.SetDefaultKey(defaultKey));

        const MnemonicContainer& mnemonic = wallet.GetMnemonicContainer();
        BOOST_REQUIRE(mnemonic.GetMnemonic(expectedMnemonic));
        expectedSeed = mnemonic.GetSeed();
        BOOST_REQUIRE(!expectedMnemonic.empty());
        BOOST_REQUIRE(!expectedSeed.empty());

        BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
        BOOST_CHECK(wallet.GetMnemonicContainer().IsCrypted());
        BOOST_REQUIRE(wallet.GetDatabase().PeriodicFlush());
    }

    {
        CWallet wallet(std::make_unique<BerkeleyDatabase>(bitdb, filename));
        bool firstRun;
        BOOST_REQUIRE(wallet.LoadWallet(firstRun) == DB_LOAD_OK);
        BOOST_CHECK(!firstRun);
        BOOST_CHECK(wallet.GetVersion() >= FEATURE_HD);
        BOOST_REQUIRE(wallet.GetMnemonicContainer().IsCrypted());
        BOOST_REQUIRE(wallet.Unlock(passphrase));

        MnemonicContainer decrypted;
        BOOST_REQUIRE(wallet.DecryptMnemonicContainer(decrypted));
        SecureString actualMnemonic;
        BOOST_REQUIRE(decrypted.GetMnemonic(actualMnemonic));
        BOOST_CHECK(actualMnemonic == expectedMnemonic);
        BOOST_CHECK(decrypted.GetSeed() == expectedSeed);

        BOOST_CHECK(!wallet.IsLocked());
        BOOST_CHECK(!wallet.ChangeWalletPassphrase(wrongPassphrase, newPassphrase));
        BOOST_CHECK(!wallet.IsLocked());
        BOOST_REQUIRE(wallet.ChangeWalletPassphrase(passphrase, newPassphrase));
        BOOST_CHECK(!wallet.IsLocked());
        BOOST_REQUIRE(wallet.Lock());
        BOOST_REQUIRE(wallet.ChangeWalletPassphrase(newPassphrase, finalPassphrase));
        BOOST_CHECK(wallet.IsLocked());
        BOOST_REQUIRE(wallet.GetDatabase().PeriodicFlush());
    }

    {
        CWallet wallet(std::make_unique<BerkeleyDatabase>(bitdb, filename));
        bool firstRun;
        BOOST_REQUIRE(wallet.LoadWallet(firstRun) == DB_LOAD_OK);
        BOOST_CHECK(!firstRun);
        BOOST_CHECK(!wallet.Unlock(passphrase));
        BOOST_CHECK(!wallet.Unlock(newPassphrase));
        BOOST_REQUIRE(wallet.Unlock(finalPassphrase));

        MnemonicContainer decrypted;
        BOOST_REQUIRE(wallet.DecryptMnemonicContainer(decrypted));
        SecureString actualMnemonic;
        BOOST_REQUIRE(decrypted.GetMnemonic(actualMnemonic));
        BOOST_CHECK(actualMnemonic == expectedMnemonic);
        BOOST_CHECK(decrypted.GetSeed() == expectedSeed);
        BOOST_REQUIRE(wallet.GetDatabase().PeriodicFlush());
    }

    BOOST_CHECK(bitdb.RemoveDb(filename));
}

BOOST_AUTO_TEST_SUITE_END()
