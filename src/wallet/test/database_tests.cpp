// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/testutil.h"
#include "wallet/db.h"
#include "wallet/test/wallet_test_fixture.h"
#include "wallet/wallet.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/filesystem/fstream.hpp>

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

class WalletDatabasePathTestingSetup : public BasicTestingSetup
{
private:
    fs::path m_path;

public:
    WalletDatabasePathTestingSetup()
        : BasicTestingSetup(CBaseChainParams::MAIN)
    {
        bitdb.Close();
        bitdb.Reset();
        ClearDatadirCache();
        m_path = GetTempPath() / strprintf("wallet_database_policy_%d_%d", GetTime(), GetRand(100000));
        fs::create_directories(m_path);
        ForceSetArg("-datadir", m_path.string());
        ClearDatadirCache();
    }

    ~WalletDatabasePathTestingSetup()
    {
        bitdb.Close();
        bitdb.Reset();
        ClearDatadirCache();
        fs::remove_all(m_path);
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

void WriteFile(const fs::path& path, const std::string& contents)
{
    fs::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot create test wallet file");
    }
    file.write(contents.data(), contents.size());
    if (!file.good()) {
        throw std::runtime_error("Cannot write test wallet file");
    }
}

std::string ReadFile(const fs::path& path)
{
    fs::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot read test wallet file");
    }
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
} // namespace

BOOST_FIXTURE_TEST_CASE(wallet_database_factory_preopen_policy, WalletDatabasePathTestingSetup)
{
    const fs::path environmentPath = GetDataDir() / "database";
    BOOST_REQUIRE(!fs::exists(environmentPath));

    auto expectFailure = [&environmentPath](
                             const std::string& filename,
                             const DatabaseOptions& options,
                             DatabaseStatus expectedStatus) {
        DatabaseStatus status = DatabaseStatus::SUCCESS;
        std::string error{"unchanged"};
        std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(filename, options, status, error);
        BOOST_CHECK(!database);
        BOOST_CHECK(status == expectedStatus);
        BOOST_CHECK(!error.empty());
        BOOST_CHECK_NE(error, "unchanged");
        BOOST_CHECK(!fs::exists(environmentPath));
    };

    const DatabaseOptions defaults;
    DatabaseOptions requireCreate;
    requireCreate.require_create = true;
    const std::string escapedFilename = strprintf("../escaped_wallet_%d.dat", GetRand(100000));
    const fs::path escapedPath = GetDataDir() / escapedFilename;
    BOOST_REQUIRE(!fs::exists(escapedPath));
    expectFailure(escapedFilename, defaults, DatabaseStatus::FAILED_BAD_PATH);
    BOOST_CHECK(!fs::exists(escapedPath));

    DatabaseOptions requireExisting;
    requireExisting.require_existing = true;
    expectFailure("missing_wallet.dat", requireExisting, DatabaseStatus::FAILED_NOT_FOUND);

    const std::string unknownFilename{"unknown_wallet.dat"};
    const fs::path unknownPath = GetDataDir() / unknownFilename;
    const std::string unknownContents{"not a wallet database"};
    WriteFile(unknownPath, unknownContents);
    expectFailure(unknownFilename, requireCreate, DatabaseStatus::FAILED_ALREADY_EXISTS);
    expectFailure(unknownFilename, defaults, DatabaseStatus::FAILED_BAD_FORMAT);
    BOOST_CHECK_EQUAL(ReadFile(unknownPath), unknownContents);
    BOOST_CHECK(fs::remove(unknownPath));

    static constexpr std::array<char, 16> SQLITE_MAGIC{{
        'S',
        'Q',
        'L',
        'i',
        't',
        'e',
        ' ',
        'f',
        'o',
        'r',
        'm',
        'a',
        't',
        ' ',
        '3',
        '\0',
    }};
    const std::string truncatedSQLiteFilename{"truncated_sqlite_wallet.dat"};
    const fs::path truncatedSQLitePath = GetDataDir() / truncatedSQLiteFilename;
    const std::string truncatedSQLiteContents(SQLITE_MAGIC.begin(), SQLITE_MAGIC.end());
    WriteFile(truncatedSQLitePath, truncatedSQLiteContents);
    expectFailure(truncatedSQLiteFilename, defaults, DatabaseStatus::FAILED_UNSUPPORTED);
    BOOST_CHECK_EQUAL(ReadFile(truncatedSQLitePath), truncatedSQLiteContents);

    DatabaseOptions salvage;
    salvage.salvage = true;
    expectFailure(truncatedSQLiteFilename, salvage, DatabaseStatus::FAILED_UNSUPPORTED);
    BOOST_CHECK_EQUAL(ReadFile(truncatedSQLitePath), truncatedSQLiteContents);
    BOOST_CHECK(fs::remove(truncatedSQLitePath));

    const std::string danglingFilename{"dangling_wallet.dat"};
    const fs::path danglingPath = GetDataDir() / danglingFilename;
    const fs::path missingTarget = GetDataDir() / "missing_symlink_target.dat";
    bool pathExists = true;
    std::string pathError;
    BOOST_CHECK(WalletDatabasePathExists(missingTarget, pathExists, pathError));
    BOOST_CHECK(!pathExists);
    BOOST_CHECK(pathError.empty());

    boost::system::error_code symlinkError;
    fs::create_symlink(missingTarget, danglingPath, symlinkError);
    if (!symlinkError) {
        pathExists = false;
        BOOST_CHECK(WalletDatabasePathExists(danglingPath, pathExists, pathError));
        BOOST_CHECK(pathExists);
        BOOST_CHECK(pathError.empty());
        expectFailure(danglingFilename, defaults, DatabaseStatus::FAILED_BAD_PATH);
        BOOST_CHECK(fs::remove(danglingPath));
    } else {
        BOOST_TEST_MESSAGE("Skipping dangling-symlink checks: " << symlinkError.message());
    }
}

BOOST_FIXTURE_TEST_SUITE(wallet_database_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(berkeley_owner_contract)
{
    auto dummy = MakeDummyWalletDatabase();
    {
        auto batch = dummy->MakeBatch();
        BOOST_REQUIRE(batch);
        BOOST_CHECK(!batch->Write(std::string("key"), std::string("value")));
        batch->Flush();
        batch->Close();
        batch->Close();
    }
    BOOST_CHECK(dummy->Filename().empty());
    BOOST_CHECK(!dummy->Backup("unused"));
    BOOST_CHECK(!dummy->PeriodicFlush());
    BOOST_CHECK(dummy->Rewrite());
    dummy->Flush(false);
    {
        LOCK(bitdb.cs_db);
        BOOST_CHECK(bitdb.mapFileUseCount.count("") == 0);
    }

    const std::string filename{"database_owner_test.dat"};
    auto database = MakeBerkeleyDatabase(bitdb, filename);
    {
        LOCK(bitdb.cs_db);
        BOOST_CHECK(bitdb.mapFileUseCount.count(filename) == 0);
    }

    BOOST_CHECK_THROW(database->MakeBatch(), std::runtime_error);

    auto first = database->MakeBatch({DatabaseBatchMode::READ_WRITE_CREATE});
    BOOST_REQUIRE(first);
    BOOST_CHECK(first->Write(std::string("shared"), std::string("visible")));
    auto second = database->MakeBatch();
    BOOST_REQUIRE(second);
    std::string value;
    BOOST_CHECK(second->Read(std::string("shared"), value));
    BOOST_CHECK_EQUAL(value, "visible");
    {
        LOCK(bitdb.cs_db);
        BOOST_REQUIRE(bitdb.mapFileUseCount.count(filename) == 1);
        BOOST_CHECK_EQUAL(bitdb.mapFileUseCount.at(filename), 2);
    }
    BOOST_CHECK(!database->PeriodicFlush());

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
    BOOST_CHECK(database->PeriodicFlush());
    {
        LOCK(bitdb.cs_db);
        BOOST_CHECK(bitdb.mapFileUseCount.count(filename) == 0);
    }

    {
        auto reopened = database->MakeBatch({DatabaseBatchMode::READ_ONLY});
        BOOST_REQUIRE(reopened);
        BOOST_CHECK(reopened->Read(std::string("shared"), value));
        BOOST_CHECK_EQUAL(value, "visible");
    }
    BOOST_CHECK(database->PeriodicFlush());
    BOOST_CHECK(bitdb.RemoveDb(filename));
}

BOOST_AUTO_TEST_CASE(wallet_database_factory_policy)
{
    auto makeDatabase = [](const std::string& filename, const DatabaseOptions& options, DatabaseStatus& status, std::string& error) {
        error = "unchanged";
        std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(filename, options, status, error);
        if (database) {
            BOOST_CHECK(error.empty());
        } else {
            BOOST_CHECK(!error.empty());
            BOOST_CHECK_NE(error, "unchanged");
        }
        return database;
    };

    DatabaseStatus status;
    std::string error;
    const DatabaseOptions defaults;

    for (const char* invalid : {"", ".", "..", "../wallet.dat", "subdir/wallet.dat", "subdir\\wallet.dat", "/wallet.dat", "wallet:bad.dat"}) {
        BOOST_CHECK(!makeDatabase(invalid, defaults, status, error));
        BOOST_CHECK(status == DatabaseStatus::FAILED_BAD_PATH);
        BOOST_CHECK(!error.empty());
    }

    DatabaseOptions contradictory;
    contradictory.require_existing = true;
    contradictory.require_create = true;
    BOOST_CHECK(!makeDatabase("factory_options_test.dat", contradictory, status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_INVALID_OPTIONS);

    const std::string missingFilename{"factory_missing_test.dat"};
    const fs::path missingPath = GetDataDir() / missingFilename;
    BOOST_REQUIRE(!fs::exists(missingPath));

    DatabaseOptions requireExisting;
    requireExisting.require_existing = true;
    BOOST_CHECK(!makeDatabase(missingFilename, requireExisting, status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_NOT_FOUND);
    BOOST_CHECK(!fs::exists(missingPath));

    DatabaseOptions requireCreate;
    requireCreate.require_create = true;
    std::unique_ptr<WalletDatabase> missingDatabase = makeDatabase(missingFilename, requireCreate, status, error);
    BOOST_REQUIRE(missingDatabase);
    BOOST_CHECK(status == DatabaseStatus::SUCCESS);
    BOOST_CHECK(missingDatabase->Format() == DatabaseFormat::BERKELEY);
    BOOST_CHECK(!fs::exists(missingPath));
    missingDatabase.reset();

    DatabaseOptions requireSQLite;
    requireSQLite.require_create = true;
    requireSQLite.require_format = DatabaseFormat::SQLITE;
    BOOST_CHECK(!makeDatabase(missingFilename, requireSQLite, status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_UNSUPPORTED);
    BOOST_CHECK(!fs::exists(missingPath));

    std::unique_ptr<WalletDatabase> defaultDatabase = makeDatabase(missingFilename, defaults, status, error);
    BOOST_REQUIRE(defaultDatabase);
    BOOST_CHECK(status == DatabaseStatus::SUCCESS);
    BOOST_CHECK(defaultDatabase->Format() == DatabaseFormat::BERKELEY);
    BOOST_CHECK(!fs::exists(missingPath));
    {
        std::unique_ptr<DatabaseBatch> batch = defaultDatabase->MakeBatch({DatabaseBatchMode::READ_WRITE_CREATE});
        BOOST_REQUIRE(batch);
        BOOST_REQUIRE(batch->Write(std::string("default-key"), std::string("default-value")));
    }
    BOOST_REQUIRE(defaultDatabase->PeriodicFlush());
    defaultDatabase.reset();

    std::unique_ptr<WalletDatabase> defaultReopened = makeDatabase(missingFilename, requireExisting, status, error);
    BOOST_REQUIRE(defaultReopened);
    {
        std::unique_ptr<DatabaseBatch> batch = defaultReopened->MakeBatch({DatabaseBatchMode::READ_ONLY});
        BOOST_REQUIRE(batch);
        std::string value;
        BOOST_CHECK(batch->Read(std::string("default-key"), value));
        BOOST_CHECK_EQUAL(value, "default-value");
    }
    BOOST_REQUIRE(defaultReopened->PeriodicFlush());
    defaultReopened.reset();
    BOOST_CHECK(bitdb.RemoveDb(missingFilename));

    const std::string unknownFilename{"factory_unknown_test.dat"};
    const fs::path unknownPath = GetDataDir() / unknownFilename;
    const std::string unknownContents{"not a wallet database"};
    WriteFile(unknownPath, unknownContents);
    BOOST_CHECK(!makeDatabase(unknownFilename, defaults, status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_BAD_FORMAT);
    BOOST_CHECK_EQUAL(ReadFile(unknownPath), unknownContents);
    BOOST_CHECK(fs::remove(unknownPath));

    const std::string directoryFilename{"factory_directory_test.dat"};
    const fs::path directoryPath = GetDataDir() / directoryFilename;
    BOOST_REQUIRE(fs::create_directory(directoryPath));
    BOOST_CHECK(!makeDatabase(directoryFilename, defaults, status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_BAD_PATH);
    BOOST_CHECK(fs::remove(directoryPath));

    const std::string symlinkTargetFilename{"factory_symlink_target.dat"};
    const std::string symlinkFilename{"factory_symlink_test.dat"};
    const fs::path symlinkTargetPath = GetDataDir() / symlinkTargetFilename;
    const fs::path symlinkPath = GetDataDir() / symlinkFilename;
    WriteFile(symlinkTargetPath, unknownContents);
    boost::system::error_code symlinkError;
    fs::create_symlink(symlinkTargetPath, symlinkPath, symlinkError);
    if (!symlinkError) {
        BOOST_CHECK(!makeDatabase(symlinkFilename, defaults, status, error));
        BOOST_CHECK(status == DatabaseStatus::FAILED_BAD_PATH);
        BOOST_CHECK_EQUAL(ReadFile(symlinkTargetPath), unknownContents);
        BOOST_CHECK(fs::remove(symlinkPath));
    } else {
        BOOST_TEST_MESSAGE("Skipping symlink-target checks: " << symlinkError.message());
    }
    BOOST_CHECK(fs::remove(symlinkTargetPath));

    const std::string sqliteFilename{"factory_sqlite_test.dat"};
    const fs::path sqlitePath = GetDataDir() / sqliteFilename;
    std::string sqliteContents(512, '\0');
    static constexpr std::array<char, 16> SQLITE_MAGIC{{
        'S',
        'Q',
        'L',
        'i',
        't',
        'e',
        ' ',
        'f',
        'o',
        'r',
        'm',
        'a',
        't',
        ' ',
        '3',
        '\0',
    }};
    std::copy(SQLITE_MAGIC.begin(), SQLITE_MAGIC.end(), sqliteContents.begin());
    WriteFile(sqlitePath, sqliteContents);
    BOOST_CHECK(!makeDatabase(sqliteFilename, defaults, status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_UNSUPPORTED);
    BOOST_CHECK_EQUAL(ReadFile(sqlitePath), sqliteContents);

    DatabaseOptions requireBerkeley;
    requireBerkeley.require_format = DatabaseFormat::BERKELEY;
    BOOST_CHECK(!makeDatabase(sqliteFilename, requireBerkeley, status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_BAD_FORMAT);
    BOOST_CHECK_EQUAL(ReadFile(sqlitePath), sqliteContents);
    BOOST_CHECK(fs::remove(sqlitePath));

    const std::string berkeleyFilename{"factory_berkeley_test.dat"};
    const fs::path berkeleyPath = GetDataDir() / berkeleyFilename;
    std::unique_ptr<WalletDatabase> created = MakeBerkeleyDatabase(bitdb, berkeleyFilename);
    {
        std::unique_ptr<DatabaseBatch> batch = created->MakeBatch({DatabaseBatchMode::READ_WRITE_CREATE});
        BOOST_REQUIRE(batch);
        BOOST_REQUIRE(batch->Write(std::string("factory-key"), std::string("factory-value")));
    }
    BOOST_REQUIRE(created->PeriodicFlush());
    BOOST_REQUIRE(fs::exists(berkeleyPath));

    BOOST_CHECK(!makeDatabase(berkeleyFilename, requireCreate, status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_ALREADY_EXISTS);

    std::unique_ptr<WalletDatabase> reopened = makeDatabase(berkeleyFilename, requireExisting, status, error);
    BOOST_REQUIRE(reopened);
    BOOST_CHECK(status == DatabaseStatus::SUCCESS);
    BOOST_CHECK(reopened->Format() == DatabaseFormat::BERKELEY);
    {
        std::unique_ptr<DatabaseBatch> batch = reopened->MakeBatch({DatabaseBatchMode::READ_ONLY});
        BOOST_REQUIRE(batch);
        std::string value;
        BOOST_CHECK(batch->Read(std::string("factory-key"), value));
        BOOST_CHECK_EQUAL(value, "factory-value");
    }
    BOOST_REQUIRE(reopened->PeriodicFlush());
    reopened.reset();
    created.reset();
    BOOST_CHECK(bitdb.RemoveDb(berkeleyFilename));
}

BOOST_AUTO_TEST_CASE(wallet_database_factory_salvage)
{
    struct MockTimeReset {
        ~MockTimeReset() { SetMockTime(0); }
    } mockTimeReset;

    constexpr int64_t RECOVERY_TIME = 1900000000;
    SetMockTime(RECOVERY_TIME);

    const std::string filename{"factory_salvage_test.dat"};
    const std::string backupFilename = strprintf("wallet.%d.bak", RECOVERY_TIME);
    CKey key;
    key.MakeNewKey(true);
    const CPubKey publicKey = key.GetPubKey();

    {
        std::unique_ptr<WalletDatabase> database = MakeBerkeleyDatabase(bitdb, filename);
        {
            CWalletDB walletDatabase(*database, {DatabaseBatchMode::READ_WRITE_CREATE});
            BOOST_REQUIRE(walletDatabase.WriteKey(publicKey, key.GetPrivKey(), CKeyMetadata(RECOVERY_TIME)));
        }
        BOOST_REQUIRE(database->PeriodicFlush());
    }

    DatabaseOptions options;
    options.salvage = true;
    DatabaseStatus status;
    std::string error;
    std::unique_ptr<WalletDatabase> recovered = MakeWalletDatabase(filename, options, status, error);
    BOOST_REQUIRE(recovered);
    BOOST_CHECK(status == DatabaseStatus::SUCCESS_SALVAGED);
    BOOST_CHECK(fs::exists(GetDataDir() / backupFilename));

    {
        CWallet wallet(std::move(recovered));
        bool firstRun;
        BOOST_REQUIRE(wallet.LoadWallet(firstRun) == DB_LOAD_OK);
        BOOST_CHECK(wallet.HaveKey(publicKey.GetID()));
        BOOST_REQUIRE(wallet.GetDatabase().PeriodicFlush());
    }

    BOOST_CHECK(bitdb.RemoveDb(filename));
    BOOST_CHECK(bitdb.RemoveDb(backupFilename));
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
        CWallet wallet(MakeBerkeleyDatabase(bitdb, filename));
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
        CWallet wallet(MakeBerkeleyDatabase(bitdb, filename));
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
        CWallet wallet(MakeBerkeleyDatabase(bitdb, filename));
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
