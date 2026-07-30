// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "config/bitcoin-config.h"

#include "test/testutil.h"
#include "wallet/db.h"
#include "wallet/test/wallet_test_fixture.h"
#include "wallet/wallet.h"

#ifdef USE_SQLITE
#include "chainparams.h"
#include "crypto/common.h"
#include "wallet/sqlite.h"

#include <sqlite3.h>

#ifndef WIN32
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#endif

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <future>
#include <iterator>
#include <memory>
#include <optional>
#include <set>
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

#ifdef USE_SQLITE
bool ExecuteRawSQLite(
    const fs::path& path,
    const std::vector<std::string>& statements,
    bool create = false)
{
    if (sqlite3_initialize() != SQLITE_OK) {
        return false;
    }

    sqlite3* database = nullptr;
    const int flags = SQLITE_OPEN_FULLMUTEX |
                      SQLITE_OPEN_NOFOLLOW |
                      SQLITE_OPEN_READWRITE |
                      (create ? SQLITE_OPEN_CREATE : 0);
    int result = sqlite3_open_v2(path.string().c_str(), &database, flags, nullptr);
    if (result == SQLITE_OK) {
        for (const std::string& statement : statements) {
            result = sqlite3_exec(database, statement.c_str(), nullptr, nullptr, nullptr);
            if (result != SQLITE_OK) {
                break;
            }
        }
    }

    if (database && sqlite3_close(database) != SQLITE_OK) {
        result = SQLITE_BUSY;
    }
    if (sqlite3_shutdown() != SQLITE_OK) {
        result = SQLITE_BUSY;
    }
    return result == SQLITE_OK;
}

std::optional<int64_t> ReadRawSQLiteInteger(const fs::path& path, const char* statement)
{
    if (sqlite3_initialize() != SQLITE_OK) {
        return std::nullopt;
    }

    sqlite3* database = nullptr;
    sqlite3_stmt* prepared = nullptr;
    std::optional<int64_t> value;
    const int flags = SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_READWRITE;
    int result = sqlite3_open_v2(path.string().c_str(), &database, flags, nullptr);
    if (result == SQLITE_OK) {
        result = sqlite3_prepare_v2(database, statement, -1, &prepared, nullptr);
    }
    if (result == SQLITE_OK && sqlite3_step(prepared) == SQLITE_ROW) {
        value = sqlite3_column_int64(prepared, 0);
    }
    if (prepared && sqlite3_finalize(prepared) != SQLITE_OK) {
        value.reset();
    }
    if (database && sqlite3_close(database) != SQLITE_OK) {
        value.reset();
    }
    if (sqlite3_shutdown() != SQLITE_OK) {
        value.reset();
    }
    return value;
}

std::string ExpectedApplicationIdPragma()
{
    const uint32_t applicationId = ReadBE32(Params().MessageStart());
    return strprintf(
        "PRAGMA application_id = %d",
        static_cast<int32_t>(applicationId));
}

class BlockingSQLiteStatementExecutor final : public SQLiteStatementExecutor
{
private:
    const std::set<std::string> m_blocked;

public:
    explicit BlockingSQLiteStatementExecutor(std::set<std::string> blocked)
        : m_blocked(std::move(blocked))
    {
    }

    int Execute(sqlite3* database, const char* statement) override
    {
        if (m_blocked.count(statement) != 0) {
            return SQLITE_IOERR;
        }
        return SQLiteStatementExecutor::Execute(database, statement);
    }
};

class RollbackThenFailSQLiteStatementExecutor final : public SQLiteStatementExecutor
{
public:
    int Execute(sqlite3* database, const char* statement) override
    {
        if (std::string(statement) != "COMMIT TRANSACTION") {
            return SQLiteStatementExecutor::Execute(database, statement);
        }
        const int rollbackResult =
            SQLiteStatementExecutor::Execute(database, "ROLLBACK TRANSACTION");
        return rollbackResult == SQLITE_OK ? SQLITE_IOERR : rollbackResult;
    }
};

class ExecuteThenThrowSQLiteStatementExecutor final : public SQLiteStatementExecutor
{
private:
    const std::string m_target;

public:
    explicit ExecuteThenThrowSQLiteStatementExecutor(std::string target)
        : m_target(std::move(target))
    {
    }

    int Execute(sqlite3* database, const char* statement) override
    {
        const int result =
            SQLiteStatementExecutor::Execute(database, statement);
        if (result == SQLITE_OK && m_target == statement) {
            throw std::runtime_error("injected SQLite executor exception");
        }
        return result;
    }
};

void RemoveSQLiteTestFiles(const std::string& filename)
{
    const fs::path path = GetDataDir() / filename;
    for (const char* suffix : {"", "-journal", "-wal", "-shm"}) {
        boost::system::error_code error;
        fs::remove(path.string() + suffix, error);
    }
}

bool HasSQLiteTestCandidate(const std::string& filename)
{
    const std::string prefix = "." + filename + ".sqlite-";
    for (fs::directory_iterator entry(GetDataDir()), end;
        entry != end;
        ++entry) {
        if (entry->path().filename().string().find(prefix) == 0) {
            return true;
        }
    }
    return false;
}

void RemoveSQLiteTestCandidates(const std::string& filename)
{
    const std::string prefix = "." + filename + ".sqlite-";
    for (fs::directory_iterator entry(GetDataDir()), end;
        entry != end;) {
        const fs::path path = entry->path();
        ++entry;
        if (path.filename().string().find(prefix) == 0) {
            boost::system::error_code error;
            fs::remove(path, error);
        }
    }
}
#endif
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

#ifdef USE_SQLITE
BOOST_AUTO_TEST_CASE(sqlite_batch_transaction_rewrite_backup_contract)
{
    const std::string filename{"sqlite_batch_test.dat"};
    const std::string backupFilename{"sqlite_batch_test.backup"};
    const fs::path path = GetDataDir() / filename;
    const fs::path journalPath = path.string() + "-journal";
    const fs::path backupPath = GetDataDir() / backupFilename;
    const fs::path backupDirectory = GetDataDir() / "sqlite_backup_directory";
    const fs::path directoryBackupPath = backupDirectory / filename;
    const std::string binaryKey{"key\0\xff", 5};
    const std::string binaryValue{"value\0\xff", 7};
    RemoveSQLiteTestFiles(filename);
    RemoveSQLiteTestFiles(backupFilename);
    fs::remove_all(backupDirectory);

    DatabaseOptions createOptions;
    createOptions.require_create = true;
    createOptions.require_format = DatabaseFormat::SQLITE;
    DatabaseStatus status = DatabaseStatus::FAILED_LOAD;
    std::string error{"unchanged"};
    std::unique_ptr<WalletDatabase> database =
        MakeSQLiteDatabase(filename, createOptions, status, error);
    BOOST_REQUIRE(database);
    BOOST_CHECK(status == DatabaseStatus::SUCCESS);
    BOOST_CHECK(error.empty());
    BOOST_CHECK(database->Format() == DatabaseFormat::SQLITE);
    BOOST_CHECK_EQUAL(database->Filename(), filename);
    BOOST_REQUIRE(fs::is_regular_file(path));
#ifndef WIN32
    const fs::perms privatePermissions = fs::owner_read | fs::owner_write;
    BOOST_CHECK_EQUAL(
        fs::status(path).permissions() & (fs::group_all | fs::others_all),
        fs::no_perms);
    BOOST_CHECK_EQUAL(
        fs::status(path).permissions() & privatePermissions,
        privatePermissions);
#endif

    DatabaseOptions existingOptions;
    existingOptions.require_existing = true;
    existingOptions.require_format = DatabaseFormat::SQLITE;
    status = DatabaseStatus::SUCCESS;
    error = "unchanged";
    std::unique_ptr<WalletDatabase> competingOwner =
        MakeSQLiteDatabase(filename, existingOptions, status, error);
    BOOST_CHECK(!competingOwner);
    BOOST_CHECK(status == DatabaseStatus::FAILED_VERIFY);
    BOOST_CHECK(!error.empty());
    BOOST_CHECK_NE(error, "unchanged");

    std::unique_ptr<DatabaseBatch> batch =
        database->MakeBatch({DatabaseBatchMode::READ_WRITE_CREATE});
    BOOST_REQUIRE(batch);
    int64_t synchronousMode = -1;
    BOOST_REQUIRE(GetSQLiteSynchronousModeForTesting(
        *batch,
        synchronousMode));
    BOOST_CHECK_EQUAL(synchronousMode, 3);
    int version;
    BOOST_CHECK(batch->ReadVersion(version));
    BOOST_CHECK_EQUAL(version, CLIENT_VERSION);
    BOOST_CHECK(batch->Write(binaryKey, binaryValue, false));
    BOOST_CHECK(!batch->Write(binaryKey, std::string("replacement"), false));

    std::string value;
    BOOST_CHECK(batch->Read(binaryKey, value));
    BOOST_CHECK_EQUAL(value, binaryValue);
    BOOST_CHECK(batch->Exists(binaryKey));
    BOOST_CHECK(batch->Write(binaryKey, std::string("replacement")));
    BOOST_CHECK(batch->Read(binaryKey, value));
    BOOST_CHECK_EQUAL(value, "replacement");

    BOOST_CHECK(batch->Write(std::string("erase-me"), std::string("temporary")));
    BOOST_CHECK(batch->Erase(std::string("erase-me")));
    BOOST_CHECK(!batch->Exists(std::string("erase-me")));
    BOOST_CHECK(batch->Erase(std::string("erase-me")));
    BOOST_CHECK(batch->Erase(std::string("missing")));

    BOOST_CHECK(batch->Write(std::string("z"), std::string("length-first")));
    BOOST_CHECK(batch->Write(std::string("aa"), std::string("first")));
    BOOST_CHECK(batch->Write(std::string("bb"), std::string("second")));
    BOOST_CHECK(batch->Write(std::string("cc"), std::string("third")));
    auto cursor = batch->GetCursor();
    BOOST_REQUIRE(cursor);
    std::vector<std::string> orderedRawKeys;
    while (true) {
        CDataStream keyStream(SER_DISK, CLIENT_VERSION);
        CDataStream valueStream(SER_DISK, CLIENT_VERSION);
        const DatabaseCursor::Status cursorStatus = cursor->Next(keyStream, valueStream);
        if (cursorStatus == DatabaseCursor::Status::DONE) {
            break;
        }
        BOOST_REQUIRE(cursorStatus == DatabaseCursor::Status::MORE);
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

    BOOST_CHECK(batch->Write(std::make_pair(std::string("rangd"), uint32_t{0}), std::string("before")));
    BOOST_CHECK(batch->Write(std::make_pair(std::string("range"), uint32_t{2}), std::string("first-range")));
    BOOST_CHECK(batch->Write(std::make_pair(std::string("range"), uint32_t{4}), std::string("second-range")));
    BOOST_CHECK(batch->Write(std::make_pair(std::string("rangf"), uint32_t{0}), std::string("after")));
    CDataStream startKey(SER_DISK, CLIENT_VERSION);
    startKey << std::make_pair(std::string("range"), uint32_t{1});
    cursor = batch->GetCursor(startKey);
    BOOST_REQUIRE(cursor);
    std::vector<uint32_t> rangeKeys;
    while (true) {
        CDataStream keyStream(SER_DISK, CLIENT_VERSION);
        CDataStream valueStream(SER_DISK, CLIENT_VERSION);
        const DatabaseCursor::Status cursorStatus = cursor->Next(keyStream, valueStream);
        BOOST_REQUIRE(cursorStatus == DatabaseCursor::Status::MORE);
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

    BOOST_CHECK(batch->TxnBegin());
    BOOST_CHECK(batch->HasActiveTxn());
    BOOST_CHECK(!batch->TxnBegin());
    BOOST_CHECK(batch->Write(std::string("aborted"), std::string("hidden")));
    BOOST_CHECK(batch->Exists(std::string("aborted")));
    BOOST_CHECK(batch->TxnAbort());
    BOOST_CHECK(!batch->HasActiveTxn());
    BOOST_CHECK(!batch->Exists(std::string("aborted")));
    BOOST_CHECK(!batch->TxnAbort());
    BOOST_CHECK(!batch->TxnCommit());

    BOOST_REQUIRE(batch->TxnBegin());
    BOOST_REQUIRE(batch->Write(std::string("committed"), std::string("visible")));
    BOOST_REQUIRE(SetSQLiteStatementExecutorForTesting(
        *batch,
        std::make_unique<BlockingSQLiteStatementExecutor>(
            std::set<std::string>{"COMMIT TRANSACTION"})));
    BOOST_CHECK(!batch->TxnCommit());
    BOOST_CHECK(batch->HasActiveTxn());
    BOOST_CHECK(batch->Exists(std::string("committed")));
    BOOST_REQUIRE(batch->TxnAbort());
    BOOST_CHECK(!batch->HasActiveTxn());
    BOOST_CHECK(!batch->Exists(std::string("committed")));

    BOOST_REQUIRE(SetSQLiteStatementExecutorForTesting(
        *batch,
        std::make_unique<RollbackThenFailSQLiteStatementExecutor>()));
    BOOST_REQUIRE(batch->TxnBegin());
    BOOST_REQUIRE(batch->Write(
        std::string("auto-rollback"),
        std::string("must-stay-hidden")));
    BOOST_CHECK(!batch->TxnCommit());
    BOOST_CHECK(batch->HasActiveTxn());
    BOOST_CHECK(!batch->Write(
        std::string("must-not-autocommit"),
        std::string("rejected")));
    BOOST_REQUIRE(batch->TxnAbort());
    BOOST_CHECK(!batch->HasActiveTxn());
    BOOST_CHECK(!batch->Exists(std::string("auto-rollback")));
    BOOST_CHECK(!batch->Exists(std::string("must-not-autocommit")));

    BOOST_REQUIRE(SetSQLiteStatementExecutorForTesting(
        *batch,
        std::make_unique<ExecuteThenThrowSQLiteStatementExecutor>(
            "BEGIN TRANSACTION")));
    BOOST_CHECK(!batch->TxnBegin());
    BOOST_CHECK(!batch->HasActiveTxn());

    BOOST_REQUIRE(SetSQLiteStatementExecutorForTesting(
        *batch,
        std::make_unique<SQLiteStatementExecutor>()));
    BOOST_CHECK(batch->Write(
        std::string("after-begin-exception"),
        std::string("usable")));

    std::unique_ptr<DatabaseBatch> readBatch = database->MakeBatch();
    std::unique_ptr<DatabaseBatch> existsBatch = database->MakeBatch();
    std::unique_ptr<DatabaseBatch> cursorBatch = database->MakeBatch();
    BOOST_REQUIRE(readBatch);
    BOOST_REQUIRE(existsBatch);
    BOOST_REQUIRE(cursorBatch);

    BOOST_REQUIRE(batch->TxnBegin());
    BOOST_REQUIRE(batch->Write(
        std::string("cross-batch-abort"),
        std::string("hidden")));
    std::promise<void> readStarted;
    std::promise<void> existsStarted;
    std::promise<void> cursorStarted;
    std::future<std::pair<bool, std::string> > blockedRead = std::async(
        std::launch::async,
        [&readBatch, &readStarted] {
            readStarted.set_value();
            std::string readValue;
            const bool found = readBatch->Read(
                std::string("cross-batch-abort"),
                readValue);
            return std::make_pair(found, readValue);
        });
    std::future<bool> blockedExists = std::async(
        std::launch::async,
        [&existsBatch, &existsStarted] {
            existsStarted.set_value();
            return existsBatch->Exists(std::string("cross-batch-abort"));
        });
    std::future<bool> blockedCursor = std::async(
        std::launch::async,
        [&cursorBatch, &cursorStarted] {
            cursorStarted.set_value();
            return cursorBatch->GetCursor() != nullptr;
        });
    readStarted.get_future().wait();
    existsStarted.get_future().wait();
    cursorStarted.get_future().wait();
    BOOST_CHECK(blockedRead.wait_for(std::chrono::milliseconds{100}) == std::future_status::timeout);
    BOOST_CHECK(blockedExists.wait_for(std::chrono::milliseconds{100}) == std::future_status::timeout);
    BOOST_CHECK(blockedCursor.wait_for(std::chrono::milliseconds{100}) == std::future_status::timeout);
    BOOST_REQUIRE(batch->TxnAbort());
    const auto abortedRead = blockedRead.get();
    BOOST_CHECK(!abortedRead.first);
    BOOST_CHECK(abortedRead.second.empty());
    BOOST_CHECK(!blockedExists.get());
    BOOST_CHECK(blockedCursor.get());

    BOOST_REQUIRE(batch->TxnBegin());
    BOOST_REQUIRE(batch->Write(std::string("transaction-one"), std::string("first")));
    std::unique_ptr<DatabaseBatch> secondBatch = database->MakeBatch();
    BOOST_REQUIRE(secondBatch);
    BOOST_CHECK(!secondBatch->TxnCommit());
    BOOST_CHECK(!secondBatch->TxnAbort());

    std::promise<void> committedReadStarted;
    std::future<std::pair<bool, std::string> > committedRead = std::async(
        std::launch::async,
        [&readBatch, &committedReadStarted] {
            committedReadStarted.set_value();
            std::string readValue;
            const bool found =
                readBatch->Read(std::string("transaction-one"), readValue);
            return std::make_pair(found, readValue);
        });
    std::promise<void> writerStarted;
    std::future<bool> blockedWriter = std::async(
        std::launch::async,
        [&secondBatch, &writerStarted] {
            writerStarted.set_value();
            return secondBatch->Write(
                std::string("transaction-two"),
                std::string("second"));
        });
    committedReadStarted.get_future().wait();
    writerStarted.get_future().wait();
    BOOST_CHECK(committedRead.wait_for(std::chrono::milliseconds{100}) == std::future_status::timeout);
    BOOST_CHECK(blockedWriter.wait_for(std::chrono::milliseconds{100}) == std::future_status::timeout);
    BOOST_REQUIRE(batch->TxnCommit());
    const auto visibleRead = committedRead.get();
    BOOST_CHECK(visibleRead.first);
    BOOST_CHECK_EQUAL(visibleRead.second, "first");
    BOOST_CHECK(blockedWriter.get());
    BOOST_CHECK(secondBatch->Read(std::string("transaction-one"), value));
    BOOST_CHECK_EQUAL(value, "first");
    BOOST_CHECK(secondBatch->Read(std::string("transaction-two"), value));
    BOOST_CHECK_EQUAL(value, "second");

    cursor = cursorBatch->GetCursor();
    BOOST_REQUIRE(cursor);
    CDataStream heldCursorKey(SER_DISK, CLIENT_VERSION);
    CDataStream heldCursorValue(SER_DISK, CLIENT_VERSION);
    BOOST_REQUIRE(
        cursor->Next(heldCursorKey, heldCursorValue) ==
        DatabaseCursor::Status::MORE);
    std::promise<void> cursorWriterStarted;
    std::future<bool> cursorBlockedWriter = std::async(
        std::launch::async,
        [&secondBatch, &cursorWriterStarted] {
            cursorWriterStarted.set_value();
            return secondBatch->Write(
                std::string("after-cursor"),
                std::string("visible"));
        });
    cursorWriterStarted.get_future().wait();
    BOOST_CHECK(cursorBlockedWriter.wait_for(std::chrono::milliseconds{100}) == std::future_status::timeout);
    cursor.reset();
    BOOST_CHECK(cursorBlockedWriter.get());

    cursor = cursorBatch->GetCursor();
    BOOST_REQUIRE(cursor);
    std::future<void> cursorBatchClose = std::async(
        std::launch::async,
        [&cursorBatch] {
            cursorBatch->Close();
        });
    const std::future_status closeStatus =
        cursorBatchClose.wait_for(std::chrono::seconds{1});
    BOOST_CHECK(closeStatus == std::future_status::ready);
    if (closeStatus == std::future_status::ready) {
        CDataStream keyAfterBatchClose(SER_DISK, CLIENT_VERSION);
        CDataStream valueAfterBatchClose(SER_DISK, CLIENT_VERSION);
        BOOST_CHECK(
            cursor->Next(keyAfterBatchClose, valueAfterBatchClose) ==
            DatabaseCursor::Status::MORE);
    }
    cursor.reset();
    cursorBatchClose.get();

    readBatch.reset();
    existsBatch.reset();
    cursorBatch.reset();

    std::unique_ptr<DatabaseBatch> readOnly =
        database->MakeBatch({DatabaseBatchMode::READ_ONLY, false});
    BOOST_REQUIRE(readOnly);
    BOOST_CHECK(readOnly->Read(std::string("transaction-one"), value));
    BOOST_CHECK(!readOnly->Write(std::string("read-only"), std::string("rejected")));
    BOOST_CHECK(!readOnly->Erase(std::string("transaction-one")));
    BOOST_CHECK(!readOnly->TxnBegin());
    readOnly.reset();

    std::unique_ptr<DatabaseBatch> closedBatch = database->MakeBatch();
    BOOST_REQUIRE(closedBatch);
    closedBatch->Close();
    closedBatch->Close();
    BOOST_CHECK(!closedBatch->Read(std::string("transaction-one"), value));
    BOOST_CHECK(!closedBatch->Exists(std::string("transaction-one")));
    BOOST_CHECK(!closedBatch->Write(
        std::string("closed-write"),
        std::string("rejected")));
    BOOST_CHECK(!closedBatch->Erase(std::string("transaction-one")));
    BOOST_CHECK(!closedBatch->GetCursor());
    BOOST_CHECK(!closedBatch->TxnBegin());
    BOOST_CHECK(!closedBatch->TxnCommit());
    BOOST_CHECK(!closedBatch->TxnAbort());
    closedBatch.reset();

    secondBatch.reset();
    batch.reset();

    {
        std::unique_ptr<DatabaseBatch> destructorAbort = database->MakeBatch();
        BOOST_REQUIRE(destructorAbort->TxnBegin());
        BOOST_REQUIRE(destructorAbort->Write(
            std::string("destructor-abort"),
            std::string("hidden")));
    }
    batch = database->MakeBatch();
    BOOST_REQUIRE(batch);
    BOOST_CHECK(!batch->Exists(std::string("destructor-abort")));
    batch.reset();

    std::unique_ptr<DatabaseBatch> idleBatch = database->MakeBatch();
    BOOST_REQUIRE(idleBatch);
    BOOST_REQUIRE(idleBatch->Read(std::string("transaction-one"), value));
    BOOST_CHECK_EQUAL(value, "first");
    {
        std::unique_ptr<DatabaseBatch> failedAbort = database->MakeBatch();
        BOOST_REQUIRE(failedAbort->TxnBegin());
        BOOST_REQUIRE(failedAbort->Write(
            std::string("failed-destructor-abort"),
            std::string("hidden")));
        BOOST_REQUIRE(SetSQLiteStatementExecutorForTesting(
            *failedAbort,
            std::make_unique<BlockingSQLiteStatementExecutor>(
                std::set<std::string>{"ROLLBACK TRANSACTION"})));
    }
    BOOST_REQUIRE(idleBatch->Read(std::string("transaction-one"), value));
    BOOST_CHECK_EQUAL(value, "first");
    BOOST_CHECK(idleBatch->Write(
        std::string("idle-after-reset"),
        std::string("usable")));
    idleBatch.reset();

    batch = database->MakeBatch();
    BOOST_REQUIRE(batch);
    BOOST_CHECK(!batch->Exists(std::string("failed-destructor-abort")));
    BOOST_CHECK(batch->Write(std::string("after-reset"), std::string("usable")));
    BOOST_CHECK(batch->Read(std::string("idle-after-reset"), value));
    BOOST_CHECK_EQUAL(value, "usable");
    BOOST_CHECK(batch->Write(std::string("version"), 1));
    BOOST_CHECK(batch->Write(
        std::make_pair(std::string("version"), uint32_t{1}),
        std::string("opaque")));
    BOOST_CHECK(batch->Write(
        std::make_pair(std::string("pool"), int64_t{1}),
        std::string("skipped")));
    batch.reset();

    const std::string poolPrefix{"\x04pool", 5};
    BOOST_REQUIRE(database->Rewrite(poolPrefix.c_str()));
    batch = database->MakeBatch();
    BOOST_REQUIRE(batch);
    BOOST_CHECK(batch->ReadVersion(version));
    BOOST_CHECK_EQUAL(version, CLIENT_VERSION);
    BOOST_CHECK(batch->Read(
        std::make_pair(std::string("version"), uint32_t{1}),
        value));
    BOOST_CHECK_EQUAL(value, "opaque");
    BOOST_CHECK(!batch->Exists(std::make_pair(std::string("pool"), int64_t{1})));
    BOOST_CHECK(batch->Read(std::string("after-reset"), value));
    BOOST_CHECK_EQUAL(value, "usable");
    batch.reset();
    if (fs::exists(journalPath)) {
        BOOST_CHECK_EQUAL(fs::file_size(journalPath), 0U);
    }

    BOOST_REQUIRE(database->Backup(backupPath.string()));
    BOOST_REQUIRE(fs::is_regular_file(backupPath));
    const std::string firstBackup = ReadFile(backupPath);
    BOOST_CHECK(!database->Backup(backupPath.string()));
    BOOST_CHECK_EQUAL(ReadFile(backupPath), firstBackup);
#ifndef WIN32
    BOOST_CHECK_EQUAL(
        fs::status(backupPath).permissions() & (fs::group_all | fs::others_all),
        fs::no_perms);
#endif
    BOOST_REQUIRE(fs::create_directory(backupDirectory));
    BOOST_REQUIRE(database->Backup(backupDirectory.string()));
    BOOST_REQUIRE(fs::is_regular_file(directoryBackupPath));
    BOOST_CHECK(!database->Backup(backupDirectory.string()));
    database.reset();

    const std::optional<int64_t> directoryBackupApplicationId =
        ReadRawSQLiteInteger(directoryBackupPath, "PRAGMA application_id");
    BOOST_REQUIRE(directoryBackupApplicationId);
    BOOST_CHECK_EQUAL(
        *directoryBackupApplicationId,
        static_cast<int32_t>(ReadBE32(Params().MessageStart())));

    BOOST_REQUIRE(ExecuteRawSQLite(
        path,
        {"INSERT INTO main(key, value) VALUES(X'', X'')"}));
    error = "unchanged";
    database = MakeSQLiteDatabase(filename, existingOptions, status, error);
    BOOST_REQUIRE(database);
    BOOST_CHECK(status == DatabaseStatus::SUCCESS);
    BOOST_CHECK(error.empty());
    batch = database->MakeBatch();
    BOOST_REQUIRE(batch);
    cursor = batch->GetCursor();
    BOOST_REQUIRE(cursor);
    CDataStream emptyKey(SER_DISK, CLIENT_VERSION);
    CDataStream emptyValue(SER_DISK, CLIENT_VERSION);
    BOOST_CHECK(cursor->Next(emptyKey, emptyValue) == DatabaseCursor::Status::MORE);
    BOOST_CHECK(emptyKey.empty());
    BOOST_CHECK(emptyValue.empty());
    cursor.reset();
    batch.reset();
    database.reset();

    std::unique_ptr<WalletDatabase> backup =
        MakeSQLiteDatabase(backupFilename, existingOptions, status, error);
    BOOST_REQUIRE(backup);
    batch = backup->MakeBatch();
    BOOST_REQUIRE(batch);
    BOOST_CHECK(batch->Read(std::string("after-reset"), value));
    BOOST_CHECK_EQUAL(value, "usable");
    BOOST_CHECK(!batch->Exists(std::make_pair(std::string("pool"), int64_t{1})));
    batch.reset();
    backup.reset();

    RemoveSQLiteTestFiles(filename);
    RemoveSQLiteTestFiles(backupFilename);
    fs::remove_all(backupDirectory);
}

BOOST_AUTO_TEST_CASE(sqlite_indeterminate_executor_exception_poison)
{
    const std::string filename{"sqlite_executor_exception.dat"};
    RemoveSQLiteTestFiles(filename);

    DatabaseOptions createOptions;
    createOptions.require_create = true;
    createOptions.require_format = DatabaseFormat::SQLITE;
    DatabaseStatus status;
    std::string error;
    std::unique_ptr<WalletDatabase> database =
        MakeSQLiteDatabase(filename, createOptions, status, error);
    BOOST_REQUIRE(database);
    std::unique_ptr<DatabaseBatch> batch = database->MakeBatch();
    BOOST_REQUIRE(batch);
    BOOST_REQUIRE(SetSQLiteStatementExecutorForTesting(
        *batch,
        std::make_unique<ExecuteThenThrowSQLiteStatementExecutor>(
            "COMMIT TRANSACTION")));
    BOOST_REQUIRE(batch->TxnBegin());
    BOOST_REQUIRE(batch->Write(
        std::string("indeterminate-commit"),
        std::string("committed-before-exception")));
    BOOST_CHECK(!batch->TxnCommit());
    BOOST_CHECK(!batch->HasActiveTxn());
    BOOST_CHECK(!batch->Write(
        std::string("after-indeterminate-commit"),
        std::string("rejected")));
    BOOST_CHECK_THROW(database->MakeBatch(), std::runtime_error);
    batch.reset();
    database.reset();

    DatabaseOptions existingOptions;
    existingOptions.require_existing = true;
    existingOptions.require_format = DatabaseFormat::SQLITE;
    database = MakeSQLiteDatabase(
        filename,
        existingOptions,
        status,
        error);
    BOOST_REQUIRE(database);
    batch = database->MakeBatch();
    BOOST_REQUIRE(batch);
    std::string value;
    BOOST_CHECK(batch->Read(
        std::string("indeterminate-commit"),
        value));
    BOOST_CHECK_EQUAL(value, "committed-before-exception");
    BOOST_CHECK(!batch->Exists(
        std::string("after-indeterminate-commit")));
    batch.reset();
    database.reset();
    RemoveSQLiteTestFiles(filename);
}

BOOST_AUTO_TEST_CASE(sqlite_post_publish_failure_cleanup)
{
    const std::string createFilename{
        "sqlite_failed_publication_create.dat"};
    const std::string ambiguousFilename{
        "sqlite_ambiguous_publication_create.dat"};
    const std::string sourceFilename{
        "sqlite_failed_publication_source.dat"};
    const std::string backupFilename{
        "sqlite_failed_publication_backup.dat"};
    RemoveSQLiteTestFiles(createFilename);
    RemoveSQLiteTestFiles(ambiguousFilename);
    RemoveSQLiteTestFiles(sourceFilename);
    RemoveSQLiteTestFiles(backupFilename);

    DatabaseOptions createOptions;
    createOptions.require_create = true;
    createOptions.require_format = DatabaseFormat::SQLITE;
    DatabaseStatus status = DatabaseStatus::SUCCESS;
    std::string error{"unchanged"};
    InjectSQLitePostPublishFailureForTesting();
    std::unique_ptr<WalletDatabase> database = MakeSQLiteDatabase(
        createFilename,
        createOptions,
        status,
        error);
    BOOST_CHECK(!database);
    BOOST_CHECK(status == DatabaseStatus::FAILED_LOAD);
    BOOST_CHECK(!error.empty());
    BOOST_CHECK_NE(error, "unchanged");
    BOOST_CHECK(!fs::exists(GetDataDir() / createFilename));
    BOOST_CHECK(!fs::exists(
        (GetDataDir() / createFilename).string() + "-journal"));
    BOOST_CHECK(!HasSQLiteTestCandidate(createFilename));

    InjectSQLiteAmbiguousPublishFailureForTesting();
    database = MakeSQLiteDatabase(
        ambiguousFilename,
        createOptions,
        status,
        error);
    BOOST_CHECK(!database);
    BOOST_CHECK(status == DatabaseStatus::FAILED_LOAD);
    BOOST_CHECK(!fs::exists(GetDataDir() / ambiguousFilename));
    BOOST_CHECK(!HasSQLiteTestCandidate(ambiguousFilename));

    database = MakeSQLiteDatabase(
        sourceFilename,
        createOptions,
        status,
        error);
    BOOST_REQUIRE(database);
    std::unique_ptr<DatabaseBatch> batch = database->MakeBatch();
    BOOST_REQUIRE(batch);
    BOOST_REQUIRE(batch->Write(
        std::string("source"),
        std::string("preserved")));
    batch.reset();

    InjectSQLitePostPublishFailureForTesting();
    BOOST_CHECK(!database->Backup(
        (GetDataDir() / backupFilename).string()));
    BOOST_CHECK(!fs::exists(GetDataDir() / backupFilename));
    BOOST_CHECK(!fs::exists(
        (GetDataDir() / backupFilename).string() + "-journal"));
    BOOST_CHECK(!HasSQLiteTestCandidate(backupFilename));
    batch = database->MakeBatch();
    BOOST_REQUIRE(batch);
    std::string value;
    BOOST_CHECK(batch->Read(std::string("source"), value));
    BOOST_CHECK_EQUAL(value, "preserved");
    batch.reset();
    database.reset();

    RemoveSQLiteTestFiles(createFilename);
    RemoveSQLiteTestFiles(ambiguousFilename);
    RemoveSQLiteTestFiles(sourceFilename);
    RemoveSQLiteTestFiles(backupFilename);
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(sqlite_close_failure_retains_owned_paths)
{
    const std::string prePublishFilename{
        "sqlite_failed_close_before_publish.dat"};
    const std::string postPublishFilename{
        "sqlite_failed_close_after_publish.dat"};
    const std::string sourceFilename{
        "sqlite_failed_close_backup_source.dat"};
    const std::string backupFilename{
        "sqlite_failed_close_backup.dat"};
    for (const std::string& filename : {
             prePublishFilename,
             postPublishFilename,
             sourceFilename,
             backupFilename}) {
        RemoveSQLiteTestFiles(filename);
        RemoveSQLiteTestCandidates(filename);
    }

    DatabaseOptions createOptions;
    createOptions.require_create = true;
    createOptions.require_format = DatabaseFormat::SQLITE;
    DatabaseStatus status = DatabaseStatus::SUCCESS;
    std::string error{"unchanged"};

    InjectSQLiteCloseFailureForTesting();
    std::unique_ptr<WalletDatabase> database = MakeSQLiteDatabase(
        prePublishFilename,
        createOptions,
        status,
        error);
    BOOST_CHECK(!database);
    BOOST_CHECK(status == DatabaseStatus::FAILED_LOAD);
    BOOST_CHECK(!fs::exists(GetDataDir() / prePublishFilename));
    BOOST_CHECK(HasSQLiteTestCandidate(prePublishFilename));
    BOOST_CHECK(ResetSQLiteLifecycleForTesting());
    RemoveSQLiteTestCandidates(prePublishFilename);

    InjectSQLitePostPublishFailureForTesting();
    InjectSQLiteCloseFailureForTesting(1);
    database = MakeSQLiteDatabase(
        postPublishFilename,
        createOptions,
        status,
        error);
    BOOST_CHECK(!database);
    BOOST_CHECK(status == DatabaseStatus::FAILED_LOAD);
    BOOST_CHECK(fs::exists(GetDataDir() / postPublishFilename));
    BOOST_CHECK(!HasSQLiteTestCandidate(postPublishFilename));
    BOOST_CHECK(ResetSQLiteLifecycleForTesting());
    RemoveSQLiteTestFiles(postPublishFilename);

    database = MakeSQLiteDatabase(
        sourceFilename,
        createOptions,
        status,
        error);
    BOOST_REQUIRE(database);
    {
        std::unique_ptr<DatabaseBatch> batch = database->MakeBatch();
        BOOST_REQUIRE(batch);
        BOOST_REQUIRE(batch->Write(
            std::string("source"),
            std::string("preserved")));
    }

    InjectSQLiteCloseFailureForTesting(1);
    BOOST_CHECK(!database->Backup(
        (GetDataDir() / backupFilename).string()));
    BOOST_CHECK(fs::exists(GetDataDir() / backupFilename));
    BOOST_CHECK(!HasSQLiteTestCandidate(backupFilename));
    BOOST_CHECK_THROW(
        database->MakeBatch(),
        std::runtime_error);
    database.reset();
    BOOST_CHECK(ResetSQLiteLifecycleForTesting());

    DatabaseOptions existingOptions;
    existingOptions.require_existing = true;
    existingOptions.require_format = DatabaseFormat::SQLITE;
    database = MakeSQLiteDatabase(
        backupFilename,
        existingOptions,
        status,
        error);
    BOOST_REQUIRE(database);
    {
        std::unique_ptr<DatabaseBatch> batch = database->MakeBatch();
        BOOST_REQUIRE(batch);
        std::string value;
        BOOST_CHECK(batch->Read(std::string("source"), value));
        BOOST_CHECK_EQUAL(value, "preserved");
    }
    database.reset();

    for (const std::string& filename : {
             prePublishFilename,
             postPublishFilename,
             sourceFilename,
             backupFilename}) {
        RemoveSQLiteTestFiles(filename);
        RemoveSQLiteTestCandidates(filename);
    }
}

BOOST_AUTO_TEST_CASE(sqlite_identity_lock_closes_across_exec)
{
    const std::string filename{
        "sqlite_close_on_exec_identity.dat"};
    RemoveSQLiteTestFiles(filename);
    RemoveSQLiteTestCandidates(filename);

    DatabaseOptions createOptions;
    createOptions.require_create = true;
    createOptions.require_format = DatabaseFormat::SQLITE;
    DatabaseStatus status = DatabaseStatus::SUCCESS;
    std::string error;
    std::unique_ptr<WalletDatabase> database =
        MakeSQLiteDatabase(
            filename,
            createOptions,
            status,
            error);
    BOOST_REQUIRE(database);

    int execPipe[2]{-1, -1};
    BOOST_REQUIRE_EQUAL(pipe(execPipe), 0);
    bool pipeConfigured = true;
    for (const int descriptor : execPipe) {
        const int flags = fcntl(descriptor, F_GETFD);
        if (flags < 0 ||
            fcntl(
                descriptor,
                F_SETFD,
                flags | FD_CLOEXEC) != 0) {
            pipeConfigured = false;
        }
    }
    if (!pipeConfigured) {
        close(execPipe[0]);
        close(execPipe[1]);
    }
    BOOST_REQUIRE(pipeConfigured);

    const pid_t child = fork();
    if (child == 0) {
        close(execPipe[0]);
        execl(
            "/bin/sleep",
            "sleep",
            "5",
            static_cast<char*>(nullptr));
        _exit(127);
    }
    if (child < 0) {
        close(execPipe[0]);
        close(execPipe[1]);
    }
    BOOST_REQUIRE(child > 0);

    close(execPipe[1]);
    char byte{0};
    ssize_t readResult;
    do {
        readResult = read(execPipe[0], &byte, 1);
    } while (readResult < 0 && errno == EINTR);
    close(execPipe[0]);
    BOOST_CHECK_EQUAL(readResult, 0);

    int childStatus{0};
    pid_t earlyWait;
    do {
        earlyWait =
            waitpid(child, &childStatus, WNOHANG);
    } while (earlyWait < 0 && errno == EINTR);
    BOOST_CHECK_EQUAL(earlyWait, 0);

    database.reset();
    DatabaseOptions existingOptions;
    existingOptions.require_existing = true;
    existingOptions.require_format = DatabaseFormat::SQLITE;
    database = MakeSQLiteDatabase(
        filename,
        existingOptions,
        status,
        error);
    BOOST_CHECK(database);

    if (earlyWait == 0) {
        BOOST_CHECK_EQUAL(kill(child, SIGTERM), 0);
        pid_t waited;
        do {
            waited = waitpid(child, &childStatus, 0);
        } while (waited < 0 && errno == EINTR);
        BOOST_CHECK_EQUAL(waited, child);
    }
    database.reset();
    RemoveSQLiteTestFiles(filename);
    RemoveSQLiteTestCandidates(filename);
}
#endif

BOOST_AUTO_TEST_CASE(sqlite_identity_schema_corruption_policy)
{
    auto expectVerifyFailure = [](
                                   const std::string& filename,
                                   const std::string& before,
                                   DatabaseStatus expectedStatus =
                                       DatabaseStatus::FAILED_VERIFY) {
        DatabaseOptions options;
        options.require_existing = true;
        options.require_format = DatabaseFormat::SQLITE;
        DatabaseStatus status = DatabaseStatus::SUCCESS;
        std::string error{"unchanged"};
        std::unique_ptr<WalletDatabase> database =
            MakeSQLiteDatabase(filename, options, status, error);
        BOOST_TEST_CONTEXT(filename)
        {
            BOOST_CHECK(!database);
            BOOST_CHECK(status == expectedStatus);
            BOOST_CHECK(!error.empty());
            BOOST_CHECK_NE(error, "unchanged");
            BOOST_CHECK(error.find(filename) != std::string::npos);
            BOOST_CHECK_EQUAL(ReadFile(GetDataDir() / filename), before);
        }
    };

    DatabaseOptions createOptions;
    createOptions.require_create = true;
    createOptions.require_format = DatabaseFormat::SQLITE;
    DatabaseStatus status;
    std::string error;

    const std::string applicationIdFilename{"sqlite_wrong_application_id.dat"};
    RemoveSQLiteTestFiles(applicationIdFilename);
    std::unique_ptr<WalletDatabase> database =
        MakeSQLiteDatabase(applicationIdFilename, createOptions, status, error);
    BOOST_REQUIRE(database);
    database.reset();
    const fs::path applicationIdPath = GetDataDir() / applicationIdFilename;
    BOOST_REQUIRE(ExecuteRawSQLite(applicationIdPath, {"PRAGMA application_id = 0"}));
    const fs::path applicationIdJournal =
        applicationIdPath.string() + "-journal";
    const std::string foreignJournal(1024, 'J');
    WriteFile(applicationIdJournal, foreignJournal);
#ifndef WIN32
    fs::permissions(
        applicationIdJournal,
        fs::owner_read |
            fs::owner_write);
#endif
    const std::string wrongApplicationId = ReadFile(applicationIdPath);
    expectVerifyFailure(applicationIdFilename, wrongApplicationId);
    BOOST_CHECK_EQUAL(ReadFile(applicationIdJournal), foreignJournal);
    RemoveSQLiteTestFiles(applicationIdFilename);

    const std::string versionFilename{"sqlite_wrong_schema_version.dat"};
    RemoveSQLiteTestFiles(versionFilename);
    database = MakeSQLiteDatabase(versionFilename, createOptions, status, error);
    BOOST_REQUIRE(database);
    database.reset();
    const fs::path versionPath = GetDataDir() / versionFilename;
    BOOST_REQUIRE(ExecuteRawSQLite(versionPath, {"PRAGMA user_version = 1"}));
    const std::string wrongVersion = ReadFile(versionPath);
    expectVerifyFailure(versionFilename, wrongVersion);
    RemoveSQLiteTestFiles(versionFilename);

    const std::string schemaFilename{"sqlite_wrong_schema.dat"};
    RemoveSQLiteTestFiles(schemaFilename);
    const fs::path schemaPath = GetDataDir() / schemaFilename;
    BOOST_REQUIRE(ExecuteRawSQLite(
        schemaPath,
        {
            "CREATE TABLE main(key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL)",
            ExpectedApplicationIdPragma(),
            "PRAGMA user_version = 0",
        },
        true));
    const std::string wrongSchema = ReadFile(schemaPath);
    expectVerifyFailure(schemaFilename, wrongSchema);
    const std::optional<int64_t> tableCount = ReadRawSQLiteInteger(
        schemaPath,
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='main'");
    BOOST_REQUIRE(tableCount);
    BOOST_CHECK_EQUAL(*tableCount, 1);
    RemoveSQLiteTestFiles(schemaFilename);

    const std::string constrainedSchemaFilename{
        "sqlite_constrained_schema.dat"};
    RemoveSQLiteTestFiles(constrainedSchemaFilename);
    const fs::path constrainedSchemaPath =
        GetDataDir() / constrainedSchemaFilename;
    BOOST_REQUIRE(ExecuteRawSQLite(
        constrainedSchemaPath,
        {
            "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, "
            "value BLOB NOT NULL CHECK(length(value) < 10))",
            ExpectedApplicationIdPragma(),
            "PRAGMA user_version = 0",
        },
        true));
    const std::string constrainedSchema = ReadFile(constrainedSchemaPath);
    expectVerifyFailure(constrainedSchemaFilename, constrainedSchema);
    RemoveSQLiteTestFiles(constrainedSchemaFilename);

    const std::string extraObjectFilename{"sqlite_extra_schema_object.dat"};
    RemoveSQLiteTestFiles(extraObjectFilename);
    const fs::path extraObjectPath = GetDataDir() / extraObjectFilename;
    BOOST_REQUIRE(ExecuteRawSQLite(
        extraObjectPath,
        {
            "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, "
            "value BLOB NOT NULL)",
            "CREATE TRIGGER reject_wallet_write BEFORE INSERT ON main "
            "BEGIN SELECT RAISE(ABORT, 'rejected'); END",
            ExpectedApplicationIdPragma(),
            "PRAGMA user_version = 0",
        },
        true));
    const std::string extraObjectSchema = ReadFile(extraObjectPath);
    expectVerifyFailure(extraObjectFilename, extraObjectSchema);
    RemoveSQLiteTestFiles(extraObjectFilename);

    const std::string internalObjectFilename{
        "sqlite_extra_internal_schema_object.dat"};
    RemoveSQLiteTestFiles(internalObjectFilename);
    database = MakeSQLiteDatabase(
        internalObjectFilename,
        createOptions,
        status,
        error);
    BOOST_REQUIRE(database);
    {
        std::unique_ptr<DatabaseBatch> batch = database->MakeBatch();
        BOOST_REQUIRE(batch->Write(
            std::string("analyzed"),
            std::string("record")));
    }
    database.reset();
    const fs::path internalObjectPath =
        GetDataDir() / internalObjectFilename;
    BOOST_REQUIRE(ExecuteRawSQLite(internalObjectPath, {"ANALYZE"}));
    const std::string internalObjectSchema = ReadFile(internalObjectPath);
    expectVerifyFailure(internalObjectFilename, internalObjectSchema);
    RemoveSQLiteTestFiles(internalObjectFilename);

    const std::string nonBlobFilename{"sqlite_non_blob_record.dat"};
    RemoveSQLiteTestFiles(nonBlobFilename);
    database = MakeSQLiteDatabase(nonBlobFilename, createOptions, status, error);
    BOOST_REQUIRE(database);
    database.reset();
    const fs::path nonBlobPath = GetDataDir() / nonBlobFilename;
    BOOST_REQUIRE(ExecuteRawSQLite(
        nonBlobPath,
        {"INSERT INTO main(key, value) VALUES('text-key', 'text-value')"}));
    const std::string nonBlobRecord = ReadFile(nonBlobPath);
    expectVerifyFailure(nonBlobFilename, nonBlobRecord);
    RemoveSQLiteTestFiles(nonBlobFilename);

#ifndef WIN32
    const std::string publicModeFilename{"sqlite_public_mode.dat"};
    RemoveSQLiteTestFiles(publicModeFilename);
    database = MakeSQLiteDatabase(
        publicModeFilename,
        createOptions,
        status,
        error);
    BOOST_REQUIRE(database);
    database.reset();
    const fs::path publicModePath = GetDataDir() / publicModeFilename;
    const std::string publicModeContents = ReadFile(publicModePath);
    fs::permissions(
        publicModePath,
        fs::owner_read |
            fs::owner_write |
            fs::group_read);
    expectVerifyFailure(publicModeFilename, publicModeContents);
    fs::permissions(
        publicModePath,
        fs::owner_read |
            fs::owner_write);
    RemoveSQLiteTestFiles(publicModeFilename);

    const std::string publicJournalFilename{"sqlite_public_journal.dat"};
    RemoveSQLiteTestFiles(publicJournalFilename);
    database = MakeSQLiteDatabase(
        publicJournalFilename,
        createOptions,
        status,
        error);
    BOOST_REQUIRE(database);
    database.reset();
    const fs::path publicJournalPath =
        GetDataDir() / publicJournalFilename;
    const fs::path publicJournal =
        publicJournalPath.string() + "-journal";
    const std::string publicJournalContents(1024, 'J');
    WriteFile(publicJournal, publicJournalContents);
    fs::permissions(
        publicJournal,
        fs::owner_read |
            fs::owner_write |
            fs::group_read);
    const std::string privateDatabaseContents =
        ReadFile(publicJournalPath);
    expectVerifyFailure(
        publicJournalFilename,
        privateDatabaseContents,
        DatabaseStatus::FAILED_BAD_PATH);
    BOOST_CHECK_EQUAL(
        ReadFile(publicJournal),
        publicJournalContents);
    fs::permissions(
        publicJournal,
        fs::owner_read |
            fs::owner_write);
    RemoveSQLiteTestFiles(publicJournalFilename);
#endif

    const std::string corruptFilename{"sqlite_corrupt_wallet.dat"};
    RemoveSQLiteTestFiles(corruptFilename);
    database = MakeSQLiteDatabase(corruptFilename, createOptions, status, error);
    BOOST_REQUIRE(database);
    {
        std::unique_ptr<DatabaseBatch> batch = database->MakeBatch();
        for (int i = 0; i < 64; ++i) {
            BOOST_REQUIRE(batch->Write(
                std::make_pair(std::string("large"), i),
                std::string(4096, static_cast<char>(i))));
        }
    }
    database.reset();
    const fs::path corruptPath = GetDataDir() / corruptFilename;
    const uintmax_t originalSize = fs::file_size(corruptPath);
    BOOST_REQUIRE(originalSize > 8192U);
    fs::resize_file(corruptPath, originalSize / 2);
    const std::string corruptContents = ReadFile(corruptPath);
    expectVerifyFailure(corruptFilename, corruptContents);
    RemoveSQLiteTestFiles(corruptFilename);

    const std::string walModeFilename{"sqlite_wal_mode_header.dat"};
    RemoveSQLiteTestFiles(walModeFilename);
    database = MakeSQLiteDatabase(walModeFilename, createOptions, status, error);
    BOOST_REQUIRE(database);
    database.reset();
    const fs::path walModePath = GetDataDir() / walModeFilename;
    BOOST_REQUIRE(ExecuteRawSQLite(
        walModePath,
        {"PRAGMA journal_mode = WAL"}));
    for (const char* suffix : {"-wal", "-shm"}) {
        boost::system::error_code removeError;
        fs::remove(walModePath.string() + suffix, removeError);
    }
    const std::string walModeContents = ReadFile(walModePath);
    BOOST_REQUIRE(walModeContents.size() > 19);
    BOOST_REQUIRE_EQUAL(
        static_cast<unsigned char>(walModeContents[18]),
        2U);
    BOOST_REQUIRE_EQUAL(
        static_cast<unsigned char>(walModeContents[19]),
        2U);
    expectVerifyFailure(walModeFilename, walModeContents);
    BOOST_CHECK(!fs::exists(walModePath.string() + "-wal"));
    BOOST_CHECK(!fs::exists(walModePath.string() + "-shm"));
    RemoveSQLiteTestFiles(walModeFilename);

    const std::string existingFilename{"sqlite_create_existing.dat"};
    RemoveSQLiteTestFiles(existingFilename);
    database = MakeSQLiteDatabase(existingFilename, createOptions, status, error);
    BOOST_REQUIRE(database);
    database.reset();
    const fs::path existingPath = GetDataDir() / existingFilename;
    const std::string existingContents = ReadFile(existingPath);
    status = DatabaseStatus::SUCCESS;
    error = "unchanged";
    database = MakeSQLiteDatabase(existingFilename, createOptions, status, error);
    BOOST_CHECK(!database);
    BOOST_CHECK(status == DatabaseStatus::FAILED_ALREADY_EXISTS);
    BOOST_CHECK(!error.empty());
    BOOST_CHECK_NE(error, "unchanged");
    BOOST_CHECK_EQUAL(ReadFile(existingPath), existingContents);
    RemoveSQLiteTestFiles(existingFilename);
}
#endif

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
