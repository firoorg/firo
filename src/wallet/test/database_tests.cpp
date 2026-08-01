// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "config/bitcoin-config.h"

#include "base58.h"
#include "hash.h"
#include "primitives/block.h"
#include "protocol.h"
#include "script/standard.h"
#include "spark/state.h"
#include "test/testutil.h"
#include "wallet/db.h"
#include "wallet/test/wallet_test_fixture.h"
#include "wallet/wallet.h"

#ifdef USE_SQLITE
#include "chainparams.h"
#include "crypto/common.h"
#include "init.h"
#include "wallet/sqlite.h"

#include <sqlite3.h>

#ifndef WIN32
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <sys/wait.h>
#include <unistd.h>
#endif
#endif

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <boost/filesystem/fstream.hpp>

#ifdef USE_SQLITE
extern std::atomic<bool> fRequestShutdown;
#endif

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
        {
            LOCK(bitdb.cs_db);
            bitdb.mapDb.clear();
            bitdb.mapFileUseCount.clear();
        }
        ClearDatadirCache();
        m_path = GetTempPath() / strprintf("wallet_database_policy_%d_%d", GetTime(), GetRand(100000));
        fs::create_directories(m_path);
        ForceSetArg("-datadir", m_path.string());
        ClearDatadirCache();
    }

    ~WalletDatabasePathTestingSetup()
    {
        bitdb.Flush(true);
        bitdb.Close();
        bitdb.Reset();
        {
            LOCK(bitdb.cs_db);
            bitdb.mapDb.clear();
            bitdb.mapFileUseCount.clear();
        }
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

template <typename T>
bool SameSerializedValue(const T& expected, const T& actual)
{
    return SerializeToString(expected) == SerializeToString(actual);
}

bool SameKey(const CKey& expected, const CKey& actual)
{
    return expected.IsCompressed() == actual.IsCompressed() &&
           expected.GetPrivKey() == actual.GetPrivKey();
}

bool SameAccountingEntry(
    const CAccountingEntry& expected,
    const CAccountingEntry& actual)
{
    return expected.strAccount == actual.strAccount &&
           expected.nCreditDebit == actual.nCreditDebit &&
           expected.nTime == actual.nTime &&
           expected.strOtherAccount == actual.strOtherAccount &&
           expected.strComment == actual.strComment &&
           expected.mapValue == actual.mapValue &&
           expected.nOrderPos == actual.nOrderPos &&
           expected.nEntryNo == actual.nEntryNo;
}

bool SameIdentifiedCoin(
    const spark::IdentifiedCoinData& expected,
    const spark::IdentifiedCoinData& actual)
{
    return expected.i == actual.i &&
           expected.d == actual.d &&
           expected.v == actual.v &&
           expected.k == actual.k &&
           expected.memo == actual.memo;
}

bool SameRecoveredCoin(
    const spark::RecoveredCoinData& expected,
    const spark::RecoveredCoinData& actual)
{
    return expected.s == actual.s &&
           expected.T == actual.T;
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

#if (defined(__linux__) && defined(SYS_renameat2)) || defined(__APPLE__)
std::optional<std::vector<RawRecord> > ReadRawSQLiteRecordsNotIndexed(
    const fs::path& path)
{
    if (sqlite3_initialize() != SQLITE_OK) {
        return std::nullopt;
    }

    sqlite3* database = nullptr;
    sqlite3_stmt* prepared = nullptr;
    std::vector<RawRecord> records;
    const int flags =
        SQLITE_OPEN_FULLMUTEX |
        SQLITE_OPEN_NOFOLLOW |
        SQLITE_OPEN_READONLY;
    bool valid =
        sqlite3_open_v2(
            path.string().c_str(),
            &database,
            flags,
            nullptr) == SQLITE_OK &&
        sqlite3_prepare_v2(
            database,
            "SELECT key, value FROM main NOT INDEXED ORDER BY rowid",
            -1,
            &prepared,
            nullptr) == SQLITE_OK;

    while (valid) {
        const int result = sqlite3_step(prepared);
        if (result == SQLITE_DONE) {
            break;
        }
        if (result != SQLITE_ROW ||
            sqlite3_column_type(prepared, 0) != SQLITE_BLOB ||
            sqlite3_column_type(prepared, 1) != SQLITE_BLOB) {
            valid = false;
            break;
        }

        const int keySize = sqlite3_column_bytes(prepared, 0);
        const int valueSize = sqlite3_column_bytes(prepared, 1);
        const void* const key = sqlite3_column_blob(prepared, 0);
        const void* const value = sqlite3_column_blob(prepared, 1);
        if (keySize < 0 ||
            valueSize < 0 ||
            (keySize != 0 && !key) ||
            (valueSize != 0 && !value)) {
            valid = false;
            break;
        }
        records.emplace_back(
            keySize == 0 ?
                std::string{} :
                std::string(
                    static_cast<const char*>(key),
                    static_cast<size_t>(keySize)),
            valueSize == 0 ?
                std::string{} :
                std::string(
                    static_cast<const char*>(value),
                    static_cast<size_t>(valueSize)));
    }

    if (prepared && sqlite3_finalize(prepared) != SQLITE_OK) {
        valid = false;
    }
    if (database && sqlite3_close(database) != SQLITE_OK) {
        valid = false;
    }
    if (sqlite3_shutdown() != SQLITE_OK) {
        valid = false;
    }
    if (!valid) {
        return std::nullopt;
    }
    return records;
}

bool CorruptSQLitePrimaryKeyIndex(const fs::path& path)
{
    const std::optional<int64_t> pageSize =
        ReadRawSQLiteInteger(path, "PRAGMA page_size");
    const std::optional<int64_t> rootPage =
        ReadRawSQLiteInteger(
            path,
            "SELECT rootpage FROM sqlite_master "
            "WHERE type='index' AND name='sqlite_autoindex_main_1'");
    if (!pageSize ||
        !rootPage ||
        *pageSize <= 0 ||
        *rootPage <= 1) {
        return false;
    }

    const uint64_t pageOffset =
        (static_cast<uint64_t>(*rootPage) - 1) *
        static_cast<uint64_t>(*pageSize);
    std::string contents = ReadFile(path);
    if (pageOffset >= contents.size()) {
        return false;
    }

    const unsigned char pageType =
        static_cast<unsigned char>(contents[pageOffset]);
    if (pageType != 0x02 && pageType != 0x0a) {
        return false;
    }
    contents[pageOffset] = 0;
    WriteFile(path, contents);
    return true;
}

bool CreateHotJournalRestoringForeignHeader(
    const fs::path& path)
{
    if (!ExecuteRawSQLite(
            path,
            {
                "PRAGMA application_id = 0",
                "PRAGMA user_version = 1",
            })) {
        return false;
    }

    const pid_t child = fork();
    if (child == 0) {
        sqlite3* database = nullptr;
        const int flags =
            SQLITE_OPEN_FULLMUTEX |
            SQLITE_OPEN_NOFOLLOW |
            SQLITE_OPEN_READWRITE;
        bool success =
            sqlite3_open_v2(
                path.string().c_str(),
                &database,
                flags,
                nullptr) == SQLITE_OK &&
            sqlite3_exec(
                database,
                "PRAGMA journal_mode = DELETE",
                nullptr,
                nullptr,
                nullptr) == SQLITE_OK &&
            sqlite3_exec(
                database,
                "PRAGMA synchronous = FULL",
                nullptr,
                nullptr,
                nullptr) == SQLITE_OK &&
            sqlite3_exec(
                database,
                "PRAGMA cache_size = 1",
                nullptr,
                nullptr,
                nullptr) == SQLITE_OK &&
            sqlite3_exec(
                database,
                "PRAGMA cache_spill = ON",
                nullptr,
                nullptr,
                nullptr) == SQLITE_OK &&
            sqlite3_exec(
                database,
                "BEGIN IMMEDIATE TRANSACTION",
                nullptr,
                nullptr,
                nullptr) == SQLITE_OK &&
            sqlite3_exec(
                database,
                "INSERT INTO main(key, value) "
                "VALUES(X'70656e64696e672d31', zeroblob(100000))",
                nullptr,
                nullptr,
                nullptr) == SQLITE_OK &&
            sqlite3_exec(
                database,
                "INSERT INTO main(key, value) "
                "VALUES(X'70656e64696e672d32', zeroblob(100000))",
                nullptr,
                nullptr,
                nullptr) == SQLITE_OK;
        _exit(success ? 0 : 1);
    }
    if (child <= 0) {
        return false;
    }

    int childStatus = 0;
    pid_t waited;
    do {
        waited = waitpid(
            child,
            &childStatus,
            0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child ||
        !WIFEXITED(childStatus) ||
        WEXITSTATUS(childStatus) != 0) {
        return false;
    }

    const fs::path journalPath =
        path.string() + "-journal";
    const std::string journal =
        ReadFile(journalPath);
    static constexpr std::array<unsigned char, 8>
        JOURNAL_MAGIC{{
            0xd9,
            0xd5,
            0x05,
            0xf9,
            0x20,
            0xa1,
            0x63,
            0xd7,
        }};
    if (journal.size() <= 512 ||
        !std::equal(
            JOURNAL_MAGIC.begin(),
            JOURNAL_MAGIC.end(),
            reinterpret_cast<const unsigned char*>(
                journal.data()))) {
        return false;
    }

    int flags = O_RDWR;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int descriptor =
        open(path.string().c_str(), flags);
    if (descriptor < 0) {
        return false;
    }

    std::array<unsigned char, 4> schemaVersion{};
    std::array<unsigned char, 4> applicationId{};
    WriteBE32(
        schemaVersion.data(),
        0);
    WriteBE32(
        applicationId.data(),
        ReadBE32(
            Params().MessageStart()));
    const bool patched =
        pwrite(
            descriptor,
            schemaVersion.data(),
            schemaVersion.size(),
            60) ==
            static_cast<ssize_t>(
                schemaVersion.size()) &&
        pwrite(
            descriptor,
            applicationId.data(),
            applicationId.size(),
            68) ==
            static_cast<ssize_t>(
                applicationId.size()) &&
        fsync(descriptor) == 0;
    const bool closed =
        close(descriptor) == 0;
    return patched && closed;
}

std::optional<std::string> RawRecordType(const RawRecord& record)
{
    CDataStream key(
        record.first.data(),
        record.first.data() + record.first.size(),
        SER_DISK,
        CLIENT_VERSION);
    std::string type;
    try {
        key >> type;
    } catch (...) {
        return std::nullopt;
    }
    return type;
}

std::unique_ptr<WalletDatabase> CreateSQLiteTestDatabaseFromRawRecords(
    const std::string& filename,
    const std::vector<RawRecord>& records,
    DatabaseStatus& status,
    std::string& error)
{
    DatabaseOptions options;
    options.require_create = true;
    options.require_format = DatabaseFormat::SQLITE;
    std::unique_ptr<WalletDatabase> database =
        MakeSQLiteDatabase(
            filename,
            options,
            status,
            error);
    if (!database) {
        return nullptr;
    }

    std::unique_ptr<DatabaseBatch> batch =
        database->MakeBatch();
    if (!batch || !batch->TxnBegin()) {
        return nullptr;
    }
    for (const RawRecord& record : records) {
        CDataStream key(
            record.first.data(),
            record.first.data() + record.first.size(),
            SER_DISK,
            CLIENT_VERSION);
        CDataStream value(
            record.second.data(),
            record.second.data() + record.second.size(),
            SER_DISK,
            CLIENT_VERSION);
        if (!batch->WriteRawRecord(
                std::move(key),
                std::move(value),
                false)) {
            batch->TxnAbort();
            return nullptr;
        }
    }
    if (!batch->TxnCommit()) {
        return nullptr;
    }
    return database;
}
#endif

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

class CommitThenFailSQLiteStatementExecutor final : public SQLiteStatementExecutor
{
public:
    int Execute(sqlite3* database, const char* statement) override
    {
        const int result =
            SQLiteStatementExecutor::Execute(database, statement);
        if (result == SQLITE_OK &&
            std::string(statement) == "COMMIT TRANSACTION") {
            return SQLITE_IOERR;
        }
        return result;
    }
};

class RollbackCommitSQLiteStatementExecutor final : public SQLiteStatementExecutor
{
public:
    int Execute(sqlite3* database, const char* statement) override
    {
        if (std::string(statement) == "COMMIT TRANSACTION") {
            const int result =
                SQLiteStatementExecutor::Execute(
                    database,
                    "ROLLBACK TRANSACTION");
            return result == SQLITE_OK ?
                       SQLITE_IOERR :
                       result;
        }
        return SQLiteStatementExecutor::Execute(
            database,
            statement);
    }
};

class RollbackWriteSQLiteStatementExecutor final : public SQLiteStatementExecutor
{
private:
    bool m_trigger_created{false};

public:
    int Execute(sqlite3* database, const char* statement) override
    {
        const int result =
            SQLiteStatementExecutor::Execute(database, statement);
        if (result != SQLITE_OK ||
            m_trigger_created ||
            std::string(statement) != "BEGIN TRANSACTION") {
            return result;
        }

        const int trigger_result =
            SQLiteStatementExecutor::Execute(
                database,
                "CREATE TEMP TRIGGER injected_write_rollback "
                "BEFORE INSERT ON main BEGIN "
                "SELECT RAISE(ROLLBACK, 'injected rollback'); "
                "END");
        if (trigger_result == SQLITE_OK) {
            m_trigger_created = true;
        }
        return trigger_result;
    }
};

class NonBlobSQLiteStatementExecutor final : public SQLiteStatementExecutor
{
public:
    int Execute(sqlite3* database, const char* statement) override
    {
        const int result =
            SQLiteStatementExecutor::Execute(database, statement);
        if (result != SQLITE_OK ||
            std::string(statement) != "BEGIN TRANSACTION") {
            return result;
        }
        return SQLiteStatementExecutor::Execute(
            database,
            "UPDATE main SET value = CAST(value AS TEXT)");
    }
};

enum class SQLiteColumnFailure {
    BLOB,
    BYTES,
};

class FailingSQLiteColumnReader final : public SQLiteColumnReader
{
private:
    const SQLiteColumnFailure m_failure;
    const bool m_rollback;
    bool m_blob_seen{false};
    bool m_order_valid{true};
    bool m_failed{false};
    bool m_error_pending{false};
    int m_rollback_result{SQLITE_OK};

    void Fail(sqlite3_stmt* statement)
    {
        if (m_rollback) {
            m_rollback_result = sqlite3_exec(
                sqlite3_db_handle(statement),
                "ROLLBACK TRANSACTION",
                nullptr,
                nullptr,
                nullptr);
        }
        m_failed = true;
        m_error_pending = true;
    }

public:
    FailingSQLiteColumnReader(
        SQLiteColumnFailure failure,
        bool rollback)
        : m_failure(failure),
          m_rollback(rollback)
    {
    }

    const void* Blob(
        sqlite3_stmt* statement,
        int column) override
    {
        m_blob_seen = true;
        if (!m_failed &&
            m_failure == SQLiteColumnFailure::BLOB) {
            Fail(statement);
            return nullptr;
        }
        return SQLiteColumnReader::Blob(statement, column);
    }

    int Bytes(
        sqlite3_stmt* statement,
        int column) override
    {
        m_order_valid = m_order_valid && m_blob_seen;
        if (!m_failed &&
            m_failure == SQLiteColumnFailure::BYTES) {
            Fail(statement);
            return 0;
        }
        return SQLiteColumnReader::Bytes(statement, column);
    }

    int ErrorCode(sqlite3* database) override
    {
        if (m_error_pending) {
            m_error_pending = false;
            return SQLITE_NOMEM;
        }
        return SQLiteColumnReader::ErrorCode(database);
    }

    bool Failed() const { return m_failed; }
    bool OrderValid() const { return m_order_valid; }
    int RollbackResult() const { return m_rollback_result; }
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

class ShutdownRequestReset
{
private:
    const bool m_previous;

public:
    ShutdownRequestReset()
        : m_previous(fRequestShutdown.exchange(false))
    {
    }

    ~ShutdownRequestReset()
    {
        fRequestShutdown.store(m_previous);
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

std::set<std::string> SQLiteTestDirectoryEntries()
{
    std::set<std::string> entries;
    for (fs::directory_iterator entry(GetDataDir()), end;
        entry != end;
        ++entry) {
        entries.insert(
            entry->path().filename().string());
    }
    return entries;
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

std::vector<fs::path> FindMigrationPaths(
    const std::string& prefix)
{
    std::vector<fs::path> paths;
    for (fs::directory_iterator entry(GetDataDir()), end;
        entry != end;
        ++entry) {
        if (entry->path().filename().string().find(prefix) == 0) {
            paths.push_back(entry->path());
        }
    }
    return paths;
}

std::unique_ptr<WalletDatabase> ReopenBerkeleyForMigration(
    const std::string& filename,
    std::string& error)
{
    DatabaseOptions options;
    options.require_existing = true;
    options.require_format =
        DatabaseFormat::BERKELEY;
    options.recover = false;
    DatabaseStatus status;
    return MakeWalletDatabase(
        filename,
        options,
        status,
        error);
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
#ifdef USE_SQLITE
    expectFailure(truncatedSQLiteFilename, defaults, DatabaseStatus::FAILED_VERIFY);
#else
    expectFailure(truncatedSQLiteFilename, defaults, DatabaseStatus::FAILED_UNSUPPORTED);
#endif
    BOOST_CHECK_EQUAL(ReadFile(truncatedSQLitePath), truncatedSQLiteContents);

    DatabaseOptions salvage;
    salvage.salvage = true;
#ifdef USE_SQLITE
    expectFailure(truncatedSQLiteFilename, salvage, DatabaseStatus::FAILED_VERIFY);
#else
    expectFailure(truncatedSQLiteFilename, salvage, DatabaseStatus::FAILED_UNSUPPORTED);
#endif
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

    DatabaseOptions requireBerkeleyCreate;
    requireBerkeleyCreate.require_create = true;
    requireBerkeleyCreate.require_format = DatabaseFormat::BERKELEY;
    std::unique_ptr<WalletDatabase> missingDatabase = makeDatabase(
        missingFilename,
        requireBerkeleyCreate,
        status,
        error);
    BOOST_REQUIRE(missingDatabase);
    BOOST_CHECK(status == DatabaseStatus::SUCCESS);
    BOOST_CHECK(missingDatabase->Format() == DatabaseFormat::BERKELEY);
    BOOST_CHECK(!fs::exists(missingPath));
    missingDatabase.reset();

    const std::string explicitSQLiteFilename{"factory_explicit_sqlite_test.dat"};
    const fs::path explicitSQLitePath = GetDataDir() / explicitSQLiteFilename;
    DatabaseOptions requireSQLite;
    requireSQLite.require_create = true;
    requireSQLite.require_format = DatabaseFormat::SQLITE;
#ifdef USE_SQLITE
    std::unique_ptr<WalletDatabase> explicitSQLite = makeDatabase(
        explicitSQLiteFilename,
        requireSQLite,
        status,
        error);
    BOOST_REQUIRE(explicitSQLite);
    BOOST_CHECK(status == DatabaseStatus::SUCCESS);
    BOOST_CHECK(explicitSQLite->Format() == DatabaseFormat::SQLITE);
    BOOST_CHECK(fs::exists(explicitSQLitePath));
    explicitSQLite.reset();

    DatabaseOptions requireExistingBerkeley;
    requireExistingBerkeley.require_existing = true;
    requireExistingBerkeley.require_format = DatabaseFormat::BERKELEY;
    BOOST_CHECK(!makeDatabase(
        explicitSQLiteFilename,
        requireExistingBerkeley,
        status,
        error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_BAD_FORMAT);
    RemoveSQLiteTestFiles(explicitSQLiteFilename);
#else
    BOOST_CHECK(!makeDatabase(explicitSQLiteFilename, requireSQLite, status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_UNSUPPORTED);
    BOOST_CHECK(!fs::exists(explicitSQLitePath));
#endif

    std::unique_ptr<WalletDatabase> defaultDatabase = makeDatabase(missingFilename, defaults, status, error);
    BOOST_REQUIRE(defaultDatabase);
    BOOST_CHECK(status == DatabaseStatus::SUCCESS);
#ifdef USE_SQLITE
    BOOST_CHECK(defaultDatabase->Format() == DatabaseFormat::SQLITE);
    BOOST_CHECK(fs::exists(missingPath));
#else
    BOOST_CHECK(defaultDatabase->Format() == DatabaseFormat::BERKELEY);
    BOOST_CHECK(!fs::exists(missingPath));
#endif
    {
        std::unique_ptr<DatabaseBatch> batch = defaultDatabase->MakeBatch({DatabaseBatchMode::READ_WRITE_CREATE});
        BOOST_REQUIRE(batch);
        BOOST_REQUIRE(batch->Write(std::string("default-key"), std::string("default-value")));
    }
    BOOST_REQUIRE(defaultDatabase->PeriodicFlush());
    defaultDatabase.reset();

    std::unique_ptr<WalletDatabase> defaultReopened = makeDatabase(missingFilename, requireExisting, status, error);
    BOOST_REQUIRE(defaultReopened);
#ifdef USE_SQLITE
    BOOST_CHECK(defaultReopened->Format() == DatabaseFormat::SQLITE);
#else
    BOOST_CHECK(defaultReopened->Format() == DatabaseFormat::BERKELEY);
#endif
    {
        std::unique_ptr<DatabaseBatch> batch = defaultReopened->MakeBatch({DatabaseBatchMode::READ_ONLY});
        BOOST_REQUIRE(batch);
        std::string value;
        BOOST_CHECK(batch->Read(std::string("default-key"), value));
        BOOST_CHECK_EQUAL(value, "default-value");
    }
    BOOST_REQUIRE(defaultReopened->PeriodicFlush());
    defaultReopened.reset();
#ifdef USE_SQLITE
    RemoveSQLiteTestFiles(missingFilename);
#else
    BOOST_CHECK(bitdb.RemoveDb(missingFilename));
#endif

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
#ifdef USE_SQLITE
    BOOST_CHECK(status == DatabaseStatus::FAILED_VERIFY);
#else
    BOOST_CHECK(status == DatabaseStatus::FAILED_UNSUPPORTED);
#endif
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

    BOOST_CHECK(!makeDatabase(berkeleyFilename, requireBerkeleyCreate, status, error));
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

#if defined(USE_SQLITE) && (defined(__linux__) || defined(__APPLE__))
BOOST_AUTO_TEST_CASE(berkeley_migration_backup_is_exclusive_and_private)
{
    const std::string sourceFilename{
        "migration_backup_source.dat"};
    DatabaseOptions createOptions;
    createOptions.require_create = true;
    createOptions.require_format =
        DatabaseFormat::BERKELEY;
    DatabaseStatus status;
    std::string error;
    std::unique_ptr<WalletDatabase> source =
        MakeWalletDatabase(
            sourceFilename,
            createOptions,
            status,
            error);
    BOOST_REQUIRE(source);
    {
        auto batch = source->MakeBatch(
            {DatabaseBatchMode::READ_WRITE_CREATE});
        BOOST_REQUIRE(batch);
        BOOST_REQUIRE(batch->Write(
            std::string("migration-backup-key"),
            std::string("migration-backup-value")));
    }
    BOOST_REQUIRE(source->PeriodicFlush());
    source.reset();
    source = ReopenBerkeleyForMigration(
        sourceFilename,
        error);
    BOOST_REQUIRE_MESSAGE(source, error);

    BerkeleyDatabase* const berkeley =
        dynamic_cast<BerkeleyDatabase*>(
            source.get());
    BOOST_REQUIRE(berkeley);
    const std::string collisionFilename{
        "migration-backup-collision.bak"};
    const fs::path collisionPath =
        GetDataDir() / collisionFilename;
    const std::string collisionContents{
        "must not be overwritten"};
    WriteFile(collisionPath, collisionContents);
    BOOST_CHECK(
        berkeley->CreateMigrationBackup(
            collisionFilename,
            error) ==
        MigrationBackupResult::EXISTS);
    BOOST_CHECK_EQUAL(
        ReadFile(collisionPath),
        collisionContents);
    BOOST_REQUIRE(fs::remove(collisionPath));

    const std::string backupFilename{
        "migration-backup-private.bak"};
    BOOST_REQUIRE(
        berkeley->CreateMigrationBackup(
            backupFilename,
            error) ==
        MigrationBackupResult::SUCCESS);
    BOOST_CHECK(error.empty());
    const fs::path backupPath =
        GetDataDir() / backupFilename;
    BOOST_CHECK_EQUAL(
        berkeley->MigrationBackupPath().string(),
        backupPath.string());
    struct stat metadata{};
    BOOST_REQUIRE(
        lstat(
            backupPath.string().c_str(),
            &metadata) == 0);
    BOOST_CHECK(S_ISREG(metadata.st_mode));
    BOOST_CHECK_EQUAL(metadata.st_nlink, 1);
    BOOST_CHECK_EQUAL(
        metadata.st_mode & 0777,
        S_IRUSR | S_IWUSR);
    BOOST_CHECK(
        berkeley->MigrationBackupMatchesPath(
            error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK(
        berkeley->PrepareForMigrationPublication(
            error));
    BOOST_CHECK(error.empty());

    DatabaseOptions openBackup;
    openBackup.require_existing = true;
    openBackup.require_format =
        DatabaseFormat::BERKELEY;
    std::unique_ptr<WalletDatabase> backup =
        MakeWalletDatabase(
            backupFilename,
            openBackup,
            status,
            error);
    BOOST_REQUIRE(backup);
    std::string value;
    {
        auto batch = backup->MakeBatch(
            {DatabaseBatchMode::READ_ONLY});
        BOOST_REQUIRE(batch);
        BOOST_CHECK(batch->Read(
            std::string("migration-backup-key"),
            value));
    }
    BOOST_CHECK_EQUAL(
        value,
        "migration-backup-value");

    source->Flush(true);
    backup.reset();
    source.reset();
    bitdb.Close();
    bitdb.Reset();

    CDBEnv reopenedEnvironment;
    BOOST_REQUIRE(
        reopenedEnvironment.Open(
            GetDataDir()));
    struct stat sourceMetadata{};
    BOOST_REQUIRE(
        lstat(
            (GetDataDir() / sourceFilename)
                .string()
                .c_str(),
            &sourceMetadata) == 0);
    std::unique_ptr<WalletDatabase> reopenedSource =
        MakeBerkeleyDatabase(
            reopenedEnvironment,
            sourceFilename,
            {},
            DatabaseFileIdentity{
                static_cast<uint64_t>(
                    sourceMetadata.st_dev),
                static_cast<uint64_t>(
                    sourceMetadata.st_ino)});
    {
        auto batch = reopenedSource->MakeBatch(
            {DatabaseBatchMode::READ_ONLY});
        BOOST_REQUIRE(batch);
        value.clear();
        BOOST_REQUIRE(batch->Read(
            std::string("migration-backup-key"),
            value));
        BOOST_CHECK_EQUAL(
            value,
            "migration-backup-value");
    }
    reopenedSource.reset();
    reopenedEnvironment.Flush(true);
    BOOST_REQUIRE(bitdb.Open(GetDataDir()));
}

BOOST_AUTO_TEST_CASE(wallet_database_migration_preserves_raw_records)
{
    const std::string sourceFilename{
        "migration_raw_source.dat"};
    DatabaseOptions createOptions;
    createOptions.require_create = true;
    createOptions.require_format =
        DatabaseFormat::BERKELEY;
    DatabaseStatus status;
    std::string error;
    std::unique_ptr<WalletDatabase> source =
        MakeWalletDatabase(
            sourceFilename,
            createOptions,
            status,
            error);
    BOOST_REQUIRE(source);
    {
        CWalletDB walletDatabase(*source);
        BOOST_REQUIRE(walletDatabase.WriteKV(
            "migration-known",
            "known-value"));
    }
    {
        auto batch = source->MakeBatch(
            {DatabaseBatchMode::READ_WRITE});
        BOOST_REQUIRE(batch);
        BOOST_REQUIRE(batch->Write(
            std::string("version"),
            CLIENT_VERSION - 1));
        CDataStream key(SER_DISK, CLIENT_VERSION);
        key << std::make_pair(
            std::string("future-wallet-record"),
            uint32_t{7});
        CDataStream value(SER_DISK, CLIENT_VERSION);
        const std::array<unsigned char, 7> rawValue{{
            0x00,
            0x01,
            0x7f,
            0x80,
            0xff,
            0x00,
            0x42,
        }};
        value.write(
            reinterpret_cast<const char*>(
                rawValue.data()),
            rawValue.size());
        BOOST_REQUIRE(batch->WriteRawRecord(
            std::move(key),
            std::move(value),
            false));
    }

    std::vector<RawRecord> expected;
    {
        auto batch = source->MakeBatch(
            {DatabaseBatchMode::READ_ONLY});
        BOOST_REQUIRE(batch);
        expected = ReadRawRecords(*batch);
    }
    BOOST_REQUIRE(source->PeriodicFlush());
    source.reset();
    source = ReopenBerkeleyForMigration(
        sourceFilename,
        error);
    BOOST_REQUIRE_MESSAGE(source, error);

    std::string backupPath;
    BOOST_REQUIRE_MESSAGE(
        MigrateWalletDatabaseToSQLite(
            *source,
            backupPath,
            error),
        error);
    BOOST_CHECK(error.empty());
    BOOST_REQUIRE(!backupPath.empty());
    source.reset();

    const fs::path backupFilesystemPath{
        backupPath};
    BOOST_CHECK(
        fs::is_regular_file(
            backupFilesystemPath));
    struct stat backupMetadata{};
    BOOST_REQUIRE(
        lstat(
            backupFilesystemPath.string().c_str(),
            &backupMetadata) == 0);
    BOOST_CHECK_EQUAL(
        backupMetadata.st_mode & 0777,
        S_IRUSR | S_IWUSR);

    DatabaseOptions openSQLite;
    openSQLite.require_existing = true;
    openSQLite.require_format =
        DatabaseFormat::SQLITE;
    std::unique_ptr<WalletDatabase> migrated =
        MakeWalletDatabase(
            sourceFilename,
            openSQLite,
            status,
            error);
    BOOST_REQUIRE(migrated);
    {
        auto batch = migrated->MakeBatch(
            {DatabaseBatchMode::READ_ONLY});
        BOOST_REQUIRE(batch);
        BOOST_CHECK(
            ReadRawRecords(*batch) ==
            expected);
    }

    DatabaseOptions openBackup;
    openBackup.require_existing = true;
    openBackup.require_format =
        DatabaseFormat::BERKELEY;
    std::unique_ptr<WalletDatabase> backup =
        MakeWalletDatabase(
            backupFilesystemPath.filename().string(),
            openBackup,
            status,
            error);
    BOOST_REQUIRE(backup);
    {
        auto batch = backup->MakeBatch(
            {DatabaseBatchMode::READ_ONLY});
        BOOST_REQUIRE(batch);
        BOOST_CHECK(
            ReadRawRecords(*batch) ==
            expected);
    }

    {
        CWalletDB walletDatabase(*migrated);
        BOOST_REQUIRE(walletDatabase.WriteKV(
            "migration-post-write",
            "post-write-value"));
    }
    migrated.reset();
    migrated = MakeWalletDatabase(
        sourceFilename,
        openSQLite,
        status,
        error);
    BOOST_REQUIRE(migrated);
    std::string postWrite;
    {
        auto batch = migrated->MakeBatch(
            {DatabaseBatchMode::READ_ONLY});
        BOOST_REQUIRE(batch);
        BOOST_CHECK(batch->Read(
            std::make_pair(
                std::string("kv"),
                std::string("migration-post-write")),
            postWrite));
    }
    BOOST_CHECK_EQUAL(
        postWrite,
        "post-write-value");
}

BOOST_AUTO_TEST_CASE(wallet_database_migration_rejects_corrupt_and_empty_keys)
{
    auto createSource = [](
                            const std::string& filename) {
        DatabaseOptions options;
        options.require_create = true;
        options.require_format =
            DatabaseFormat::BERKELEY;
        DatabaseStatus status;
        std::string error;
        return MakeWalletDatabase(
            filename,
            options,
            status,
            error);
    };

    const std::string corruptFilename{
        "migration_corrupt_source.dat"};
    std::unique_ptr<WalletDatabase> corrupt =
        createSource(corruptFilename);
    BOOST_REQUIRE(corrupt);
    {
        auto batch = corrupt->MakeBatch(
            {DatabaseBatchMode::READ_WRITE_CREATE});
        BOOST_REQUIRE(batch);
        CDataStream key(SER_DISK, CLIENT_VERSION);
        key << std::string("key");
        CDataStream value(SER_DISK, CLIENT_VERSION);
        value << std::string("malformed private key record");
        BOOST_REQUIRE(batch->WriteRawRecord(
            std::move(key),
            std::move(value),
            false));
    }
    std::vector<RawRecord> corruptRecords;
    {
        auto batch = corrupt->MakeBatch(
            {DatabaseBatchMode::READ_ONLY});
        corruptRecords = ReadRawRecords(*batch);
    }
    std::string error;
    BOOST_REQUIRE(corrupt->PeriodicFlush());
    corrupt.reset();
    corrupt = ReopenBerkeleyForMigration(
        corruptFilename,
        error);
    BOOST_REQUIRE_MESSAGE(corrupt, error);
    std::string backupPath;
    BOOST_CHECK(!MigrateWalletDatabaseToSQLite(
        *corrupt,
        backupPath,
        error));
    BOOST_CHECK(!backupPath.empty());
    BOOST_CHECK(
        error.find(backupPath) !=
        std::string::npos);
    BOOST_CHECK(
        IsBerkeleyDatabase(
            GetDataDir() / corruptFilename));
    {
        auto batch = corrupt->MakeBatch(
            {DatabaseBatchMode::READ_ONLY});
        BOOST_CHECK(
            ReadRawRecords(*batch) ==
            corruptRecords);
    }
    BOOST_CHECK(
        FindMigrationPaths(
            ".firo-wallet-sqlite-migration-")
            .empty());

    const std::string emptyFilename{
        "migration_empty_key_source.dat"};
    std::unique_ptr<WalletDatabase> empty =
        createSource(emptyFilename);
    BOOST_REQUIRE(empty);
    {
        auto batch = empty->MakeBatch(
            {DatabaseBatchMode::READ_WRITE_CREATE});
        BOOST_REQUIRE(batch);
        CDataStream key(SER_DISK, CLIENT_VERSION);
        CDataStream value(SER_DISK, CLIENT_VERSION);
        value << std::string("reserved");
        BOOST_REQUIRE(batch->WriteRawRecord(
            std::move(key),
            std::move(value),
            false));
    }
    BOOST_REQUIRE(empty->PeriodicFlush());
    empty.reset();
    empty = ReopenBerkeleyForMigration(
        emptyFilename,
        error);
    BOOST_REQUIRE_MESSAGE(empty, error);
    backupPath.clear();
    error.clear();
    BOOST_CHECK(!MigrateWalletDatabaseToSQLite(
        *empty,
        backupPath,
        error));
    BOOST_CHECK(
        error.find("raw empty key") !=
        std::string::npos);
    BOOST_CHECK(
        IsBerkeleyDatabase(
            GetDataDir() / emptyFilename));
    BOOST_CHECK(
        FindMigrationPaths(
            ".firo-wallet-sqlite-migration-")
            .empty());
}

BOOST_AUTO_TEST_CASE(wallet_database_migration_exchange_error_is_indeterminate)
{
    ShutdownRequestReset shutdownReset;
    fRequestShutdown.store(false);

    const std::string sourceFilename{
        "migration_exchange_source.dat"};
    DatabaseOptions createOptions;
    createOptions.require_create = true;
    createOptions.require_format =
        DatabaseFormat::BERKELEY;
    DatabaseStatus status;
    std::string error;
    std::unique_ptr<WalletDatabase> source =
        MakeWalletDatabase(
            sourceFilename,
            createOptions,
            status,
            error);
    BOOST_REQUIRE(source);
    {
        CWalletDB walletDatabase(*source);
        BOOST_REQUIRE(walletDatabase.WriteKV(
            "migration-exchange",
            "preserved"));
    }
    BOOST_REQUIRE(source->PeriodicFlush());
    source.reset();
    source = ReopenBerkeleyForMigration(
        sourceFilename,
        error);
    BOOST_REQUIRE_MESSAGE(source, error);

    InjectSQLiteMigrationExchangeFailureForTesting();
    std::string backupPath;
    BOOST_CHECK(!MigrateWalletDatabaseToSQLite(
        *source,
        backupPath,
        error));
    BOOST_CHECK(fRequestShutdown.load());
    BOOST_CHECK(!backupPath.empty());
    BOOST_CHECK(
        error.find(backupPath) !=
        std::string::npos);
    source.reset();

    DatabaseOptions openSQLite;
    openSQLite.require_existing = true;
    openSQLite.require_format =
        DatabaseFormat::SQLITE;
    std::unique_ptr<WalletDatabase> finalDatabase =
        MakeWalletDatabase(
            sourceFilename,
            openSQLite,
            status,
            error);
    BOOST_REQUIRE(finalDatabase);

    const std::vector<fs::path> displaced =
        FindMigrationPaths(
            ".firo-wallet-sqlite-migration-");
    BOOST_REQUIRE_EQUAL(displaced.size(), 1);
    BOOST_CHECK(
        IsBerkeleyDatabase(
            displaced.front()));
    DatabaseOptions openBerkeley;
    openBerkeley.require_existing = true;
    openBerkeley.require_format =
        DatabaseFormat::BERKELEY;
    std::unique_ptr<WalletDatabase> displacedDatabase =
        MakeWalletDatabase(
            displaced.front().filename().string(),
            openBerkeley,
            status,
            error);
    BOOST_REQUIRE(displacedDatabase);
    std::unique_ptr<WalletDatabase> backupDatabase =
        MakeWalletDatabase(
            fs::path(backupPath).filename().string(),
            openBerkeley,
            status,
            error);
    BOOST_REQUIRE(backupDatabase);
}

BOOST_AUTO_TEST_CASE(wallet_database_migration_candidate_is_one_shot)
{
    ShutdownRequestReset shutdownReset;
    fRequestShutdown.store(false);

    const std::string sourceFilename{
        "migration_one_shot_source.dat"};
    DatabaseOptions createSourceOptions;
    createSourceOptions.require_create = true;
    createSourceOptions.require_format =
        DatabaseFormat::BERKELEY;
    DatabaseStatus status;
    std::string error;
    std::unique_ptr<WalletDatabase> source =
        MakeWalletDatabase(
            sourceFilename,
            createSourceOptions,
            status,
            error);
    BOOST_REQUIRE(source);
    {
        auto batch = source->MakeBatch(
            {DatabaseBatchMode::READ_WRITE_CREATE});
        BOOST_REQUIRE(batch);
        BOOST_REQUIRE(batch->Write(
            std::string("one-shot-source"),
            std::string("preserved-in-backup")));
    }
    BOOST_REQUIRE(source->PeriodicFlush());
    source.reset();
    source = ReopenBerkeleyForMigration(
        sourceFilename,
        error);
    BOOST_REQUIRE_MESSAGE(source, error);

    BerkeleyDatabase* const berkeley =
        dynamic_cast<BerkeleyDatabase*>(
            source.get());
    BOOST_REQUIRE(berkeley);
    BOOST_REQUIRE(
        berkeley->CreateMigrationBackup(
            "migration-one-shot-backup.bak",
            error) ==
        MigrationBackupResult::SUCCESS);
    const fs::path sourcePath =
        GetDataDir() / sourceFilename;
    const std::string sourceContents =
        ReadFile(sourcePath);
    const std::string backupContents =
        ReadFile(
            berkeley->MigrationBackupPath());

    const std::string candidateFilename{
        ".migration-one-shot-candidate.tmp"};
    DatabaseOptions candidateOptions;
    candidateOptions.require_create = true;
    candidateOptions.require_format =
        DatabaseFormat::SQLITE;
    candidateOptions.logical_wallet_create = true;
    candidateOptions.sqlite_migration_candidate = true;
    std::unique_ptr<WalletDatabase> candidate =
        MakeWalletDatabase(
            candidateFilename,
            candidateOptions,
            status,
            error);
    BOOST_REQUIRE_MESSAGE(candidate, error);
    BOOST_REQUIRE(
        candidate->CompleteCreation(error) ==
        DatabaseCreationResult::COMPLETE);
    BOOST_REQUIRE(error.empty());

    std::unique_ptr<DatabaseBatch> blockingSourceBatch =
        source->MakeBatch(
            {DatabaseBatchMode::READ_ONLY});
    BOOST_REQUIRE(blockingSourceBatch);
    std::promise<void> publisherStarted;
    std::future<void> publisherReady =
        publisherStarted.get_future();
    std::atomic<bool> interruptionObserved{false};
    boost::thread interruptedPublisher([&] {
        publisherStarted.set_value();
        try {
            PublishSQLiteMigrationCandidate(
                *candidate,
                *berkeley,
                error);
        } catch (const boost::thread_interrupted&) {
            interruptionObserved.store(true);
        }
    });
    publisherReady.wait();
    interruptedPublisher.interrupt();
    interruptedPublisher.join();
    BOOST_CHECK(interruptionObserved.load());
    BOOST_CHECK(
        error.find("exact owned candidate") !=
        std::string::npos);
    BOOST_CHECK(!fRequestShutdown.load());
    BOOST_CHECK(!fs::exists(
        GetDataDir() / candidateFilename));
    std::optional<DatabaseFormat> sourceFormat;
    BOOST_REQUIRE(
        ReadWalletDatabaseFormat(
            sourceFilename,
            sourceFormat,
            error));
    BOOST_REQUIRE(sourceFormat);
    BOOST_CHECK(
        *sourceFormat ==
        DatabaseFormat::BERKELEY);
    BOOST_CHECK_EQUAL(
        ReadFile(sourcePath),
        sourceContents);
    BOOST_CHECK_EQUAL(
        ReadFile(
            berkeley->MigrationBackupPath()),
        backupContents);
    BOOST_CHECK(
        berkeley->MigrationBackupMatchesPath(
            error));

    blockingSourceBatch.reset();
    candidate.reset();
    candidate = MakeWalletDatabase(
        candidateFilename,
        candidateOptions,
        status,
        error);
    BOOST_REQUIRE_MESSAGE(candidate, error);
    BOOST_REQUIRE(
        candidate->CompleteCreation(error) ==
        DatabaseCreationResult::COMPLETE);
    BOOST_REQUIRE(error.empty());

    BOOST_REQUIRE(
        PublishSQLiteMigrationCandidate(
            *candidate,
            *berkeley,
            error) ==
        SQLiteMigrationPublishResult::SUCCESS);
    BOOST_REQUIRE(error.empty());
    std::optional<DatabaseFormat> finalFormat;
    BOOST_REQUIRE(
        ReadWalletDatabaseFormat(
            sourceFilename,
            finalFormat,
            error));
    BOOST_REQUIRE(finalFormat);
    BOOST_CHECK(
        *finalFormat ==
        DatabaseFormat::SQLITE);
    const std::string finalContents =
        ReadFile(sourcePath);

    BOOST_CHECK(
        PublishSQLiteMigrationCandidate(
            *candidate,
            *berkeley,
            error) ==
        SQLiteMigrationPublishResult::FAILED);
    BOOST_CHECK(
        error.find("already published and consumed") !=
        std::string::npos);
    BOOST_CHECK(!fRequestShutdown.load());
    BOOST_CHECK(!fs::exists(
        GetDataDir() / candidateFilename));
    BOOST_CHECK_EQUAL(
        ReadFile(sourcePath),
        finalContents);
    BOOST_CHECK_EQUAL(
        ReadFile(
            berkeley->MigrationBackupPath()),
        backupContents);
    BOOST_CHECK(
        berkeley->MigrationBackupMatchesPath(
            error));
}
#endif

BOOST_AUTO_TEST_CASE(berkeley_factory_first_open_policy)
{
    DatabaseStatus status;
    std::string error;
    DatabaseOptions requireCreate;
    requireCreate.require_create = true;
    requireCreate.require_format = DatabaseFormat::BERKELEY;

    const std::string appearedFilename{
        "factory_bdb_appeared_before_open.dat"};
    const fs::path appearedPath = GetDataDir() / appearedFilename;
    std::unique_ptr<WalletDatabase> createOwner =
        MakeWalletDatabase(
            appearedFilename,
            requireCreate,
            status,
            error);
    BOOST_REQUIRE(createOwner);
    BOOST_CHECK(!fs::exists(appearedPath));

    std::unique_ptr<WalletDatabase> racedDatabase =
        MakeBerkeleyDatabase(bitdb, appearedFilename);
    std::unique_ptr<DatabaseBatch> racedBatch =
        racedDatabase->MakeBatch(
            {DatabaseBatchMode::READ_WRITE_CREATE});
    BOOST_REQUIRE(racedBatch);
    BOOST_REQUIRE(racedBatch->Write(
        std::string("raced-record"),
        std::string("must-remain")));
    BOOST_CHECK_THROW(
        createOwner->MakeBatch(
            {DatabaseBatchMode::READ_WRITE_CREATE}),
        std::runtime_error);
    {
        LOCK(bitdb.cs_db);
        BOOST_REQUIRE(
            bitdb.mapFileUseCount.count(appearedFilename) == 1);
        BOOST_CHECK_EQUAL(
            bitdb.mapFileUseCount.at(appearedFilename),
            1);
    }
    racedBatch.reset();
    BOOST_REQUIRE(racedDatabase->PeriodicFlush());
    BOOST_CHECK_THROW(
        createOwner->MakeBatch(
            {DatabaseBatchMode::READ_WRITE_CREATE}),
        std::runtime_error);
    {
        LOCK(bitdb.cs_db);
        BOOST_CHECK(
            bitdb.mapFileUseCount.count(appearedFilename) == 0);
    }
    {
        std::unique_ptr<DatabaseBatch> racedBatch =
            racedDatabase->MakeBatch(
                {DatabaseBatchMode::READ_ONLY});
        BOOST_REQUIRE(racedBatch);
        std::string value;
        BOOST_REQUIRE(racedBatch->Read(
            std::string("raced-record"),
            value));
        BOOST_CHECK_EQUAL(value, "must-remain");
    }
    BOOST_REQUIRE(racedDatabase->PeriodicFlush());
    racedDatabase.reset();
    createOwner.reset();
    BOOST_REQUIRE(bitdb.RemoveDb(appearedFilename));

    const std::string disappearedFilename{
        "factory_bdb_disappeared_before_open.dat"};
    const fs::path disappearedPath =
        GetDataDir() / disappearedFilename;
    std::unique_ptr<WalletDatabase> existingDatabase =
        MakeBerkeleyDatabase(bitdb, disappearedFilename);
    {
        std::unique_ptr<DatabaseBatch> batch =
            existingDatabase->MakeBatch(
                {DatabaseBatchMode::READ_WRITE_CREATE});
        BOOST_REQUIRE(batch);
        BOOST_REQUIRE(batch->Write(
            std::string("existing-record"),
            std::string("existing")));
    }
    BOOST_REQUIRE(existingDatabase->PeriodicFlush());
    existingDatabase.reset();

    DatabaseOptions requireExisting;
    requireExisting.require_existing = true;
    requireExisting.require_format = DatabaseFormat::BERKELEY;
    std::unique_ptr<WalletDatabase> existingOwner =
        MakeWalletDatabase(
            disappearedFilename,
            requireExisting,
            status,
            error);
    BOOST_REQUIRE(existingOwner);
    BOOST_REQUIRE(bitdb.RemoveDb(disappearedFilename));
    BOOST_REQUIRE(!fs::exists(disappearedPath));
    BOOST_CHECK_THROW(
        existingOwner->MakeBatch(
            {DatabaseBatchMode::READ_WRITE_CREATE}),
        std::runtime_error);
    BOOST_CHECK(!fs::exists(disappearedPath));
    {
        LOCK(bitdb.cs_db);
        BOOST_CHECK(
            bitdb.mapFileUseCount.count(disappearedFilename) == 0);
    }
    existingOwner.reset();

#ifndef WIN32
    const std::string retainedFilename{
        "factory_bdb_retained_identity.dat"};
    const std::string substituteFilename{
        "factory_bdb_substitute_identity.dat"};
    const std::string displacedFilename{
        "factory_bdb_displaced_identity.dat"};
    const fs::path retainedPath =
        GetDataDir() / retainedFilename;
    const fs::path substitutePath =
        GetDataDir() / substituteFilename;
    const fs::path displacedPath =
        GetDataDir() / displacedFilename;
    auto createIdentityWallet = [](const std::string& filename,
                                    const std::string& value) {
        std::unique_ptr<WalletDatabase> database =
            MakeBerkeleyDatabase(bitdb, filename);
        {
            std::unique_ptr<DatabaseBatch> batch =
                database->MakeBatch(
                    {DatabaseBatchMode::READ_WRITE_CREATE});
            BOOST_REQUIRE(batch);
            BOOST_REQUIRE(batch->Write(
                std::string("identity-record"),
                value));
        }
        BOOST_REQUIRE(database->PeriodicFlush());
    };
    createIdentityWallet(retainedFilename, "retained");
    createIdentityWallet(substituteFilename, "substitute");

    DatabaseOptions retainedOptions = requireExisting;
    retainedOptions.verify = false;
    std::unique_ptr<WalletDatabase> retainedOwner =
        MakeWalletDatabase(
            retainedFilename,
            retainedOptions,
            status,
            error);
    BOOST_REQUIRE(retainedOwner);
    fs::rename(retainedPath, displacedPath);
    fs::rename(substitutePath, retainedPath);
    BOOST_CHECK_THROW(
        retainedOwner->MakeBatch(
            {DatabaseBatchMode::READ_WRITE_CREATE}),
        std::runtime_error);
    retainedOwner.reset();
    fs::rename(retainedPath, substitutePath);
    fs::rename(displacedPath, retainedPath);

    auto checkIdentityWallet = [](const std::string& filename,
                                   const std::string& expected) {
        std::unique_ptr<WalletDatabase> database =
            MakeBerkeleyDatabase(bitdb, filename);
        std::unique_ptr<DatabaseBatch> batch =
            database->MakeBatch(
                {DatabaseBatchMode::READ_ONLY});
        BOOST_REQUIRE(batch);
        std::string value;
        BOOST_REQUIRE(batch->Read(
            std::string("identity-record"),
            value));
        BOOST_CHECK_EQUAL(value, expected);
        batch.reset();
        BOOST_REQUIRE(database->PeriodicFlush());
    };
    checkIdentityWallet(retainedFilename, "retained");
    checkIdentityWallet(substituteFilename, "substitute");
    BOOST_REQUIRE(bitdb.RemoveDb(retainedFilename));
    BOOST_REQUIRE(bitdb.RemoveDb(substituteFilename));
#endif

    const std::string cachedFilename{
        "factory_bdb_cached_before_open.dat"};
    std::unique_ptr<WalletDatabase> cachedDatabase =
        MakeBerkeleyDatabase(bitdb, cachedFilename);
    {
        std::unique_ptr<DatabaseBatch> batch =
            cachedDatabase->MakeBatch(
                {DatabaseBatchMode::READ_WRITE_CREATE});
        BOOST_REQUIRE(batch);
        BOOST_REQUIRE(batch->Write(
            std::string("cached-record"),
            std::string("preserved")));
    }
    DatabaseOptions cachedExistingOptions =
        requireExisting;
    cachedExistingOptions.verify = false;
    std::unique_ptr<WalletDatabase> cachedExistingOwner =
        MakeWalletDatabase(
            cachedFilename,
            cachedExistingOptions,
            status,
            error);
    BOOST_REQUIRE(cachedExistingOwner);
    {
        std::unique_ptr<DatabaseBatch> batch =
            cachedExistingOwner->MakeBatch(
                {DatabaseBatchMode::READ_WRITE_CREATE});
        BOOST_REQUIRE(batch);
        std::string value;
        BOOST_REQUIRE(batch->Read(
            std::string("cached-record"),
            value));
        BOOST_CHECK_EQUAL(value, "preserved");
    }
    BOOST_REQUIRE(cachedExistingOwner->PeriodicFlush());
    cachedExistingOwner.reset();
    cachedDatabase.reset();
    BOOST_REQUIRE(bitdb.RemoveDb(cachedFilename));

    const std::string consumedFilename{
        "factory_bdb_first_open_consumed.dat"};
    std::unique_ptr<WalletDatabase> consumedOwner =
        MakeWalletDatabase(
            consumedFilename,
            requireCreate,
            status,
            error);
    BOOST_REQUIRE(consumedOwner);
    std::unique_ptr<DatabaseBatch> firstBatch =
        consumedOwner->MakeBatch(
            {DatabaseBatchMode::READ_WRITE_CREATE});
    BOOST_REQUIRE(firstBatch);
    BOOST_REQUIRE(firstBatch->Write(
        std::string("first"),
        std::string("created")));
    std::unique_ptr<DatabaseBatch> secondBatch =
        consumedOwner->MakeBatch(
            {DatabaseBatchMode::READ_WRITE_CREATE});
    BOOST_REQUIRE(secondBatch);
    BOOST_REQUIRE(secondBatch->Write(
        std::string("second"),
        std::string("ordinary")));
    std::string value;
    BOOST_REQUIRE(secondBatch->Read(std::string("first"), value));
    BOOST_CHECK_EQUAL(value, "created");
    firstBatch.reset();
    secondBatch.reset();
    BOOST_REQUIRE(consumedOwner->PeriodicFlush());
    consumedOwner.reset();
    BOOST_REQUIRE(bitdb.RemoveDb(consumedFilename));
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
        BOOST_CHECK(
            batch.ReadWithStatus(binaryKey, value) ==
            DatabaseReadStatus::SUCCESS);
        BOOST_CHECK(
            batch.ReadWithStatus(std::string("absent"), value) ==
            DatabaseReadStatus::NOT_FOUND);
        BOOST_CHECK(
            batch.ExistsWithStatus(binaryKey) ==
            DatabaseReadStatus::SUCCESS);
        BOOST_CHECK(
            batch.ExistsWithStatus(std::string("absent")) ==
            DatabaseReadStatus::NOT_FOUND);

        BOOST_CHECK(batch.Write(binaryKey, std::string("replacement")));
        BOOST_CHECK(batch.Read(binaryKey, value));
        BOOST_CHECK_EQUAL(value, "replacement");
        BOOST_REQUIRE(batch.Write(
            std::string("malformed-value"),
            uint8_t{1}));
        uint64_t malformedValue{0};
        BOOST_CHECK(
            batch.ReadWithStatus(
                std::string("malformed-value"),
                malformedValue) ==
            DatabaseReadStatus::CORRUPT);
        BOOST_REQUIRE(batch.Erase(std::string("malformed-value")));

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
        batch.Close();
        std::string closedValue;
        BOOST_CHECK(
            batch.ReadWithStatus(binaryKey, closedValue) ==
            DatabaseReadStatus::FAILED);
        BOOST_CHECK(
            batch.ExistsWithStatus(binaryKey) ==
            DatabaseReadStatus::FAILED);
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

    const std::string backupFilename{
        "database_batch_test.backup"};
    const fs::path backupPath =
        GetDataDir() / backupFilename;
    BOOST_REQUIRE(database.Backup(
        backupPath.string()));
    const std::string firstBackup =
        ReadFile(backupPath);
    {
        BerkeleyBatchForTest batch(database, "r+");
        BOOST_REQUIRE(batch.Write(
            std::string("after-first-backup"),
            std::string("overwritten-backup-value")));
    }
    BOOST_REQUIRE(database.Backup(
        backupPath.string()));
    BOOST_CHECK(
        ReadFile(backupPath) != firstBackup);
    BOOST_CHECK(
        ReadFile(backupPath) ==
        ReadFile(GetDataDir() / filename));

    const fs::path backupDirectory =
        GetDataDir() / "database-backup-directory";
    const fs::path directoryBackupPath =
        backupDirectory / filename;
    BOOST_REQUIRE(fs::create_directory(backupDirectory));
    BOOST_REQUIRE(database.Backup(
        backupDirectory.string()));
    BOOST_CHECK(
        ReadFile(directoryBackupPath) ==
        ReadFile(GetDataDir() / filename));

    const fs::path missingParent =
        GetDataDir() / "missing-backup-parent";
    const fs::path failedBackup =
        missingParent / "database.backup";
    BOOST_CHECK(!fs::exists(missingParent));
    BOOST_CHECK(!database.Backup(
        failedBackup.string()));

    BOOST_CHECK(fs::remove(directoryBackupPath));
    BOOST_CHECK(fs::remove(backupDirectory));
    BOOST_CHECK(fs::remove(backupPath));
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
    const std::string publicationCollisionFilename{
        "sqlite_batch_publish_collision.backup"};
    const fs::path publicationCollisionPath =
        GetDataDir() / publicationCollisionFilename;
    const fs::path backupDirectory = GetDataDir() / "sqlite_backup_directory";
    const fs::path directoryBackupPath = backupDirectory / filename;
    const std::string binaryKey{"key\0\xff", 5};
    const std::string binaryValue{"value\0\xff", 7};
    RemoveSQLiteTestFiles(filename);
    RemoveSQLiteTestFiles(backupFilename);
    RemoveSQLiteTestFiles(publicationCollisionFilename);
    RemoveSQLiteTestCandidates(publicationCollisionFilename);
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
    BOOST_CHECK(
        batch->ReadWithStatus(binaryKey, value) ==
        DatabaseReadStatus::SUCCESS);
    BOOST_CHECK(
        batch->ReadWithStatus(std::string("absent"), value) ==
        DatabaseReadStatus::NOT_FOUND);
    BOOST_CHECK(
        batch->ExistsWithStatus(binaryKey) ==
        DatabaseReadStatus::SUCCESS);
    BOOST_CHECK(
        batch->ExistsWithStatus(std::string("absent")) ==
        DatabaseReadStatus::NOT_FOUND);
    BOOST_CHECK(batch->Write(binaryKey, std::string("replacement")));
    BOOST_CHECK(batch->Read(binaryKey, value));
    BOOST_CHECK_EQUAL(value, "replacement");
    BOOST_REQUIRE(batch->Write(
        std::string("malformed-value"),
        uint8_t{1}));
    uint64_t malformedValue{0};
    BOOST_CHECK(
        batch->ReadWithStatus(
            std::string("malformed-value"),
            malformedValue) ==
        DatabaseReadStatus::CORRUPT);
    BOOST_REQUIRE(batch->Erase(std::string("malformed-value")));
    BOOST_REQUIRE(SetSQLiteStatementExecutorForTesting(
        *batch,
        std::make_unique<NonBlobSQLiteStatementExecutor>()));
    BOOST_REQUIRE(batch->TxnBegin());
    BOOST_CHECK(
        batch->ReadWithStatus(binaryKey, value) ==
        DatabaseReadStatus::CORRUPT);
    BOOST_REQUIRE(batch->TxnAbort());
    BOOST_REQUIRE(SetSQLiteStatementExecutorForTesting(
        *batch,
        std::make_unique<SQLiteStatementExecutor>()));

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
    BOOST_CHECK(
        closedBatch->ReadWithStatus(
            std::string("transaction-one"),
            value) ==
        DatabaseReadStatus::FAILED);
    BOOST_CHECK(
        closedBatch->ExistsWithStatus(
            std::string("transaction-one")) ==
        DatabaseReadStatus::FAILED);
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

    std::string backupError{"unchanged"};
    BOOST_REQUIRE(database->Backup(
        backupPath.string(),
        backupError));
    BOOST_CHECK(backupError.empty());
    BOOST_REQUIRE(fs::is_regular_file(backupPath));
    const std::string firstBackup = ReadFile(backupPath);
    const std::set<std::string> entriesBeforeCollision =
        SQLiteTestDirectoryEntries();
    backupError = "unchanged";
    BOOST_CHECK(!database->Backup(
        backupPath.string(),
        backupError));
    BOOST_CHECK(
        backupError.find("SQLite wallet") !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find(filename) !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find(backupPath.string()) !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find("new absent destination") !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find(binaryKey) ==
        std::string::npos);
    BOOST_CHECK_EQUAL(ReadFile(backupPath), firstBackup);
    for (const char* suffix : {"-journal", "-wal", "-shm"}) {
        BOOST_CHECK(!fs::exists(backupPath.string() + suffix));
    }
    BOOST_CHECK(
        SQLiteTestDirectoryEntries() ==
        entriesBeforeCollision);

    const std::set<std::string> entriesBeforePublicationCollision =
        SQLiteTestDirectoryEntries();
    InjectSQLiteBackupPublicationCollisionForTesting();
    backupError = "unchanged";
    BOOST_CHECK(!database->Backup(
        publicationCollisionPath.string(),
        backupError));
    const std::string expectedPublicationCollisionError =
        strprintf(
            "Failed to back up SQLite wallet '%s' to '%s': the destination "
            "path appeared concurrently and was not overwritten. Choose a "
            "new absent destination; SQLite wallet backups never overwrite "
            "an existing path.",
            filename,
            publicationCollisionPath.string());
    BOOST_CHECK_EQUAL(
        backupError,
        expectedPublicationCollisionError);
    BOOST_CHECK(!fs::exists(publicationCollisionPath));
    for (const char* suffix : {"-journal", "-wal", "-shm"}) {
        BOOST_CHECK(!fs::exists(
            publicationCollisionPath.string() + suffix));
    }
    BOOST_CHECK(
        SQLiteTestDirectoryEntries() ==
        entriesBeforePublicationCollision);
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
    BOOST_CHECK(!database);
    BOOST_CHECK(status == DatabaseStatus::FAILED_VERIFY);
    BOOST_CHECK(!error.empty());
    BOOST_CHECK_NE(error, "unchanged");
    BOOST_CHECK(fs::is_regular_file(path));

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
    RemoveSQLiteTestFiles(publicationCollisionFilename);
    RemoveSQLiteTestCandidates(publicationCollisionFilename);
    fs::remove_all(backupDirectory);
}

BOOST_AUTO_TEST_CASE(sqlite_column_failures_are_fail_closed)
{
    const std::string filename{"sqlite_column_failure.dat"};
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
    BOOST_REQUIRE(batch->Write(
        std::string("column-failure"),
        std::string("preserved")));

    auto blobFailure =
        std::make_unique<FailingSQLiteColumnReader>(
            SQLiteColumnFailure::BLOB,
            true);
    FailingSQLiteColumnReader* const blobFailureView =
        blobFailure.get();
    BOOST_REQUIRE(SetSQLiteColumnReaderForTesting(
        *batch,
        std::move(blobFailure)));
    BOOST_REQUIRE(batch->TxnBegin());
    std::string value{"unchanged"};
    BOOST_CHECK(
        batch->ReadWithStatus(
            std::string("column-failure"),
            value) ==
        DatabaseReadStatus::FAILED);
    BOOST_CHECK_EQUAL(value, "unchanged");
    BOOST_CHECK(blobFailureView->Failed());
    BOOST_CHECK(blobFailureView->OrderValid());
    BOOST_CHECK_EQUAL(
        blobFailureView->RollbackResult(),
        SQLITE_OK);
    BOOST_CHECK(batch->HasActiveTxn());
    BOOST_CHECK(!batch->Write(
        std::string("must-not-autocommit"),
        std::string("rejected")));
    BOOST_REQUIRE(batch->TxnAbort());
    BOOST_CHECK(!batch->HasActiveTxn());

    BOOST_REQUIRE(SetSQLiteColumnReaderForTesting(
        *batch,
        std::make_unique<SQLiteColumnReader>()));
    BOOST_REQUIRE(batch->Read(
        std::string("column-failure"),
        value));
    BOOST_CHECK_EQUAL(value, "preserved");
    BOOST_CHECK(!batch->Exists(
        std::string("must-not-autocommit")));

    auto bytesFailure =
        std::make_unique<FailingSQLiteColumnReader>(
            SQLiteColumnFailure::BYTES,
            false);
    FailingSQLiteColumnReader* const bytesFailureView =
        bytesFailure.get();
    BOOST_REQUIRE(SetSQLiteColumnReaderForTesting(
        *batch,
        std::move(bytesFailure)));
    value = "unchanged";
    BOOST_CHECK(
        batch->ReadWithStatus(
            std::string("column-failure"),
            value) ==
        DatabaseReadStatus::FAILED);
    BOOST_CHECK_EQUAL(value, "unchanged");
    BOOST_CHECK(bytesFailureView->Failed());
    BOOST_CHECK(bytesFailureView->OrderValid());
    BOOST_REQUIRE(SetSQLiteColumnReaderForTesting(
        *batch,
        std::make_unique<SQLiteColumnReader>()));
    BOOST_REQUIRE(batch->Read(
        std::string("column-failure"),
        value));
    BOOST_CHECK_EQUAL(value, "preserved");

    auto cursorFailure =
        std::make_unique<FailingSQLiteColumnReader>(
            SQLiteColumnFailure::BLOB,
            false);
    FailingSQLiteColumnReader* const cursorFailureView =
        cursorFailure.get();
    BOOST_REQUIRE(SetSQLiteColumnReaderForTesting(
        *batch,
        std::move(cursorFailure)));
    std::unique_ptr<DatabaseCursor> cursor =
        batch->GetCursor();
    BOOST_REQUIRE(cursor);
    CDataStream cursorKey(SER_DISK, CLIENT_VERSION);
    CDataStream cursorValue(SER_DISK, CLIENT_VERSION);
    BOOST_CHECK(
        cursor->Next(cursorKey, cursorValue) ==
        DatabaseCursor::Status::FAIL);
    BOOST_CHECK(cursorKey.empty());
    BOOST_CHECK(cursorValue.empty());
    BOOST_CHECK(cursorFailureView->Failed());
    BOOST_CHECK(cursorFailureView->OrderValid());
    cursor.reset();

    batch.reset();
    database.reset();
    RemoveSQLiteTestFiles(filename);
}

BOOST_AUTO_TEST_CASE(sqlite_indeterminate_executor_exception_poison)
{
    ShutdownRequestReset shutdownReset;
    BOOST_REQUIRE(!ShutdownRequested());
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
    BOOST_CHECK(!batch->TxnAbort());
    BOOST_CHECK(ShutdownRequested());
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

BOOST_AUTO_TEST_CASE(sqlite_commit_outcomes_are_classified)
{
    {
        ShutdownRequestReset shutdownReset;
        BOOST_REQUIRE(!ShutdownRequested());
        const std::string filename{"sqlite_recoverable_commit_error.dat"};
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
            std::make_unique<BlockingSQLiteStatementExecutor>(
                std::set<std::string>{"COMMIT TRANSACTION"})));
        BOOST_REQUIRE(batch->TxnBegin());
        BOOST_REQUIRE(batch->Write(
            std::string("recoverable-commit"),
            std::string("rolled-back")));
        BOOST_CHECK(!batch->TxnCommit());
        BOOST_CHECK(batch->HasActiveTxn());
        BOOST_REQUIRE(batch->TxnAbort());
        BOOST_CHECK(!batch->HasActiveTxn());
        BOOST_CHECK(!ShutdownRequested());
        BOOST_CHECK(!batch->Exists(std::string("recoverable-commit")));
        batch.reset();
        database.reset();
        RemoveSQLiteTestFiles(filename);
    }

    {
        ShutdownRequestReset shutdownReset;
        BOOST_REQUIRE(!ShutdownRequested());
        const std::string filename{"sqlite_applied_commit_error.dat"};
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
            std::make_unique<CommitThenFailSQLiteStatementExecutor>()));
        BOOST_REQUIRE(batch->TxnBegin());
        BOOST_REQUIRE(batch->Write(
            std::string("applied-commit"),
            std::string("durable-before-error")));
        BOOST_CHECK(!batch->TxnCommit());
        BOOST_CHECK(!batch->HasActiveTxn());
        BOOST_CHECK(!batch->TxnAbort());
        BOOST_CHECK(ShutdownRequested());
        BOOST_CHECK(!batch->Write(
            std::string("after-applied-commit"),
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
        BOOST_REQUIRE(batch->Read(
            std::string("applied-commit"),
            value));
        BOOST_CHECK_EQUAL(value, "durable-before-error");
        BOOST_CHECK(!batch->Exists(
            std::string("after-applied-commit")));
        batch.reset();
        database.reset();
        RemoveSQLiteTestFiles(filename);
    }
}

BOOST_AUTO_TEST_CASE(sqlite_single_write_outcomes_are_classified)
{
    {
        ShutdownRequestReset shutdownReset;
        BOOST_REQUIRE(!ShutdownRequested());
        const std::string filename{"sqlite_statement_auto_rollback.dat"};
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
            std::make_unique<RollbackWriteSQLiteStatementExecutor>()));
        BOOST_CHECK(!batch->Write(
            std::string("auto-rolled-back"),
            std::string("not-applied")));
        BOOST_CHECK(!batch->HasActiveTxn());
        BOOST_CHECK(!ShutdownRequested());
        BOOST_CHECK(!batch->Exists(std::string("auto-rolled-back")));
        BOOST_REQUIRE(batch->Write(
            std::string("auto-rolled-back"),
            std::string("retry-succeeded")));
        batch.reset();
        database.reset();
        RemoveSQLiteTestFiles(filename);
    }

    {
        ShutdownRequestReset shutdownReset;
        BOOST_REQUIRE(!ShutdownRequested());
        const std::string filename{"sqlite_single_write_commit_error.dat"};
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
            std::make_unique<BlockingSQLiteStatementExecutor>(
                std::set<std::string>{"COMMIT TRANSACTION"})));
        BOOST_CHECK(!batch->Write(
            std::string("recoverable-write"),
            std::string("rolled-back")));
        BOOST_CHECK(!batch->HasActiveTxn());
        BOOST_CHECK(!ShutdownRequested());
        BOOST_CHECK(!batch->Exists(std::string("recoverable-write")));
        BOOST_REQUIRE(SetSQLiteStatementExecutorForTesting(
            *batch,
            std::make_unique<SQLiteStatementExecutor>()));
        BOOST_REQUIRE(batch->Write(
            std::string("recoverable-write"),
            std::string("retry-succeeded")));
        batch.reset();
        database.reset();
        RemoveSQLiteTestFiles(filename);
    }

    const auto checkAppliedFailure = [](bool erase) {
        ShutdownRequestReset shutdownReset;
        BOOST_REQUIRE(!ShutdownRequested());
        const std::string filename =
            erase ?
                "sqlite_applied_erase_error.dat" :
                "sqlite_applied_write_error.dat";
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
        if (erase) {
            BOOST_REQUIRE(batch->Write(
                std::string("applied-operation"),
                std::string("erase-me")));
        }
        BOOST_REQUIRE(SetSQLiteStatementExecutorForTesting(
            *batch,
            std::make_unique<CommitThenFailSQLiteStatementExecutor>()));

        if (erase) {
            BOOST_CHECK_THROW(
                batch->Erase(std::string("applied-operation")),
                std::runtime_error);
        } else {
            BOOST_CHECK_THROW(
                batch->Write(
                    std::string("applied-operation"),
                    std::string("durable-before-error")),
                std::runtime_error);
        }
        BOOST_CHECK(ShutdownRequested());
        BOOST_CHECK(!batch->HasActiveTxn());
        BOOST_CHECK(!batch->TxnAbort());
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
        if (erase) {
            BOOST_CHECK(!batch->Exists(
                std::string("applied-operation")));
        } else {
            BOOST_REQUIRE(batch->Read(
                std::string("applied-operation"),
                value));
            BOOST_CHECK_EQUAL(value, "durable-before-error");
        }
        batch.reset();
        database.reset();
        RemoveSQLiteTestFiles(filename);
    };

    checkAppliedFailure(false);
    checkAppliedFailure(true);
}

BOOST_AUTO_TEST_CASE(sqlite_rewrite_commit_error_is_indeterminate)
{
    ShutdownRequestReset shutdownReset;
    BOOST_REQUIRE(!ShutdownRequested());
    const std::string filename{"sqlite_rewrite_commit_error.dat"};
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
    BOOST_REQUIRE(batch->Write(
        std::make_pair(std::string("pool"), int64_t{1}),
        std::string("remove-during-rewrite")));
    BOOST_REQUIRE(batch->Write(
        std::string("retained"),
        std::string("unchanged")));
    batch.reset();

    const std::string poolPrefix{"\x04pool", 5};
    InjectSQLiteRewriteCommitFailureForTesting();
    BOOST_CHECK(!database->Rewrite(poolPrefix.c_str()));
    BOOST_CHECK(ShutdownRequested());
    BOOST_CHECK_THROW(database->MakeBatch(), std::runtime_error);
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
    BOOST_CHECK(!batch->Exists(
        std::make_pair(std::string("pool"), int64_t{1})));
    BOOST_REQUIRE(batch->Read(std::string("retained"), value));
    BOOST_CHECK_EQUAL(value, "unchanged");
    batch.reset();
    database.reset();
    RemoveSQLiteTestFiles(filename);
}

BOOST_AUTO_TEST_CASE(sqlite_post_publish_failure_cleanup)
{
    ShutdownRequestReset shutdownReset;
    BOOST_REQUIRE(!ShutdownRequested());
    const std::string syncCreateFilename{
        "sqlite_failed_directory_sync_create.dat"};
    const std::string createFilename{
        "sqlite_failed_publication_create.dat"};
    const std::string ambiguousFilename{
        "sqlite_ambiguous_publication_create.dat"};
    const std::string sourceFilename{
        "sqlite_failed_publication_source.dat"};
    const std::string syncBackupFilename{
        "sqlite_failed_directory_sync_backup.dat"};
    const std::string backupFilename{
        "sqlite_failed_publication_backup.dat"};
    const std::string indeterminateBackupFilename{
        "sqlite_indeterminate_directory_sync_backup.dat"};
    const std::string indeterminateFilename{
        "sqlite_indeterminate_directory_sync_create.dat"};
    for (const std::string& filename : {
             syncCreateFilename,
             createFilename,
             ambiguousFilename,
             sourceFilename,
             syncBackupFilename,
             backupFilename,
             indeterminateBackupFilename,
             indeterminateFilename}) {
        RemoveSQLiteTestFiles(filename);
        RemoveSQLiteTestCandidates(filename);
    }

    DatabaseOptions createOptions;
    createOptions.require_create = true;
    createOptions.require_format = DatabaseFormat::SQLITE;
    DatabaseOptions defaultCreateOptions;
    defaultCreateOptions.require_create = true;
    DatabaseStatus status = DatabaseStatus::SUCCESS;
    std::string error{"unchanged"};

    InjectSQLiteDirectorySyncFailureForTesting(EINVAL);
    std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(
        syncCreateFilename,
        defaultCreateOptions,
        status,
        error);
    BOOST_CHECK(!database);
    BOOST_CHECK(status == DatabaseStatus::FAILED_LOAD);
    BOOST_CHECK(
        error.find(syncCreateFilename) !=
        std::string::npos);
    BOOST_CHECK(
        error.find("not proven durable") !=
        std::string::npos);
    BOOST_CHECK(!fs::exists(
        GetDataDir() / syncCreateFilename));
    BOOST_CHECK(!HasSQLiteTestCandidate(
        syncCreateFilename));
    BOOST_CHECK(!ShutdownRequested());

    InjectSQLitePostPublishFailureForTesting();
    database = MakeSQLiteDatabase(
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
    BOOST_CHECK(
        error.find(
            (GetDataDir() /
                ambiguousFilename)
                .string()) !=
        std::string::npos);
    BOOST_CHECK(
        error.find(
            "." + ambiguousFilename +
            ".sqlite-") !=
        std::string::npos);
    BOOST_CHECK(
        error.find("neither retained path identity") !=
        std::string::npos);
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

    InjectSQLiteDirectorySyncFailureForTesting(ENOTSUP);
    std::string backupError{"unchanged"};
    BOOST_CHECK(!database->Backup(
        (GetDataDir() / syncBackupFilename).string(),
        backupError));
    BOOST_CHECK(
        backupError.find(sourceFilename) !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find(syncBackupFilename) !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find("not proven durable") !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find("preserved") ==
        std::string::npos);
    BOOST_CHECK(!fs::exists(
        GetDataDir() / syncBackupFilename));
    BOOST_CHECK(!HasSQLiteTestCandidate(
        syncBackupFilename));
    BOOST_CHECK(!ShutdownRequested());
    batch = database->MakeBatch();
    BOOST_REQUIRE(batch);
    std::string value;
    BOOST_CHECK(batch->Read(
        std::string("source"),
        value));
    BOOST_CHECK_EQUAL(value, "preserved");
    batch.reset();

    InjectSQLitePostPublishFailureForTesting();
    backupError = "unchanged";
    BOOST_CHECK(!database->Backup(
        (GetDataDir() / backupFilename).string(),
        backupError));
    BOOST_CHECK(
        backupError.find(
            "Injected failure after publishing SQLite backup candidate") !=
        std::string::npos);
    BOOST_CHECK(!backupError.empty());
    BOOST_CHECK_NE(backupError, "unchanged");
    BOOST_CHECK(
        backupError.find(sourceFilename) !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find(backupFilename) !=
        std::string::npos);
    BOOST_CHECK(!fs::exists(GetDataDir() / backupFilename));
    BOOST_CHECK(!fs::exists(
        (GetDataDir() / backupFilename).string() + "-journal"));
    BOOST_CHECK(!HasSQLiteTestCandidate(backupFilename));
    batch = database->MakeBatch();
    BOOST_REQUIRE(batch);
    BOOST_CHECK(batch->Read(std::string("source"), value));
    BOOST_CHECK_EQUAL(value, "preserved");
    batch.reset();

    InjectSQLiteAmbiguousPublishFailureForTesting();
    InjectSQLiteDirectorySyncFailureForTesting(EIO);
    backupError = "unchanged";
    BOOST_CHECK(!database->Backup(
        (GetDataDir() /
            indeterminateBackupFilename)
            .string(),
        backupError));
    BOOST_CHECK(
        backupError.find(sourceFilename) !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find(
            (GetDataDir() /
                indeterminateBackupFilename)
                .string()) !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find(
            "." + indeterminateBackupFilename +
            ".sqlite-") !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find("may reappear after a crash") !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find(
            "either that final path or its prior owned candidate path") !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find("all reported artifacts") !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find("restart Firo") !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find("preserved") ==
        std::string::npos);
    BOOST_CHECK(!fs::exists(
        GetDataDir() /
        indeterminateBackupFilename));
    BOOST_CHECK(!HasSQLiteTestCandidate(
        indeterminateBackupFilename));
    BOOST_CHECK(!ShutdownRequested());
    batch = database->MakeBatch();
    BOOST_REQUIRE(batch);
    BOOST_CHECK(batch->Read(
        std::string("source"),
        value));
    BOOST_CHECK_EQUAL(value, "preserved");
    batch.reset();
    database.reset();

    InjectSQLitePostPublishFailureForTesting();
    InjectSQLiteDirectorySyncFailureForTesting(EIO, 1);
    status = DatabaseStatus::SUCCESS;
    error = "unchanged";
    database = MakeWalletDatabase(
        indeterminateFilename,
        defaultCreateOptions,
        status,
        error);
    BOOST_CHECK(!database);
    BOOST_CHECK(status == DatabaseStatus::FAILED_LOAD);
    BOOST_CHECK(
        error.find(indeterminateFilename) !=
        std::string::npos);
    BOOST_CHECK(
        error.find("may reappear after a crash") !=
        std::string::npos);
    BOOST_CHECK(
        error.find("restart Firo") !=
        std::string::npos);
    BOOST_CHECK(
        error.find("preserved") ==
        std::string::npos);
    BOOST_CHECK(!fs::exists(
        GetDataDir() / indeterminateFilename));
    BOOST_CHECK(!HasSQLiteTestCandidate(
        indeterminateFilename));
    BOOST_CHECK(ShutdownRequested());

    for (const std::string& filename : {
             syncCreateFilename,
             createFilename,
             ambiguousFilename,
             sourceFilename,
             syncBackupFilename,
             backupFilename,
             indeterminateBackupFilename,
             indeterminateFilename}) {
        RemoveSQLiteTestFiles(filename);
        RemoveSQLiteTestCandidates(filename);
    }
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
    const std::string collisionBackupFilename{
        "sqlite_failed_collision_cleanup_backup.dat"};
    for (const std::string& filename : {
             prePublishFilename,
             postPublishFilename,
             sourceFilename,
             backupFilename,
             collisionBackupFilename}) {
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

    const std::set<std::string> entriesBeforeInjectedFailure =
        SQLiteTestDirectoryEntries();
    InjectSQLiteBackupCollisionCleanupFailureForTesting();
    std::string collisionError{"unchanged"};
    BOOST_CHECK(!database->Backup(
        (GetDataDir() / collisionBackupFilename).string(),
        collisionError));
    BOOST_CHECK(
        collisionError.find(sourceFilename) !=
        std::string::npos);
    BOOST_CHECK(
        collisionError.find(collisionBackupFilename) !=
        std::string::npos);
    BOOST_CHECK(
        collisionError.find("appeared concurrently") !=
        std::string::npos);
    BOOST_CHECK(
        collisionError.find("could not prove cleanup of owned backup candidate") !=
        std::string::npos);
    BOOST_CHECK(
        collisionError.find("restart Firo") !=
        std::string::npos);
    BOOST_CHECK(
        collisionError.find("all reported artifacts") !=
        std::string::npos);
    BOOST_CHECK(
        collisionError.find("preserved") ==
        std::string::npos);
    BOOST_CHECK(!fs::exists(
        GetDataDir() / collisionBackupFilename));
    const std::set<std::string> entriesAfterInjectedFailure =
        SQLiteTestDirectoryEntries();
    std::vector<std::string> retainedEntries;
    for (const std::string& entry :
        entriesAfterInjectedFailure) {
        if (entriesBeforeInjectedFailure.count(entry) == 0) {
            retainedEntries.push_back(entry);
        }
    }
    BOOST_REQUIRE_EQUAL(retainedEntries.size(), 1U);
    const fs::path retainedPath =
        GetDataDir() / retainedEntries.front();
    BOOST_CHECK(fs::is_regular_file(retainedPath));
    BOOST_CHECK(
        collisionError.find(retainedPath.string()) !=
        std::string::npos);
    BOOST_CHECK(fs::remove(retainedPath));

    InjectSQLiteCloseFailureForTesting(1);
    std::string backupError{"unchanged"};
    BOOST_CHECK(!database->Backup(
        (GetDataDir() / backupFilename).string(),
        backupError));
    BOOST_CHECK(
        backupError.find(sourceFilename) !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find(backupFilename) !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find("could not prove cleanup of candidate") !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find("restart Firo") !=
        std::string::npos);
    BOOST_CHECK(
        backupError.find("preserved") ==
        std::string::npos);
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
             backupFilename,
             collisionBackupFilename}) {
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

#if (defined(__linux__) && defined(SYS_renameat2)) || defined(__APPLE__)
BOOST_AUTO_TEST_CASE(sqlite_primary_key_index_logical_recovery)
{
    struct MockTimeReset {
        ~MockTimeReset() { SetMockTime(0); }
    } mockTimeReset;

    constexpr int64_t RECOVERY_TIME = 1900000100;
    SetMockTime(RECOVERY_TIME);

    const std::string filename{
        "sqlite_primary_key_index_recovery.dat"};
    const std::string backupFilename =
        strprintf("wallet.%d.bak", RECOVERY_TIME);
    const fs::path path = GetDataDir() / filename;
    const fs::path backupPath =
        GetDataDir() / backupFilename;
    RemoveSQLiteTestFiles(filename);
    RemoveSQLiteTestFiles(backupFilename);
    RemoveSQLiteTestCandidates(filename);
    RemoveSQLiteTestCandidates(backupFilename);

    std::vector<RawRecord> expectedRecords;
    for (uint32_t i = 0; i < 64; ++i) {
        expectedRecords.emplace_back(
            SerializeToString(
                std::make_pair(
                    std::string("phase4d-row"),
                    i)),
            SerializeToString(
                std::string(
                    96,
                    static_cast<char>(
                        'A' + (i % 26)))));
    }
    const RawRecord embeddedUnknown{
        SerializeToString(
            std::make_pair(
                std::string("phase4d-unknown"),
                std::string(
                    "unknown\0key",
                    11))),
        SerializeToString(
            std::string(
                "value\0payload",
                13)),
    };
    expectedRecords.push_back(embeddedUnknown);
    const RawRecord emptyValueRecord{
        SerializeToString(
            std::string(
                "phase4d-empty-value")),
        {},
    };
    expectedRecords.push_back(emptyValueRecord);
    std::sort(
        expectedRecords.begin(),
        expectedRecords.end());

    DatabaseStatus status =
        DatabaseStatus::FAILED_LOAD;
    std::string error{"unchanged"};
    std::unique_ptr<WalletDatabase> database =
        CreateSQLiteTestDatabaseFromRawRecords(
            filename,
            expectedRecords,
            status,
            error);
    BOOST_REQUIRE_MESSAGE(database, error);
    BOOST_REQUIRE(
        status == DatabaseStatus::SUCCESS);
    BOOST_REQUIRE(database->PeriodicFlush());
    database.reset();

    const std::optional<std::vector<RawRecord> >
        storedRecords =
            ReadRawSQLiteRecordsNotIndexed(path);
    BOOST_REQUIRE(storedRecords);
    BOOST_CHECK_MESSAGE(
        *storedRecords == expectedRecords,
        "The recovery fixture changed raw rows");
    BOOST_REQUIRE_MESSAGE(
        std::find(
            storedRecords->begin(),
            storedRecords->end(),
            embeddedUnknown) !=
            storedRecords->end(),
        "The embedded-NUL unknown record was not stored");
    BOOST_REQUIRE_MESSAGE(
        std::find(
            storedRecords->begin(),
            storedRecords->end(),
            emptyValueRecord) !=
            storedRecords->end(),
        "The empty-value record was not stored");

    BOOST_REQUIRE(
        CorruptSQLitePrimaryKeyIndex(path));
    const std::optional<std::vector<RawRecord> >
        corruptTableRecords =
            ReadRawSQLiteRecordsNotIndexed(path);
    BOOST_REQUIRE_MESSAGE(
        corruptTableRecords,
        "The table became unreadable after index-only corruption");
    BOOST_CHECK_MESSAGE(
        *corruptTableRecords == expectedRecords,
        "The index-only corruption changed raw table rows");
    const std::string corruptContents =
        ReadFile(path);

    DatabaseOptions existingOptions;
    existingOptions.require_existing = true;
    existingOptions.require_format =
        DatabaseFormat::SQLITE;
    existingOptions.recover = false;
    status = DatabaseStatus::SUCCESS;
    error = "unchanged";
    database = MakeSQLiteDatabase(
        filename,
        existingOptions,
        status,
        error);
    BOOST_CHECK(!database);
    BOOST_CHECK(
        status == DatabaseStatus::FAILED_VERIFY);
    BOOST_CHECK(!error.empty());
    BOOST_CHECK_NE(error, "unchanged");
    BOOST_CHECK_MESSAGE(
        ReadFile(path) == corruptContents,
        "Verification without recovery changed the source");
    BOOST_CHECK(!fs::exists(backupPath));
    BOOST_CHECK(!HasSQLiteTestCandidate(filename));
    BOOST_CHECK(
        !HasSQLiteTestCandidate(backupFilename));

    existingOptions.recover = true;
    status = DatabaseStatus::FAILED_LOAD;
    error = "unchanged";
    database = MakeSQLiteDatabase(
        filename,
        existingOptions,
        status,
        error);
    BOOST_REQUIRE_MESSAGE(database, error);
    BOOST_CHECK(
        status ==
        DatabaseStatus::SUCCESS_RECOVERED);
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(
        database->RecoveryBackupPath(),
        backupPath.string());
    {
        std::unique_ptr<DatabaseBatch> batch =
            database->MakeBatch(
                {DatabaseBatchMode::READ_ONLY});
        BOOST_REQUIRE(batch);
        std::vector<RawRecord> recoveredRecords =
            ReadRawRecords(*batch);
        std::sort(
            recoveredRecords.begin(),
            recoveredRecords.end());
        BOOST_CHECK_MESSAGE(
            recoveredRecords == expectedRecords,
            "Logical recovery did not preserve every raw row");
    }
    BOOST_CHECK_MESSAGE(
        ReadFile(backupPath) == corruptContents,
        "The recovery backup is not an exact source copy");
    BOOST_CHECK_MESSAGE(
        ReadFile(path) != corruptContents,
        "Recovery did not replace the corrupt source");
    BOOST_CHECK(!HasSQLiteTestCandidate(filename));
    BOOST_CHECK(
        !HasSQLiteTestCandidate(backupFilename));

    struct stat sourceMetadata{};
    struct stat backupMetadata{};
    BOOST_REQUIRE_EQUAL(
        lstat(path.string().c_str(), &sourceMetadata),
        0);
    BOOST_REQUIRE_EQUAL(
        lstat(
            backupPath.string().c_str(),
            &backupMetadata),
        0);
    BOOST_CHECK(S_ISREG(backupMetadata.st_mode));
    BOOST_CHECK_EQUAL(
        backupMetadata.st_nlink,
        1);
    BOOST_CHECK_EQUAL(
        backupMetadata.st_uid,
        geteuid());
    BOOST_CHECK_EQUAL(
        backupMetadata.st_mode & 0777,
        S_IRUSR | S_IWUSR);
    BOOST_CHECK(
        sourceMetadata.st_dev !=
            backupMetadata.st_dev ||
        sourceMetadata.st_ino !=
            backupMetadata.st_ino);

    BOOST_REQUIRE(database->PeriodicFlush());
    database.reset();

    existingOptions.recover = false;
    status = DatabaseStatus::FAILED_LOAD;
    error = "unchanged";
    database = MakeSQLiteDatabase(
        filename,
        existingOptions,
        status,
        error);
    BOOST_REQUIRE_MESSAGE(database, error);
    BOOST_CHECK(
        status == DatabaseStatus::SUCCESS);
    BOOST_CHECK(error.empty());
    {
        std::unique_ptr<DatabaseBatch> batch =
            database->MakeBatch(
                {DatabaseBatchMode::READ_ONLY});
        BOOST_REQUIRE(batch);
        std::vector<RawRecord> reopenedRecords =
            ReadRawRecords(*batch);
        std::sort(
            reopenedRecords.begin(),
            reopenedRecords.end());
        BOOST_CHECK_MESSAGE(
            reopenedRecords == expectedRecords,
            "Normally reopened recovery rows changed");
    }
    BOOST_REQUIRE(database->PeriodicFlush());
    database.reset();

    RemoveSQLiteTestFiles(filename);
    RemoveSQLiteTestFiles(backupFilename);
    RemoveSQLiteTestCandidates(filename);
    RemoveSQLiteTestCandidates(backupFilename);
}

BOOST_AUTO_TEST_CASE(sqlite_key_only_salvage_exact_records)
{
    struct MockTimeReset {
        ~MockTimeReset() { SetMockTime(0); }
    } mockTimeReset;

    constexpr int64_t PLAIN_SALVAGE_TIME = 1900000200;
    constexpr int64_t ENCRYPTED_SALVAGE_TIME = 1900000201;
    constexpr int64_t MIXED_SALVAGE_TIME = 1900000202;
    constexpr unsigned int MASTER_KEY_ID = 7;

    CKey plainKey;
    plainKey.MakeNewKey(true);
    const CPubKey plainPublicKey =
        plainKey.GetPubKey();

    CKey legacyKey;
    legacyKey.MakeNewKey(true);
    const CPubKey legacyPublicKey =
        legacyKey.GetPubKey();
    CWalletKey legacyWalletKey;
    legacyWalletKey.vchPrivKey =
        legacyKey.GetPrivKey();
    legacyWalletKey.nTimeCreated =
        PLAIN_SALVAGE_TIME - 2;
    legacyWalletKey.nTimeExpires = 0;
    legacyWalletKey.strComment =
        "phase4d-salvage-wkey";

    CKey cryptedKey;
    cryptedKey.MakeNewKey(true);
    const CPubKey cryptedPublicKey =
        cryptedKey.GetPubKey();
    const std::vector<unsigned char> cryptedSecret(
        48,
        0x42);

    CMasterKey masterKey;
    masterKey.vchCryptedKey.assign(
        48,
        0x24);
    masterKey.vchSalt.assign(
        8,
        0x18);
    masterKey.nDerivationMethod = 0;
    masterKey.nDeriveIterations = 25000;
    masterKey.vchOtherDerivationParameters = {
        0x00,
        0x7f,
        0xff,
    };

    CHDChain hdChain;
    hdChain.masterKeyID =
        plainPublicKey.GetID();
    hdChain.nExternalChainCounter = 11;
    for (size_t i = 0;
        i < hdChain.nExternalChainCounters.size();
        ++i) {
        hdChain.nExternalChainCounters[i] =
            static_cast<uint32_t>(20 + i);
    }

    const std::set<std::string> allAllowedTypes{
        "key",
        "wkey",
        "mkey",
        "ckey",
        "hdchain",
    };

    DatabaseOptions salvageOptions;
    salvageOptions.require_existing = true;
    salvageOptions.require_format =
        DatabaseFormat::SQLITE;
    salvageOptions.salvage = true;

    enum class SalvageKind {
        PLAIN,
        ENCRYPTED,
        MIXED,
    };
    struct SalvageCase {
        const char* filename;
        int64_t recovery_time;
        SalvageKind kind;
        std::set<std::string> expected_types;
    };
    const std::array<SalvageCase, 3> cases{{
        {
            "sqlite_key_only_salvage_plain.dat",
            PLAIN_SALVAGE_TIME,
            SalvageKind::PLAIN,
            {"key", "wkey", "hdchain"},
        },
        {
            "sqlite_key_only_salvage_encrypted.dat",
            ENCRYPTED_SALVAGE_TIME,
            SalvageKind::ENCRYPTED,
            {"mkey", "ckey"},
        },
        {
            "sqlite_key_only_salvage_mixed.dat",
            MIXED_SALVAGE_TIME,
            SalvageKind::MIXED,
            {"key"},
        },
    }};

    for (const SalvageCase& test : cases) {
        SetMockTime(test.recovery_time);
        const std::string filename{test.filename};
        const std::string backupFilename =
            strprintf(
                "wallet.%d.bak",
                test.recovery_time);
        const fs::path path =
            GetDataDir() / filename;
        const fs::path backupPath =
            GetDataDir() / backupFilename;
        RemoveSQLiteTestFiles(filename);
        RemoveSQLiteTestFiles(backupFilename);
        RemoveSQLiteTestCandidates(filename);
        RemoveSQLiteTestCandidates(backupFilename);

        DatabaseOptions createOptions;
        createOptions.require_create = true;
        createOptions.require_format =
            DatabaseFormat::SQLITE;
        DatabaseStatus status =
            DatabaseStatus::FAILED_LOAD;
        std::string error{"unchanged"};
        std::unique_ptr<WalletDatabase> database =
            MakeSQLiteDatabase(
                filename,
                createOptions,
                status,
                error);
        BOOST_REQUIRE_MESSAGE(database, error);
        BOOST_REQUIRE(
            status == DatabaseStatus::SUCCESS);
        {
            CWalletDB writer(*database);
            if (test.kind ==
                SalvageKind::ENCRYPTED) {
                BOOST_REQUIRE(
                    writer.WriteMasterKey(
                        MASTER_KEY_ID,
                        masterKey));
                BOOST_REQUIRE(
                    writer.WriteCryptedKey(
                        cryptedPublicKey,
                        cryptedSecret,
                        CKeyMetadata(
                            test.recovery_time - 1)));
            } else {
                BOOST_REQUIRE(
                    writer.WriteKey(
                        plainPublicKey,
                        plainKey.GetPrivKey(),
                        CKeyMetadata(
                            test.recovery_time - 3)));
                if (test.kind ==
                    SalvageKind::PLAIN) {
                    BOOST_REQUIRE(
                        writer.WriteHDChain(
                            hdChain));
                } else {
                    BOOST_REQUIRE(
                        writer.WriteCryptedKey(
                            cryptedPublicKey,
                            cryptedSecret,
                            CKeyMetadata(
                                test.recovery_time - 1)));
                }
            }
        }
        {
            std::unique_ptr<DatabaseBatch> batch =
                database->MakeBatch();
            BOOST_REQUIRE(batch);
            BOOST_REQUIRE(batch->TxnBegin());
            if (test.kind ==
                SalvageKind::PLAIN) {
                BOOST_REQUIRE(
                    batch->Write(
                        std::make_pair(
                            std::string("wkey"),
                            legacyPublicKey),
                        legacyWalletKey,
                        false));
            }
            BOOST_REQUIRE(
                batch->Write(
                    std::make_pair(
                        std::string(
                            "phase4d-opaque"),
                        std::string(
                            "opaque\0key",
                            10)),
                    std::string(
                        "opaque\0value",
                        12),
                    false));
            BOOST_REQUIRE(batch->TxnCommit());
        }
        BOOST_REQUIRE(database->PeriodicFlush());
        database.reset();

        const std::optional<std::vector<RawRecord> >
            sourceRecords =
                ReadRawSQLiteRecordsNotIndexed(path);
        BOOST_REQUIRE(sourceRecords);
        WalletKeyOnlyRecordValidator validator;
        std::map<std::string, size_t> allowedCounts;
        std::vector<RawRecord> expectedRecords;
        size_t keyMetadataRecords = 0;
        size_t opaqueRecords = 0;
        for (const RawRecord& record : *sourceRecords) {
            const std::optional<std::string> type =
                RawRecordType(record);
            BOOST_REQUIRE_MESSAGE(
                type,
                "A salvage source record had no decodable type");
            if (allAllowedTypes.count(*type) != 0) {
                CDataStream key(
                    record.first.data(),
                    record.first.data() +
                        record.first.size(),
                    SER_DISK,
                    CLIENT_VERSION);
                CDataStream value(
                    record.second.data(),
                    record.second.data() +
                        record.second.size(),
                    SER_DISK,
                    CLIENT_VERSION);
                const bool valid =
                    validator.IsValid(key, value);
                if (test.expected_types.count(
                        *type) != 0) {
                    BOOST_REQUIRE_MESSAGE(
                        valid,
                        "Expected salvage type " << *type
                                                 << " was not valid in " << filename);
                    ++allowedCounts[*type];
                    expectedRecords.push_back(record);
                } else {
                    BOOST_CHECK_MESSAGE(
                        !valid,
                        "Incompatible salvage type " << *type
                                                     << " was retained in " << filename);
                }
            } else if (*type == "keymeta") {
                ++keyMetadataRecords;
            } else if (*type == "phase4d-opaque") {
                ++opaqueRecords;
            }
        }
        BOOST_REQUIRE_EQUAL(
            expectedRecords.size(),
            test.expected_types.size());
        for (const std::string& type :
            test.expected_types) {
            const auto count =
                allowedCounts.find(type);
            BOOST_REQUIRE(
                count != allowedCounts.end());
            BOOST_CHECK_EQUAL(count->second, 1U);
        }
        BOOST_CHECK_EQUAL(
            keyMetadataRecords,
            test.kind == SalvageKind::MIXED ?
                2U :
                1U);
        BOOST_CHECK_EQUAL(opaqueRecords, 1U);
        std::sort(
            expectedRecords.begin(),
            expectedRecords.end());
        const std::string sourceContents =
            ReadFile(path);

        status = DatabaseStatus::FAILED_LOAD;
        error = "unchanged";
        database = MakeSQLiteDatabase(
            filename,
            salvageOptions,
            status,
            error);
        BOOST_REQUIRE_MESSAGE(database, error);
        BOOST_CHECK(
            status ==
            DatabaseStatus::SUCCESS_SALVAGED);
        BOOST_CHECK(error.empty());
        BOOST_CHECK_EQUAL(
            database->RecoveryBackupPath(),
            backupPath.string());

        std::vector<RawRecord> salvagedRecords;
        {
            std::unique_ptr<DatabaseBatch> batch =
                database->MakeBatch(
                    {DatabaseBatchMode::READ_ONLY});
            BOOST_REQUIRE(batch);
            salvagedRecords =
                ReadRawRecords(*batch);
        }
        std::sort(
            salvagedRecords.begin(),
            salvagedRecords.end());
        BOOST_CHECK_MESSAGE(
            salvagedRecords == expectedRecords,
            "Key-only salvage changed or retained unexpected raw rows");
        BOOST_CHECK_MESSAGE(
            ReadFile(backupPath) == sourceContents,
            "The salvage backup is not an exact source copy");
        BOOST_CHECK(!HasSQLiteTestCandidate(filename));
        BOOST_CHECK(
            !HasSQLiteTestCandidate(backupFilename));

        CWallet wallet(std::move(database));
        {
            CWalletDB loader(
                wallet.GetDatabase(),
                {DatabaseBatchMode::READ_ONLY});
            BOOST_REQUIRE(
                loader.LoadWallet(
                    &wallet,
                    false) == DB_LOAD_OK);
        }
        if (test.kind ==
            SalvageKind::ENCRYPTED) {
            BOOST_CHECK(wallet.IsCrypted());
            BOOST_CHECK(
                wallet.HaveKey(
                    cryptedPublicKey.GetID()));
            LOCK(wallet.cs_wallet);
            BOOST_CHECK_EQUAL(
                wallet.mapMasterKeys.count(
                    MASTER_KEY_ID),
                1U);
        } else {
            BOOST_CHECK(!wallet.IsCrypted());
            BOOST_CHECK(
                wallet.HaveKey(
                    plainPublicKey.GetID()));
            if (test.kind ==
                SalvageKind::PLAIN) {
                BOOST_CHECK(
                    wallet.HaveKey(
                        legacyPublicKey.GetID()));
                LOCK(wallet.cs_wallet);
                BOOST_CHECK(
                    SameSerializedValue(
                        hdChain,
                        wallet.GetHDChain()));
            } else {
                BOOST_CHECK(
                    !wallet.HaveKey(
                        cryptedPublicKey.GetID()));
            }
        }
        BOOST_REQUIRE(
            wallet.GetDatabase().PeriodicFlush());

        RemoveSQLiteTestFiles(filename);
        RemoveSQLiteTestFiles(backupFilename);
        RemoveSQLiteTestCandidates(filename);
        RemoveSQLiteTestCandidates(backupFilename);
    }
}

BOOST_AUTO_TEST_CASE(sqlite_key_only_salvage_rejects_storage_violations)
{
    struct MockTimeReset {
        ~MockTimeReset() { SetMockTime(0); }
    } mockTimeReset;

    struct RejectionCase {
        const char* filename;
        int64_t recovery_time;
        const char* statement;
        const char* expected_error;
    };
    static constexpr std::array<RejectionCase, 2> CASES{{
        {
            "sqlite_salvage_non_blob.dat",
            1900000220,
            "INSERT INTO main(key, value) "
            "VALUES('text-key', 'text-value')",
            "canonical BLOB domain",
        },
        {
            "sqlite_salvage_empty_key.dat",
            1900000221,
            "INSERT INTO main(key, value) "
            "VALUES(X'', X'01')",
            "empty-key creation metadata",
        },
    }};

    CKey key;
    key.MakeNewKey(true);
    const CPubKey publicKey = key.GetPubKey();

    for (const RejectionCase& test : CASES) {
        SetMockTime(test.recovery_time);
        const std::string filename{test.filename};
        const std::string backupFilename =
            strprintf(
                "wallet.%d.bak",
                test.recovery_time);
        const fs::path path =
            GetDataDir() / filename;
        const fs::path backupPath =
            GetDataDir() / backupFilename;
        RemoveSQLiteTestFiles(filename);
        RemoveSQLiteTestFiles(backupFilename);
        RemoveSQLiteTestCandidates(filename);
        RemoveSQLiteTestCandidates(backupFilename);

        DatabaseOptions createOptions;
        createOptions.require_create = true;
        createOptions.require_format =
            DatabaseFormat::SQLITE;
        DatabaseStatus status =
            DatabaseStatus::FAILED_LOAD;
        std::string error{"unchanged"};
        std::unique_ptr<WalletDatabase> database =
            MakeSQLiteDatabase(
                filename,
                createOptions,
                status,
                error);
        BOOST_REQUIRE_MESSAGE(database, error);
        {
            CWalletDB writer(*database);
            BOOST_REQUIRE(
                writer.WriteKey(
                    publicKey,
                    key.GetPrivKey(),
                    CKeyMetadata(
                        test.recovery_time - 1)));
        }
        BOOST_REQUIRE(database->PeriodicFlush());
        database.reset();
        BOOST_REQUIRE(
            ExecuteRawSQLite(
                path,
                {test.statement}));
        const std::string sourceContents =
            ReadFile(path);

        DatabaseOptions salvageOptions;
        salvageOptions.require_existing = true;
        salvageOptions.require_format =
            DatabaseFormat::SQLITE;
        salvageOptions.salvage = true;
        status = DatabaseStatus::SUCCESS;
        error = "unchanged";
        database = MakeSQLiteDatabase(
            filename,
            salvageOptions,
            status,
            error);
        BOOST_CHECK(!database);
        BOOST_CHECK(
            status ==
            DatabaseStatus::FAILED_VERIFY);
        BOOST_CHECK(
            error.find(test.expected_error) !=
            std::string::npos);
        BOOST_CHECK_MESSAGE(
            ReadFile(path) == sourceContents,
            "Rejected salvage changed its source");
        BOOST_CHECK(!fs::exists(backupPath));
        BOOST_CHECK(!HasSQLiteTestCandidate(filename));
        BOOST_CHECK(
            !HasSQLiteTestCandidate(backupFilename));

        RemoveSQLiteTestFiles(filename);
        RemoveSQLiteTestFiles(backupFilename);
        RemoveSQLiteTestCandidates(filename);
        RemoveSQLiteTestCandidates(backupFilename);
    }
}

BOOST_AUTO_TEST_CASE(sqlite_key_only_salvage_rejects_hot_journal_identity)
{
    struct MockTimeReset {
        ~MockTimeReset() { SetMockTime(0); }
    } mockTimeReset;
    ShutdownRequestReset shutdownReset;

    constexpr int64_t SALVAGE_TIME = 1900000240;
    SetMockTime(SALVAGE_TIME);
    const std::string filename{
        "sqlite_salvage_hot_journal_identity.dat"};
    const std::string backupFilename =
        strprintf(
            "wallet.%d.bak",
            SALVAGE_TIME);
    const fs::path path =
        GetDataDir() / filename;
    const fs::path journalPath =
        path.string() + "-journal";
    const fs::path backupPath =
        GetDataDir() / backupFilename;
    RemoveSQLiteTestFiles(filename);
    RemoveSQLiteTestFiles(backupFilename);
    RemoveSQLiteTestCandidates(filename);
    RemoveSQLiteTestCandidates(backupFilename);

    DatabaseOptions createOptions;
    createOptions.require_create = true;
    createOptions.require_format =
        DatabaseFormat::SQLITE;
    DatabaseStatus status =
        DatabaseStatus::FAILED_LOAD;
    std::string error{"unchanged"};
    std::unique_ptr<WalletDatabase> database =
        MakeSQLiteDatabase(
            filename,
            createOptions,
            status,
            error);
    BOOST_REQUIRE_MESSAGE(database, error);
    CKey key;
    key.MakeNewKey(true);
    {
        CWalletDB writer(*database);
        BOOST_REQUIRE(
            writer.WriteKey(
                key.GetPubKey(),
                key.GetPrivKey(),
                CKeyMetadata(
                    SALVAGE_TIME - 1)));
    }
    BOOST_REQUIRE(database->PeriodicFlush());
    database.reset();

    BOOST_REQUIRE(
        CreateHotJournalRestoringForeignHeader(
            path));
    BOOST_REQUIRE(fs::is_regular_file(journalPath));
    const std::string preflightContents =
        ReadFile(path);
    BOOST_REQUIRE(
        preflightContents.size() >= 72);
    BOOST_CHECK_EQUAL(
        ReadBE32(
            reinterpret_cast<const unsigned char*>(
                preflightContents.data() + 60)),
        0U);
    BOOST_CHECK_EQUAL(
        ReadBE32(
            reinterpret_cast<const unsigned char*>(
                preflightContents.data() + 68)),
        ReadBE32(
            Params().MessageStart()));

    DatabaseOptions salvageOptions;
    salvageOptions.require_existing = true;
    salvageOptions.require_format =
        DatabaseFormat::SQLITE;
    salvageOptions.salvage = true;
    status = DatabaseStatus::SUCCESS;
    error = "unchanged";
    database = MakeSQLiteDatabase(
        filename,
        salvageOptions,
        status,
        error);
    BOOST_CHECK(!database);
    BOOST_CHECK(
        status ==
        DatabaseStatus::FAILED_VERIFY);
    BOOST_CHECK_MESSAGE(
        error.find("application ID 0") !=
            std::string::npos,
        error);
    BOOST_CHECK(!fs::exists(journalPath));
    BOOST_CHECK(!fs::exists(backupPath));
    BOOST_CHECK(!HasSQLiteTestCandidate(filename));
    BOOST_CHECK(
        !HasSQLiteTestCandidate(backupFilename));
    BOOST_CHECK(!fRequestShutdown.load());

    const std::string recoveredContents =
        ReadFile(path);
    BOOST_REQUIRE(
        recoveredContents.size() >= 72);
    BOOST_CHECK_EQUAL(
        ReadBE32(
            reinterpret_cast<const unsigned char*>(
                recoveredContents.data() + 60)),
        1U);
    BOOST_CHECK_EQUAL(
        ReadBE32(
            reinterpret_cast<const unsigned char*>(
                recoveredContents.data() + 68)),
        0U);

    RemoveSQLiteTestFiles(filename);
    RemoveSQLiteTestFiles(backupFilename);
    RemoveSQLiteTestCandidates(filename);
    RemoveSQLiteTestCandidates(backupFilename);
}

BOOST_AUTO_TEST_CASE(sqlite_recovery_backup_ambiguous_publication_is_indeterminate)
{
    struct MockTimeReset {
        ~MockTimeReset() { SetMockTime(0); }
    } mockTimeReset;
    ShutdownRequestReset shutdownReset;

    constexpr int64_t RECOVERY_TIME = 1900000290;
    SetMockTime(RECOVERY_TIME);

    const std::string filename{
        "sqlite_recovery_backup_ambiguous_publication.dat"};
    const std::string backupFilename =
        strprintf("wallet.%d.bak", RECOVERY_TIME);
    const fs::path path = GetDataDir() / filename;
    const fs::path backupPath =
        GetDataDir() / backupFilename;
    RemoveSQLiteTestFiles(filename);
    RemoveSQLiteTestFiles(backupFilename);
    RemoveSQLiteTestCandidates(filename);
    RemoveSQLiteTestCandidates(backupFilename);
    const std::set<std::string> entriesBefore =
        SQLiteTestDirectoryEntries();

    const std::string sensitivePayload(64, 'A');
    std::vector<RawRecord> sourceRecords;
    for (uint32_t i = 0; i < 64; ++i) {
        sourceRecords.emplace_back(
            SerializeToString(
                std::make_pair(
                    std::string(
                        "phase4l-ambiguous-recovery-row"),
                    i)),
            SerializeToString(
                std::string(
                    64,
                    static_cast<char>(
                        'A' + (i % 26)))));
    }
    std::sort(
        sourceRecords.begin(),
        sourceRecords.end());

    DatabaseStatus status =
        DatabaseStatus::FAILED_LOAD;
    std::string error{"unchanged"};
    std::unique_ptr<WalletDatabase> database =
        CreateSQLiteTestDatabaseFromRawRecords(
            filename,
            sourceRecords,
            status,
            error);
    BOOST_REQUIRE_MESSAGE(database, error);
    BOOST_REQUIRE(
        status == DatabaseStatus::SUCCESS);
    BOOST_REQUIRE(database->PeriodicFlush());
    database.reset();

    BOOST_REQUIRE(
        CorruptSQLitePrimaryKeyIndex(path));
    const std::optional<std::vector<RawRecord> >
        readableRecords =
            ReadRawSQLiteRecordsNotIndexed(path);
    BOOST_REQUIRE_MESSAGE(
        readableRecords,
        "The ambiguous-publication recovery source is not readable");
    BOOST_CHECK_MESSAGE(
        *readableRecords == sourceRecords,
        "Index corruption changed ambiguous-publication source rows");
    const std::string sourceContents =
        ReadFile(path);

    DatabaseOptions recoveryOptions;
    recoveryOptions.require_existing = true;
    recoveryOptions.require_format =
        DatabaseFormat::SQLITE;
    recoveryOptions.recover = true;
    InjectSQLiteAmbiguousPublishFailureForTesting();
    status = DatabaseStatus::SUCCESS;
    error = "unchanged";
    database = MakeSQLiteDatabase(
        filename,
        recoveryOptions,
        status,
        error);
    BOOST_CHECK(!database);
    BOOST_CHECK(
        status == DatabaseStatus::FAILED_LOAD);
    BOOST_CHECK(
        error.find(
            "SQLite recovery backup publication from working path") !=
        std::string::npos);
    BOOST_CHECK(
        error.find(
            "neither retained path identity could be proven") !=
        std::string::npos);
    BOOST_CHECK(
        error.find(path.string()) !=
        std::string::npos);
    BOOST_CHECK(
        error.find(backupPath.string()) !=
        std::string::npos);
    BOOST_CHECK(
        error.find(
            "Preserve all paths and restart Firo") !=
        std::string::npos);
    BOOST_CHECK(
        error.find("phase4l-ambiguous-recovery-row") ==
        std::string::npos);
    BOOST_CHECK(
        error.find(sensitivePayload) ==
        std::string::npos);
    BOOST_CHECK(
        error.find(SerializeToString(sensitivePayload)) ==
        std::string::npos);
    BOOST_CHECK(ShutdownRequested());

    BOOST_CHECK_MESSAGE(
        ReadFile(path) == sourceContents,
        "Ambiguous backup publication changed the recovery source");
    BOOST_REQUIRE(fs::is_regular_file(backupPath));
    BOOST_CHECK_MESSAGE(
        ReadFile(backupPath) == sourceContents,
        "Ambiguous backup publication did not retain exact source bytes");
    BOOST_CHECK(
        !HasSQLiteTestCandidate(backupFilename));

    const std::set<std::string> entriesAfter =
        SQLiteTestDirectoryEntries();
    std::vector<fs::path> retainedRecoveryPaths;
    for (const std::string& entry : entriesAfter) {
        if (entriesBefore.count(entry) == 0 &&
            entry != filename &&
            entry != backupFilename) {
            retainedRecoveryPaths.push_back(
                GetDataDir() / entry);
        }
    }
    BOOST_REQUIRE_EQUAL(
        retainedRecoveryPaths.size(),
        1U);
    const fs::path recoveryPath =
        retainedRecoveryPaths.front();
    BOOST_CHECK(
        recoveryPath.filename().string().find(
            "." + filename + ".sqlite-") == 0);
    BOOST_CHECK(
        error.find(recoveryPath.string()) !=
        std::string::npos);

    const std::string workingMarker{
        "backup publication from working path '"};
    const size_t workingStart =
        error.find(workingMarker);
    BOOST_REQUIRE(
        workingStart != std::string::npos);
    const size_t workingPathStart =
        workingStart + workingMarker.size();
    const std::string finalMarker =
        "' to final path '" +
        backupPath.string() +
        "'";
    const size_t workingPathEnd =
        error.find(
            finalMarker,
            workingPathStart);
    BOOST_REQUIRE(
        workingPathEnd != std::string::npos);
    const fs::path backupWorkingPath{
        error.substr(
            workingPathStart,
            workingPathEnd -
                workingPathStart)};
    BOOST_CHECK(
        backupWorkingPath.parent_path() ==
        GetDataDir());
    BOOST_CHECK(
        backupWorkingPath.filename().string().find(
            "." + backupFilename + ".sqlite-") == 0);
    BOOST_CHECK(!fs::exists(backupWorkingPath));

    for (const fs::path& artifact : {
             path,
             backupPath,
             recoveryPath}) {
        struct stat metadata{};
        BOOST_REQUIRE_EQUAL(
            lstat(
                artifact.string().c_str(),
                &metadata),
            0);
        BOOST_CHECK(S_ISREG(metadata.st_mode));
        BOOST_CHECK_EQUAL(
            metadata.st_nlink,
            1);
        BOOST_CHECK_EQUAL(
            metadata.st_uid,
            geteuid());
        BOOST_CHECK_EQUAL(
            metadata.st_mode & 0777,
            S_IRUSR | S_IWUSR);
        for (const char* suffix :
            {"-journal", "-wal", "-shm"}) {
            BOOST_CHECK(!fs::exists(
                artifact.string() + suffix));
        }
    }

    std::optional<std::vector<RawRecord> >
        retainedRecoveryRecords =
            ReadRawSQLiteRecordsNotIndexed(
                recoveryPath);
    BOOST_REQUIRE(retainedRecoveryRecords);
    std::sort(
        retainedRecoveryRecords->begin(),
        retainedRecoveryRecords->end());
    BOOST_CHECK_MESSAGE(
        *retainedRecoveryRecords == sourceRecords,
        "Retained ambiguous-publication recovery rows changed");

    BOOST_CHECK(fs::remove(recoveryPath));
    RemoveSQLiteTestFiles(filename);
    RemoveSQLiteTestFiles(backupFilename);
    RemoveSQLiteTestCandidates(filename);
    RemoveSQLiteTestCandidates(backupFilename);
    BOOST_CHECK(
        SQLiteTestDirectoryEntries() ==
        entriesBefore);
}

BOOST_AUTO_TEST_CASE(sqlite_recovery_backup_collision_is_fail_closed)
{
    struct MockTimeReset {
        ~MockTimeReset() { SetMockTime(0); }
    } mockTimeReset;
    ShutdownRequestReset shutdownReset;

    constexpr int64_t RECOVERY_TIME = 1900000300;
    SetMockTime(RECOVERY_TIME);

    const std::string filename{
        "sqlite_recovery_backup_collision.dat"};
    const std::string backupFilename =
        strprintf("wallet.%d.bak", RECOVERY_TIME);
    const fs::path path = GetDataDir() / filename;
    const fs::path backupPath =
        GetDataDir() / backupFilename;
    RemoveSQLiteTestFiles(filename);
    RemoveSQLiteTestFiles(backupFilename);
    RemoveSQLiteTestCandidates(filename);
    RemoveSQLiteTestCandidates(backupFilename);

    std::vector<RawRecord> sourceRecords;
    for (uint32_t i = 0; i < 64; ++i) {
        sourceRecords.emplace_back(
            SerializeToString(
                std::make_pair(
                    std::string(
                        "phase4d-collision-row"),
                    i)),
            SerializeToString(
                std::string(
                    64,
                    static_cast<char>(
                        'a' + (i % 26)))));
    }
    std::sort(
        sourceRecords.begin(),
        sourceRecords.end());

    DatabaseStatus status =
        DatabaseStatus::FAILED_LOAD;
    std::string error{"unchanged"};
    std::unique_ptr<WalletDatabase> database =
        CreateSQLiteTestDatabaseFromRawRecords(
            filename,
            sourceRecords,
            status,
            error);
    BOOST_REQUIRE_MESSAGE(database, error);
    BOOST_REQUIRE(
        status == DatabaseStatus::SUCCESS);
    BOOST_REQUIRE(database->PeriodicFlush());
    database.reset();

    const std::optional<std::vector<RawRecord> >
        readableRecords =
            ReadRawSQLiteRecordsNotIndexed(path);
    BOOST_REQUIRE(readableRecords);
    BOOST_CHECK_MESSAGE(
        *readableRecords == sourceRecords,
        "The collision fixture changed raw rows");
    BOOST_REQUIRE(
        CorruptSQLitePrimaryKeyIndex(path));
    const std::optional<std::vector<RawRecord> >
        corruptRecords =
            ReadRawSQLiteRecordsNotIndexed(path);
    BOOST_REQUIRE_MESSAGE(
        corruptRecords,
        "The collision source table is not readable");
    BOOST_CHECK_MESSAGE(
        *corruptRecords == *readableRecords,
        "Index corruption changed collision source rows");
    const std::string corruptContents =
        ReadFile(path);

    const std::string backupContents{
        "preexisting\0backup",
        18};
    WriteFile(backupPath, backupContents);
    fs::permissions(
        backupPath,
        fs::owner_read |
            fs::owner_write);

    struct stat sourceBefore{};
    struct stat backupBefore{};
    BOOST_REQUIRE_EQUAL(
        lstat(path.string().c_str(), &sourceBefore),
        0);
    BOOST_REQUIRE_EQUAL(
        lstat(
            backupPath.string().c_str(),
            &backupBefore),
        0);
    const std::set<std::string> entriesBeforeCleanCollision =
        SQLiteTestDirectoryEntries();

    DatabaseOptions recoveryOptions;
    recoveryOptions.require_existing = true;
    recoveryOptions.require_format =
        DatabaseFormat::SQLITE;
    recoveryOptions.recover = true;
    status = DatabaseStatus::SUCCESS;
    error = "unchanged";
    database = MakeSQLiteDatabase(
        filename,
        recoveryOptions,
        status,
        error);
    BOOST_CHECK(!database);
    BOOST_CHECK(
        status == DatabaseStatus::FAILED_VERIFY);
    BOOST_CHECK(
        error.find(
            "Refusing to overwrite existing SQLite "
            "recovery backup") !=
        std::string::npos);
    BOOST_CHECK(
        error.find(backupPath.string()) !=
        std::string::npos);
    BOOST_CHECK_MESSAGE(
        ReadFile(path) == corruptContents,
        "Backup collision changed the recovery source");
    BOOST_CHECK_MESSAGE(
        ReadFile(backupPath) == backupContents,
        "Backup collision changed the existing backup");
    BOOST_CHECK(!HasSQLiteTestCandidate(filename));
    BOOST_CHECK(
        !HasSQLiteTestCandidate(backupFilename));
    BOOST_CHECK(
        SQLiteTestDirectoryEntries() ==
        entriesBeforeCleanCollision);
    BOOST_CHECK(!fRequestShutdown.load());

    struct stat sourceAfter{};
    struct stat backupAfter{};
    BOOST_REQUIRE_EQUAL(
        lstat(path.string().c_str(), &sourceAfter),
        0);
    BOOST_REQUIRE_EQUAL(
        lstat(
            backupPath.string().c_str(),
            &backupAfter),
        0);
    BOOST_CHECK_EQUAL(
        sourceAfter.st_dev,
        sourceBefore.st_dev);
    BOOST_CHECK_EQUAL(
        sourceAfter.st_ino,
        sourceBefore.st_ino);
    BOOST_CHECK_EQUAL(
        backupAfter.st_dev,
        backupBefore.st_dev);
    BOOST_CHECK_EQUAL(
        backupAfter.st_ino,
        backupBefore.st_ino);
    BOOST_CHECK_EQUAL(
        backupAfter.st_nlink,
        1);
    BOOST_CHECK_EQUAL(
        backupAfter.st_mode & 0777,
        S_IRUSR | S_IWUSR);

    const std::set<std::string> entriesBeforeAmbiguousCleanup =
        SQLiteTestDirectoryEntries();
    InjectSQLiteRecoveryCollisionCleanupFailureForTesting();
    status = DatabaseStatus::SUCCESS;
    error = "unchanged";
    database = MakeSQLiteDatabase(
        filename,
        recoveryOptions,
        status,
        error);
    BOOST_CHECK(!database);
    BOOST_CHECK(
        status == DatabaseStatus::FAILED_LOAD);
    BOOST_CHECK(
        error.find("failed before publication") !=
        std::string::npos);
    BOOST_CHECK(
        error.find("candidate cleanup is indeterminate") !=
        std::string::npos);
    BOOST_CHECK(
        error.find("recovery working path") !=
        std::string::npos);
    BOOST_CHECK(
        error.find("unpublished backup working path") !=
        std::string::npos);
    BOOST_CHECK(
        error.find("No atomic recovery exchange was applied") !=
        std::string::npos);
    BOOST_CHECK(
        error.find("original wallet path remains authoritative") !=
        std::string::npos);
    BOOST_CHECK(
        error.find("Preserve all reported artifacts") !=
        std::string::npos);
    BOOST_CHECK(
        error.find("restart Firo") !=
        std::string::npos);
    BOOST_CHECK(
        error.find(path.string()) !=
        std::string::npos);
    BOOST_CHECK(
        error.find(backupPath.string()) !=
        std::string::npos);
    BOOST_CHECK(
        error.find("phase4d-collision-row") ==
        std::string::npos);
    BOOST_CHECK(
        error.find(std::string(64, 'a')) ==
        std::string::npos);
    BOOST_CHECK(fRequestShutdown.load());
    BOOST_CHECK_MESSAGE(
        ReadFile(path) == corruptContents,
        "Ambiguous cleanup changed the recovery source");
    BOOST_CHECK_MESSAGE(
        ReadFile(backupPath) == backupContents,
        "Ambiguous cleanup changed the existing backup");

    struct stat sourceFinal{};
    struct stat backupFinal{};
    BOOST_REQUIRE_EQUAL(
        lstat(path.string().c_str(), &sourceFinal),
        0);
    BOOST_REQUIRE_EQUAL(
        lstat(
            backupPath.string().c_str(),
            &backupFinal),
        0);
    BOOST_CHECK_EQUAL(
        sourceFinal.st_dev,
        sourceBefore.st_dev);
    BOOST_CHECK_EQUAL(
        sourceFinal.st_ino,
        sourceBefore.st_ino);
    BOOST_CHECK_EQUAL(
        backupFinal.st_dev,
        backupBefore.st_dev);
    BOOST_CHECK_EQUAL(
        backupFinal.st_ino,
        backupBefore.st_ino);
    BOOST_CHECK_EQUAL(
        backupFinal.st_nlink,
        1);
    BOOST_CHECK_EQUAL(
        backupFinal.st_mode & 0777,
        S_IRUSR | S_IWUSR);

    const std::set<std::string> entriesAfterAmbiguousCleanup =
        SQLiteTestDirectoryEntries();
    std::vector<fs::path> retainedPaths;
    for (const std::string& entry :
        entriesAfterAmbiguousCleanup) {
        if (entriesBeforeAmbiguousCleanup.count(entry) == 0) {
            retainedPaths.push_back(
                GetDataDir() / entry);
        }
    }
    BOOST_REQUIRE_EQUAL(retainedPaths.size(), 2U);
    for (const fs::path& retainedPath : retainedPaths) {
        struct stat retainedMetadata{};
        BOOST_REQUIRE_EQUAL(
            lstat(
                retainedPath.string().c_str(),
                &retainedMetadata),
            0);
        BOOST_CHECK(S_ISREG(retainedMetadata.st_mode));
        BOOST_CHECK_EQUAL(
            retainedMetadata.st_nlink,
            1);
        BOOST_CHECK_EQUAL(
            retainedMetadata.st_uid,
            geteuid());
        BOOST_CHECK_EQUAL(
            retainedMetadata.st_mode & 0777,
            S_IRUSR | S_IWUSR);
        BOOST_CHECK(
            error.find(retainedPath.string()) !=
            std::string::npos);
        for (const char* suffix :
            {"-journal", "-wal", "-shm"}) {
            BOOST_CHECK(!fs::exists(
                retainedPath.string() + suffix));
        }
        BOOST_CHECK(fs::remove(retainedPath));
    }
    BOOST_CHECK(
        SQLiteTestDirectoryEntries() ==
        entriesBeforeAmbiguousCleanup);

    RemoveSQLiteTestFiles(filename);
    RemoveSQLiteTestFiles(backupFilename);
    RemoveSQLiteTestCandidates(filename);
    RemoveSQLiteTestCandidates(backupFilename);
}
#endif

BOOST_AUTO_TEST_CASE(sqlite_logical_wallet_creation_lifecycle)
{
    auto createLogicalDatabase = [](
                                     const std::string& filename,
                                     DatabaseStatus& status,
                                     std::string& error) {
        DatabaseOptions options;
        options.require_create = true;
        options.require_format =
            DatabaseFormat::SQLITE;
        options.logical_wallet_create = true;
        return MakeSQLiteDatabase(
            filename,
            options,
            status,
            error);
    };
    auto existingOptions = [] {
        DatabaseOptions options;
        options.require_existing = true;
        options.require_format =
            DatabaseFormat::SQLITE;
        return options;
    }();

    {
        const std::string filename{
            "sqlite_pending_wallet_load.dat"};
        const fs::path path =
            GetDataDir() / filename;
        RemoveSQLiteTestFiles(filename);
        DatabaseStatus status;
        std::string error;
        std::unique_ptr<WalletDatabase> database =
            createLogicalDatabase(
                filename,
                status,
                error);
        BOOST_REQUIRE(database);
        {
            CWallet wallet(std::move(database));
            bool firstRun = false;
            BOOST_REQUIRE(
                wallet.LoadWallet(firstRun) ==
                DB_LOAD_OK);
            BOOST_CHECK(firstRun);
        }
        BOOST_CHECK(!fs::exists(path));
    }

    {
        const std::string filename{
            "sqlite_completed_wallet.dat"};
        RemoveSQLiteTestFiles(filename);
        DatabaseStatus status;
        std::string error;
        std::unique_ptr<WalletDatabase> database =
            createLogicalDatabase(
                filename,
                status,
                error);
        BOOST_REQUIRE(database);
        {
            std::unique_ptr<DatabaseBatch> batch =
                database->MakeBatch();
            BOOST_REQUIRE(batch);
            BOOST_REQUIRE(batch->Write(
                std::string("logical-state"),
                std::string("preserved")));
        }
        BOOST_CHECK(
            database->CompleteCreation(error) ==
            DatabaseCreationResult::COMPLETE);
        BOOST_CHECK(error.empty());
        BOOST_CHECK(
            database->CompleteCreation(error) ==
            DatabaseCreationResult::COMPLETE);
        database.reset();

        database = MakeSQLiteDatabase(
            filename,
            existingOptions,
            status,
            error);
        BOOST_REQUIRE(database);
        {
            std::unique_ptr<DatabaseBatch> batch =
                database->MakeBatch();
            BOOST_REQUIRE(batch);
            std::string value;
            BOOST_REQUIRE(batch->Read(
                std::string("logical-state"),
                value));
            BOOST_CHECK_EQUAL(value, "preserved");
            BOOST_CHECK(batch->Write(
                std::string("after-completion"),
                std::string("writable")));
        }
        database.reset();
        RemoveSQLiteTestFiles(filename);
    }

    {
        ShutdownRequestReset shutdownReset;
        BOOST_REQUIRE(!ShutdownRequested());
        const std::string filename{
            "sqlite_completion_rollback.dat"};
        const fs::path path =
            GetDataDir() / filename;
        RemoveSQLiteTestFiles(filename);
        DatabaseStatus status;
        std::string error;
        std::unique_ptr<WalletDatabase> database =
            createLogicalDatabase(
                filename,
                status,
                error);
        BOOST_REQUIRE(database);
        BOOST_REQUIRE(
            SetSQLiteCreationStatementExecutorForTesting(
                *database,
                std::make_unique<
                    BlockingSQLiteStatementExecutor>(
                    std::set<std::string>{
                        "COMMIT TRANSACTION"})));
        BOOST_CHECK(
            database->CompleteCreation(error) ==
            DatabaseCreationResult::FAILED);
        BOOST_CHECK(!error.empty());
        BOOST_CHECK(!ShutdownRequested());
        database.reset();
        BOOST_CHECK(!fs::exists(path));
    }

    {
        ShutdownRequestReset shutdownReset;
        BOOST_REQUIRE(!ShutdownRequested());
        const std::string filename{
            "sqlite_completion_rolled_back_error.dat"};
        const fs::path path =
            GetDataDir() / filename;
        RemoveSQLiteTestFiles(filename);
        DatabaseStatus status;
        std::string error;
        std::unique_ptr<WalletDatabase> database =
            createLogicalDatabase(
                filename,
                status,
                error);
        BOOST_REQUIRE(database);
        BOOST_REQUIRE(
            SetSQLiteCreationStatementExecutorForTesting(
                *database,
                std::make_unique<
                    RollbackCommitSQLiteStatementExecutor>()));
        BOOST_CHECK(
            database->CompleteCreation(error) ==
            DatabaseCreationResult::FAILED);
        BOOST_CHECK(!error.empty());
        BOOST_CHECK(!ShutdownRequested());
        database.reset();
        BOOST_CHECK(!fs::exists(path));
    }

    {
        ShutdownRequestReset shutdownReset;
        BOOST_REQUIRE(!ShutdownRequested());
        const std::string filename{
            "sqlite_completion_applied_error.dat"};
        RemoveSQLiteTestFiles(filename);
        DatabaseStatus status;
        std::string error;
        std::unique_ptr<WalletDatabase> database =
            createLogicalDatabase(
                filename,
                status,
                error);
        BOOST_REQUIRE(database);
        BOOST_REQUIRE(
            SetSQLiteCreationStatementExecutorForTesting(
                *database,
                std::make_unique<
                    CommitThenFailSQLiteStatementExecutor>()));
        BOOST_CHECK(
            database->CompleteCreation(error) ==
            DatabaseCreationResult::COMPLETE);
        BOOST_CHECK(error.empty());
        BOOST_CHECK(!ShutdownRequested());
        {
            std::unique_ptr<DatabaseBatch> batch =
                database->MakeBatch();
            BOOST_REQUIRE(batch);
            BOOST_CHECK(batch->Write(
                std::string("reconciled"),
                std::string("writable")));
        }
        database.reset();

        database = MakeSQLiteDatabase(
            filename,
            existingOptions,
            status,
            error);
        BOOST_REQUIRE(database);
        database.reset();
        RemoveSQLiteTestFiles(filename);
    }

    {
        ShutdownRequestReset shutdownReset;
        BOOST_REQUIRE(!ShutdownRequested());
        const std::string filename{
            "sqlite_completion_close_failure.dat"};
        const fs::path path =
            GetDataDir() / filename;
        RemoveSQLiteTestFiles(filename);
        DatabaseStatus status;
        std::string error;
        std::unique_ptr<WalletDatabase> database =
            createLogicalDatabase(
                filename,
                status,
                error);
        BOOST_REQUIRE(database);
        BOOST_REQUIRE(
            SetSQLiteCreationStatementExecutorForTesting(
                *database,
                std::make_unique<
                    CommitThenFailSQLiteStatementExecutor>()));
        InjectSQLiteCloseFailureForTesting();
        BOOST_CHECK(
            database->CompleteCreation(error) ==
            DatabaseCreationResult::INDETERMINATE);
        BOOST_CHECK(ShutdownRequested());
        database.reset();
        BOOST_CHECK(fs::is_regular_file(path));
        BOOST_REQUIRE(ResetSQLiteLifecycleForTesting());

        database = MakeSQLiteDatabase(
            filename,
            existingOptions,
            status,
            error);
        BOOST_REQUIRE(database);
        database.reset();
        RemoveSQLiteTestFiles(filename);
    }
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(sqlite_incomplete_creation_is_retained_safely)
{
    auto logicalOptions = [] {
        DatabaseOptions options;
        options.require_create = true;
        options.require_format =
            DatabaseFormat::SQLITE;
        options.logical_wallet_create = true;
        return options;
    }();
    DatabaseOptions existingOptions;
    existingOptions.require_existing = true;
    existingOptions.require_format =
        DatabaseFormat::SQLITE;

    {
        const std::string filename{
            "sqlite_crashed_creation.dat"};
        const fs::path path =
            GetDataDir() / filename;
        RemoveSQLiteTestFiles(filename);
        const pid_t child = fork();
        if (child == 0) {
            DatabaseStatus status;
            std::string error;
            std::unique_ptr<WalletDatabase> database =
                MakeSQLiteDatabase(
                    filename,
                    logicalOptions,
                    status,
                    error);
            _exit(database ? 0 : 1);
        }
        BOOST_REQUIRE(child > 0);
        int childStatus = 0;
        pid_t waited;
        do {
            waited = waitpid(
                child,
                &childStatus,
                0);
        } while (waited < 0 && errno == EINTR);
        BOOST_REQUIRE_EQUAL(waited, child);
        BOOST_REQUIRE(WIFEXITED(childStatus));
        BOOST_REQUIRE_EQUAL(
            WEXITSTATUS(childStatus),
            0);
        BOOST_REQUIRE(fs::is_regular_file(path));

        DatabaseStatus status;
        std::string error;
        std::unique_ptr<WalletDatabase> database =
            MakeSQLiteDatabase(
                filename,
                existingOptions,
                status,
                error);
        BOOST_CHECK(!database);
        BOOST_CHECK(
            status ==
            DatabaseStatus::FAILED_VERIFY);
        BOOST_CHECK(
            error.find("incomplete") !=
            std::string::npos);
        BOOST_CHECK(fs::is_regular_file(path));
        RemoveSQLiteTestFiles(filename);
    }

    {
        const std::string filename{
            "sqlite_pending_close_failure.dat"};
        const fs::path path =
            GetDataDir() / filename;
        RemoveSQLiteTestFiles(filename);
        DatabaseStatus status;
        std::string error;
        std::unique_ptr<WalletDatabase> database =
            MakeSQLiteDatabase(
                filename,
                logicalOptions,
                status,
                error);
        BOOST_REQUIRE(database);
        InjectSQLiteCloseFailureForTesting();
        database.reset();
        BOOST_CHECK(fs::is_regular_file(path));
        BOOST_REQUIRE(ResetSQLiteLifecycleForTesting());

        database = MakeSQLiteDatabase(
            filename,
            existingOptions,
            status,
            error);
        BOOST_CHECK(!database);
        BOOST_CHECK(
            status ==
            DatabaseStatus::FAILED_VERIFY);
        BOOST_CHECK(
            error.find("incomplete") !=
            std::string::npos);
        RemoveSQLiteTestFiles(filename);
    }

    {
        const std::string filename{
            "sqlite_pending_identity_replacement.dat"};
        const std::string movedFilename{
            "sqlite_pending_identity_owned.dat"};
        const fs::path path =
            GetDataDir() / filename;
        const fs::path movedPath =
            GetDataDir() / movedFilename;
        RemoveSQLiteTestFiles(filename);
        RemoveSQLiteTestFiles(movedFilename);
        DatabaseStatus status;
        std::string error;
        std::unique_ptr<WalletDatabase> database =
            MakeSQLiteDatabase(
                filename,
                logicalOptions,
                status,
                error);
        BOOST_REQUIRE(database);
        fs::rename(path, movedPath);
        const std::string sentinel{
            "unrelated replacement"};
        WriteFile(path, sentinel);
        database.reset();
        BOOST_CHECK_EQUAL(
            ReadFile(path),
            sentinel);
        BOOST_CHECK(fs::is_regular_file(movedPath));
        RemoveSQLiteTestFiles(filename);
        RemoveSQLiteTestFiles(movedFilename);
    }

    {
        ShutdownRequestReset shutdownReset;
        BOOST_REQUIRE(!ShutdownRequested());
        const std::string filename{
            "sqlite_pending_directory_sync_failure.dat"};
        const fs::path path =
            GetDataDir() / filename;
        RemoveSQLiteTestFiles(filename);
        RemoveSQLiteTestCandidates(filename);
        DatabaseStatus status;
        std::string error;
        std::unique_ptr<WalletDatabase> database =
            MakeSQLiteDatabase(
                filename,
                logicalOptions,
                status,
                error);
        BOOST_REQUIRE(database);

        InjectSQLiteDirectorySyncFailureForTesting(EIO);
        database.reset();

        BOOST_CHECK(!fs::exists(path));
        BOOST_CHECK(!HasSQLiteTestCandidate(filename));
        BOOST_CHECK(ShutdownRequested());

        RemoveSQLiteTestFiles(filename);
        RemoveSQLiteTestCandidates(filename);
    }
}
#endif
#endif

BOOST_AUTO_TEST_CASE(wallet_record_logical_parity)
{
    CKey destinationKey;
    destinationKey.MakeNewKey(true);
    const CTxDestination destination =
        destinationKey.GetPubKey().GetID();
    const std::string destinationAddress =
        CBitcoinAddress(destination).ToString();

    CKey metadataKey;
    metadataKey.MakeNewKey(true);
    const CPubKey metadataPubKey = metadataKey.GetPubKey();
    CKeyMetadata keyMetadata{1700000042};
    keyMetadata.hdKeypath = "m/44'/136'/0'/1/9";
    keyMetadata.hdMasterKeyID =
        destinationKey.GetPubKey().GetID();

    CKey legacyKey;
    legacyKey.MakeNewKey(true);
    const CPubKey legacyPubKey = legacyKey.GetPubKey();
    CWalletKey legacyWalletKey;
    legacyWalletKey.vchPrivKey = legacyKey.GetPrivKey();
    legacyWalletKey.nTimeCreated = 1700000001;
    legacyWalletKey.nTimeExpires = 1700001001;
    legacyWalletKey.strComment = "record-parity-wkey";

    CKey redeemKey;
    redeemKey.MakeNewKey(true);
    const CScript redeemScript =
        GetScriptForDestination(redeemKey.GetPubKey().GetID());
    CKey watchKey;
    watchKey.MakeNewKey(true);
    const CScript watchScript =
        GetScriptForDestination(watchKey.GetPubKey().GetID());
    const CKeyMetadata watchMetadata{1700000023};

    CKey accountKey;
    accountKey.MakeNewKey(true);
    CAccount account;
    account.vchPubKey = accountKey.GetPubKey();

    CAccountingEntry debit;
    debit.strAccount = "z-source";
    debit.nCreditDebit = -12345;
    debit.nTime = 1700000101;
    debit.strOtherAccount = "a-target";
    debit.strComment = "record-parity-debit";
    debit.mapValue["phase"] = "4c";
    debit.nOrderPos = 0;
    debit.nEntryNo = 41;

    CAccountingEntry credit;
    credit.strAccount = "a-target";
    credit.nCreditDebit = 12345;
    credit.nTime = 1700000102;
    credit.strOtherAccount = "z-source";
    credit.strComment = "record-parity-credit";
    credit.mapValue["phase"] = "4c";
    credit.nOrderPos = 1;
    credit.nEntryNo = 42;

    const CBlockLocator blockLocator{
        std::vector<uint256>{
            uint256S("01"),
            uint256S("02"),
        }};

    const int calculatedHeight = 314159;
    const int32_t mintCount = 17;
    const int32_t mintSeedCount = 29;
    const uint256 fullHash = uint256S("11");
    const uint256 reducedHash = uint256S("12");
    const uint256 serialA = uint256S("21");
    const uint256 serialB = uint256S("22");
    secp_primitives::GroupElement pubcoinA;
    pubcoinA.set_base_g();
    pubcoinA *= secp_primitives::Scalar(7);
    secp_primitives::GroupElement pubcoinB;
    pubcoinB.set_base_g();
    pubcoinB *= secp_primitives::Scalar(11);
    const uint256 mintPoolHash = uint256S("31");
    uint160 seedMaster;
    seedMaster.SetHex("41");
    CKey seedKey;
    seedKey.MakeNewKey(true);
    const CKeyID seedId = seedKey.GetPubKey().GetID();
    const int32_t seedCount = 43;

    const spark::Params* const sparkParams =
        spark::Params::get_default();
    spark::SpendKey spendKey(sparkParams);
    spark::FullViewKey fullViewKey(spendKey);
    spark::IncomingViewKey incomingViewKey(fullViewKey);
    const uint64_t diversifier = 17;
    const uint64_t sparkValue =
        static_cast<uint64_t>(13 * COIN);
    const std::vector<unsigned char> serialContext{
        0x00,
        0x01,
        0x7f,
        0x80,
        0xff,
    };
    spark::Address sparkAddress(
        incomingViewKey,
        diversifier);
    secp_primitives::Scalar nonce;
    nonce.randomize();
    spark::Coin coin(
        sparkParams,
        spark::COIN_TYPE_MINT,
        nonce,
        sparkAddress,
        sparkValue,
        "record parity mint",
        serialContext);
    const spark::IdentifiedCoinData identifiedCoin =
        coin.identify(incomingViewKey);
    const spark::RecoveredCoinData recoveredCoin =
        coin.recover(fullViewKey, identifiedCoin);
    const uint256 lTagHash =
        primitives::GetLTagHash(recoveredCoin.T);

    CSparkMintMeta sparkMint{};
    sparkMint.nHeight = 123;
    sparkMint.nId = 4;
    sparkMint.isUsed = true;
    sparkMint.txid = uint256S("51");
    sparkMint.i = identifiedCoin.i;
    sparkMint.d = identifiedCoin.d;
    sparkMint.v = identifiedCoin.v;
    sparkMint.k = identifiedCoin.k;
    sparkMint.memo = identifiedCoin.memo;
    sparkMint.serial_context = serialContext;
    sparkMint.type = coin.type;
    sparkMint.coin = coin;

    CSparkSpendEntry sparkSpend;
    sparkSpend.lTag = recoveredCoin.T;
    sparkSpend.lTagHash = lTagHash;
    sparkSpend.hashTx = uint256S("52");
    sparkSpend.amount = sparkValue;

    CDataStream serializedCoin(SER_NETWORK, PROTOCOL_VERSION);
    serializedCoin << coin;
    CScript sparkOutputScript;
    sparkOutputScript << OP_SPARKSMINT;
    sparkOutputScript.insert(
        sparkOutputScript.end(),
        serializedCoin.begin(),
        serializedCoin.end());
    CSparkOutputTx sparkOutput;
    sparkOutput.address =
        sparkAddress.encode(spark::GetNetworkType());
    sparkOutput.amount = sparkValue;
    sparkOutput.memo = "record parity output";

    const std::vector<DatabaseFormat> formats{
        DatabaseFormat::BERKELEY,
#ifdef USE_SQLITE
        DatabaseFormat::SQLITE,
#endif
    };

    for (const DatabaseFormat format : formats) {
        BOOST_TEST_CONTEXT(
            "wallet format " << DatabaseFormatName(format))
        {
            const std::string filename = strprintf(
                "wallet_record_parity_%s.dat",
                DatabaseFormatName(format));
            DatabaseOptions createOptions;
            createOptions.require_create = true;
            createOptions.require_format = format;
            DatabaseStatus status;
            std::string error;
            std::unique_ptr<WalletDatabase> database =
                MakeWalletDatabase(
                    filename,
                    createOptions,
                    status,
                    error);
            BOOST_REQUIRE_MESSAGE(database, error);
            BOOST_REQUIRE(
                status == DatabaseStatus::SUCCESS);
            BOOST_REQUIRE(
                database->Format() == format);

            CAccountingEntry debitWrite = debit;
            CAccountingEntry creditWrite = credit;
            {
                CWalletDB writer(*database);
                BOOST_REQUIRE(writer.TxnBegin());
                BOOST_REQUIRE(writer.WriteKV(
                    "record-parity-kv",
                    "record-parity-value"));
                BOOST_REQUIRE(writer.WriteDestData(
                    destinationAddress,
                    "record-parity-dest-key",
                    "record-parity-dest-value"));
                BOOST_REQUIRE(writer.WritePurpose(
                    destinationAddress,
                    "receive"));
                BOOST_REQUIRE(writer.WriteKey(
                    metadataPubKey,
                    metadataKey.GetPrivKey(),
                    keyMetadata));
                BOOST_REQUIRE(
                    writer.WriteBestBlock(blockLocator));
                BOOST_REQUIRE(
                    writer.WriteAccount(
                        "record-parity-account",
                        account));
                BOOST_REQUIRE(
                    writer.WriteAccountingEntry(
                        debit.nEntryNo,
                        debitWrite));
                BOOST_REQUIRE(
                    writer.WriteAccountingEntry(
                        credit.nEntryNo,
                        creditWrite));
                BOOST_REQUIRE(
                    writer.WriteOrderPosNext(2));
                BOOST_REQUIRE(
                    writer.WriteCScript(
                        Hash160(redeemScript),
                        redeemScript));
                BOOST_REQUIRE(
                    writer.WriteWatchOnly(
                        watchScript,
                        watchMetadata));
                BOOST_REQUIRE(
                    writer.WriteCalculatedZCBlock(
                        calculatedHeight));
                BOOST_REQUIRE(
                    writer.WriteMintCount(mintCount));
                BOOST_REQUIRE(
                    writer.WriteMintSeedCount(
                        mintSeedCount));
                BOOST_REQUIRE(
                    writer.WritePubcoinHashes(
                        fullHash,
                        reducedHash));
                BOOST_REQUIRE(
                    writer.WritePubcoin(
                        serialA,
                        pubcoinA));
                BOOST_REQUIRE(
                    writer.WritePubcoin(
                        serialB,
                        pubcoinB));
                BOOST_REQUIRE(
                    writer.WriteMintPoolPair(
                        mintPoolHash,
                        std::make_tuple(
                            seedMaster,
                            seedId,
                            seedCount)));
                BOOST_REQUIRE(
                    writer.WriteSparkMint(
                        lTagHash,
                        sparkMint));
                BOOST_REQUIRE(
                    writer.WriteSparkSpendEntry(
                        sparkSpend));
                BOOST_REQUIRE(
                    writer.WriteSparkOutputTx(
                        sparkOutputScript,
                        sparkOutput));
                BOOST_REQUIRE(writer.TxnCommit());
                BOOST_CHECK(!writer.HasActiveTxn());
            }

            {
                CDataStream rawKey(
                    SER_DISK,
                    CLIENT_VERSION);
                rawKey << std::make_pair(
                    std::string("wkey"),
                    legacyPubKey);
                CDataStream rawValue(
                    SER_DISK,
                    CLIENT_VERSION);
                rawValue << legacyWalletKey;
                std::unique_ptr<DatabaseBatch> batch =
                    database->MakeBatch();
                BOOST_REQUIRE(batch);
                BOOST_REQUIRE(batch->TxnBegin());
                BOOST_REQUIRE(
                    batch->WriteRawRecord(
                        std::move(rawKey),
                        std::move(rawValue),
                        false));
                BOOST_REQUIRE(batch->TxnCommit());
            }

            BOOST_REQUIRE(database->PeriodicFlush());
            database.reset();

            DatabaseOptions existingOptions;
            existingOptions.require_existing = true;
            existingOptions.require_format = format;
            existingOptions.recover = false;
            database = MakeWalletDatabase(
                filename,
                existingOptions,
                status,
                error);
            BOOST_REQUIRE_MESSAGE(database, error);
            BOOST_REQUIRE(
                status == DatabaseStatus::SUCCESS);
            BOOST_REQUIRE(
                database->Format() == format);

            {
                CWallet loaded(std::move(database));
                {
                    CWalletDB loader(
                        loaded.GetDatabase(),
                        {DatabaseBatchMode::READ_ONLY});
                    BOOST_REQUIRE(
                        loader.LoadWallet(
                            &loaded,
                            false) == DB_LOAD_OK);
                }

                {
                    LOCK(loaded.cs_wallet);
                    const auto custom =
                        loaded.mapCustomKeyValues.equal_range(
                            "record-parity-kv");
                    BOOST_REQUIRE(
                        custom.first != custom.second);
                    BOOST_CHECK_EQUAL(
                        custom.first->second,
                        "record-parity-value");
                    auto customEnd = custom.first;
                    ++customEnd;
                    BOOST_CHECK(
                        customEnd == custom.second);

                    std::string destinationValue;
                    BOOST_REQUIRE(
                        loaded.GetDestData(
                            destination,
                            "record-parity-dest-key",
                            &destinationValue));
                    BOOST_CHECK_EQUAL(
                        destinationValue,
                        "record-parity-dest-value");

                    const auto addressBook =
                        loaded.mapAddressBook.find(
                            destination);
                    BOOST_REQUIRE(
                        addressBook !=
                        loaded.mapAddressBook.end());
                    BOOST_CHECK_EQUAL(
                        addressBook->second.purpose,
                        "receive");

                    const auto metadata =
                        loaded.mapKeyMetadata.find(
                            metadataPubKey.GetID());
                    BOOST_REQUIRE(
                        metadata !=
                        loaded.mapKeyMetadata.end());
                    const bool metadataMatches =
                        SameSerializedValue(
                            keyMetadata,
                            metadata->second);
                    BOOST_CHECK(metadataMatches);

                    BOOST_CHECK_EQUAL(
                        loaded.nOrderPosNext,
                        2);

                    const auto watchMeta =
                        loaded.mapKeyMetadata.find(
                            CScriptID(watchScript));
                    BOOST_REQUIRE(
                        watchMeta !=
                        loaded.mapKeyMetadata.end());
                    BOOST_CHECK(
                        SameSerializedValue(
                            watchMetadata,
                            watchMeta->second));

                    BOOST_REQUIRE_EQUAL(
                        loaded.laccentries.size(),
                        2);
                    const auto loadedDebit =
                        std::find_if(
                            loaded.laccentries.begin(),
                            loaded.laccentries.end(),
                            [](const CAccountingEntry& entry) {
                                return entry.strAccount ==
                                       "z-source";
                            });
                    const auto loadedCredit =
                        std::find_if(
                            loaded.laccentries.begin(),
                            loaded.laccentries.end(),
                            [](const CAccountingEntry& entry) {
                                return entry.strAccount ==
                                       "a-target";
                            });
                    BOOST_REQUIRE(
                        loadedDebit !=
                        loaded.laccentries.end());
                    BOOST_REQUIRE(
                        loadedCredit !=
                        loaded.laccentries.end());
                    BOOST_CHECK(
                        SameAccountingEntry(
                            debit,
                            *loadedDebit));
                    BOOST_CHECK(
                        SameAccountingEntry(
                            credit,
                            *loadedCredit));

                    BOOST_REQUIRE_EQUAL(
                        loaded.wtxOrdered.size(),
                        2);
                    auto ordered =
                        loaded.wtxOrdered.begin();
                    BOOST_CHECK_EQUAL(
                        ordered->first,
                        0);
                    BOOST_REQUIRE(
                        ordered->second.second);
                    BOOST_CHECK_EQUAL(
                        ordered->second.second->strAccount,
                        "z-source");
                    ++ordered;
                    BOOST_CHECK_EQUAL(
                        ordered->first,
                        1);
                    BOOST_REQUIRE(
                        ordered->second.second);
                    BOOST_CHECK_EQUAL(
                        ordered->second.second->strAccount,
                        "a-target");
                }

                CKey loadedLegacyKey;
                BOOST_REQUIRE(
                    loaded.GetKey(
                        legacyPubKey.GetID(),
                        loadedLegacyKey));
                BOOST_CHECK(
                    SameKey(
                        legacyKey,
                        loadedLegacyKey));
                CKey loadedMetadataKey;
                BOOST_REQUIRE(
                    loaded.GetKey(
                        metadataPubKey.GetID(),
                        loadedMetadataKey));
                const bool metadataKeyMatches =
                    SameKey(
                        metadataKey,
                        loadedMetadataKey);
                BOOST_CHECK(metadataKeyMatches);
                CScript loadedRedeemScript;
                BOOST_REQUIRE(
                    loaded.GetCScript(
                        CScriptID(redeemScript),
                        loadedRedeemScript));
                BOOST_CHECK(
                    loadedRedeemScript == redeemScript);
                BOOST_CHECK(
                    loaded.HaveWatchOnly(watchScript));

                {
                    std::unique_ptr<DatabaseBatch> batch =
                        loaded.GetDatabase().MakeBatch(
                            {DatabaseBatchMode::READ_ONLY});
                    BOOST_REQUIRE(batch);
                    CBlockLocator legacyLocator;
                    BOOST_REQUIRE(
                        batch->Read(
                            std::string("bestblock"),
                            legacyLocator));
                    BOOST_CHECK(
                        legacyLocator.vHave.empty());
                    CBlockLocator currentLocator;
                    BOOST_REQUIRE(
                        batch->Read(
                            std::string(
                                "bestblock_nomerkle"),
                            currentLocator));
                    BOOST_CHECK(
                        currentLocator.vHave ==
                        blockLocator.vHave);
                    int loadedCalculatedHeight = 0;
                    BOOST_REQUIRE(
                        batch->Read(
                            std::string(
                                "calculatedzcblock"),
                            loadedCalculatedHeight));
                    BOOST_CHECK_EQUAL(
                        loadedCalculatedHeight,
                        calculatedHeight);
                }

                {
                    CWalletDB reader(
                        loaded.GetDatabase(),
                        {DatabaseBatchMode::READ_ONLY});
                    CBlockLocator loadedLocator;
                    BOOST_REQUIRE(
                        reader.ReadBestBlock(
                            loadedLocator));
                    BOOST_CHECK(
                        loadedLocator.vHave ==
                        blockLocator.vHave);

                    CAccount loadedAccount;
                    BOOST_REQUIRE(
                        reader.ReadAccount(
                            "record-parity-account",
                            loadedAccount));
                    BOOST_CHECK(
                        loadedAccount.vchPubKey ==
                        account.vchPubKey);
                    BOOST_CHECK_EQUAL(
                        reader.GetAccountCreditDebit(
                            "z-source"),
                        debit.nCreditDebit);
                    BOOST_CHECK_EQUAL(
                        reader.GetAccountCreditDebit(
                            "a-target"),
                        credit.nCreditDebit);

                    int32_t loadedMintCount = 0;
                    BOOST_REQUIRE(
                        reader.ReadMintCount(
                            loadedMintCount));
                    BOOST_CHECK_EQUAL(
                        loadedMintCount,
                        mintCount);
                    int32_t loadedMintSeedCount = 0;
                    BOOST_REQUIRE(
                        reader.ReadMintSeedCount(
                            loadedMintSeedCount));
                    BOOST_CHECK_EQUAL(
                        loadedMintSeedCount,
                        mintSeedCount);
                    uint256 loadedReducedHash;
                    BOOST_REQUIRE(
                        reader.ReadPubcoinHashes(
                            fullHash,
                            loadedReducedHash));
                    BOOST_CHECK(
                        loadedReducedHash ==
                        reducedHash);
                    secp_primitives::GroupElement
                        loadedPubcoin;
                    BOOST_REQUIRE(
                        reader.ReadPubcoin(
                            serialA,
                            loadedPubcoin));
                    BOOST_CHECK(
                        SameSerializedValue(
                            pubcoinA,
                            loadedPubcoin));
                    BOOST_REQUIRE(
                        reader.ReadPubcoin(
                            serialB,
                            loadedPubcoin));
                    BOOST_CHECK(
                        SameSerializedValue(
                            pubcoinB,
                            loadedPubcoin));
                    const auto serialPubcoins =
                        reader.ListSerialPubcoinPairs();
                    BOOST_REQUIRE_EQUAL(
                        serialPubcoins.size(),
                        2);
                    const std::map<
                        uint256,
                        secp_primitives::GroupElement>
                        serialPubcoinMap(
                            serialPubcoins.begin(),
                            serialPubcoins.end());
                    const auto listedPubcoinA =
                        serialPubcoinMap.find(serialA);
                    const auto listedPubcoinB =
                        serialPubcoinMap.find(serialB);
                    BOOST_REQUIRE(
                        listedPubcoinA !=
                        serialPubcoinMap.end());
                    BOOST_REQUIRE(
                        listedPubcoinB !=
                        serialPubcoinMap.end());
                    BOOST_CHECK(
                        SameSerializedValue(
                            pubcoinA,
                            listedPubcoinA->second));
                    BOOST_CHECK(
                        SameSerializedValue(
                            pubcoinB,
                            listedPubcoinB->second));

                    uint160 loadedSeedMaster;
                    CKeyID loadedSeedId;
                    int32_t loadedSeedCount = 0;
                    BOOST_REQUIRE(
                        reader.ReadMintPoolPair(
                            mintPoolHash,
                            loadedSeedMaster,
                            loadedSeedId,
                            loadedSeedCount));
                    BOOST_CHECK(
                        loadedSeedMaster ==
                        seedMaster);
                    BOOST_CHECK(
                        loadedSeedId == seedId);
                    BOOST_CHECK_EQUAL(
                        loadedSeedCount,
                        seedCount);

                    CSparkMintMeta loadedSparkMint{};
                    BOOST_REQUIRE(
                        reader.ReadSparkMint(
                            lTagHash,
                            loadedSparkMint));
                    BOOST_CHECK(
                        SameSerializedValue(
                            sparkMint,
                            loadedSparkMint));
                    const auto listedSparkMints =
                        reader.ListSparkMints();
                    BOOST_REQUIRE_EQUAL(
                        listedSparkMints.size(),
                        1);
                    const auto listedSparkMint =
                        listedSparkMints.find(
                            lTagHash);
                    BOOST_REQUIRE(
                        listedSparkMint !=
                        listedSparkMints.end());
                    BOOST_CHECK(
                        SameSerializedValue(
                            sparkMint,
                            listedSparkMint->second));
                    loadedSparkMint.coin.setSerialContext(
                        loadedSparkMint.serial_context);
                    const auto loadedIdentifiedCoin =
                        loadedSparkMint.coin.identify(
                            incomingViewKey);
                    const auto loadedRecoveredCoin =
                        loadedSparkMint.coin.recover(
                            fullViewKey,
                            loadedIdentifiedCoin);
                    BOOST_CHECK(
                        SameIdentifiedCoin(
                            identifiedCoin,
                            loadedIdentifiedCoin));
                    BOOST_CHECK(
                        SameRecoveredCoin(
                            recoveredCoin,
                            loadedRecoveredCoin));

                    BOOST_CHECK(
                        reader.HasSparkSpendEntry(
                            sparkSpend.lTag));
                    CSparkSpendEntry loadedSparkSpend;
                    BOOST_REQUIRE(
                        reader.ReadSparkSpendEntry(
                            sparkSpend.lTag,
                            loadedSparkSpend));
                    BOOST_CHECK(
                        SameSerializedValue(
                            sparkSpend,
                            loadedSparkSpend));
                    std::list<CSparkSpendEntry>
                        listedSparkSpends;
                    reader.ListSparkSpends(
                        listedSparkSpends);
                    BOOST_REQUIRE_EQUAL(
                        listedSparkSpends.size(),
                        1);
                    BOOST_CHECK(
                        SameSerializedValue(
                            sparkSpend,
                            listedSparkSpends.front()));

                    CSparkOutputTx loadedSparkOutput;
                    BOOST_REQUIRE(
                        reader.ReadSparkOutputTx(
                            sparkOutputScript,
                            loadedSparkOutput));
                    BOOST_CHECK(
                        SameSerializedValue(
                            sparkOutput,
                            loadedSparkOutput));
                }

                BOOST_REQUIRE(
                    loaded.GetDatabase().PeriodicFlush());
            }

            if (format == DatabaseFormat::BERKELEY) {
                BOOST_REQUIRE(bitdb.RemoveDb(filename));
            }
#ifdef USE_SQLITE
            else {
                RemoveSQLiteTestFiles(filename);
            }
#endif
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_CASE(
    wallet_mnemonic_encryption_persists,
    WalletDatabasePathTestingSetup)
{
    const SecureString passphrase{"test passphrase"};
    const SecureString newPassphrase{"new test passphrase"};
    const SecureString finalPassphrase{"final test passphrase"};
    const SecureString wrongPassphrase{"wrong test passphrase"};
    const std::vector<DatabaseFormat> formats{
        DatabaseFormat::BERKELEY,
#ifdef USE_SQLITE
        DatabaseFormat::SQLITE,
#endif
    };

    for (const DatabaseFormat format : formats) {
        BOOST_TEST_CONTEXT(
            "wallet format " << DatabaseFormatName(format))
        {
            const std::string filename = strprintf(
                "wallet_mnemonic_encryption_%s.dat",
                DatabaseFormatName(format));
            const std::string backupFilename = strprintf(
                "wallet_mnemonic_encryption_%s.backup",
                DatabaseFormatName(format));
            const fs::path backupPath =
                GetDataDir() / backupFilename;
            SecureString expectedMnemonic;
            SecureVector expectedSeed;

            auto makeDatabase =
                [&](const std::string& databaseFilename, bool create)
                -> std::unique_ptr<WalletDatabase> {
                DatabaseOptions options;
                options.require_create = create;
                options.require_existing = !create;
                options.require_format = format;
                options.recover = false;
                DatabaseStatus status{
                    DatabaseStatus::FAILED_LOAD};
                std::string error;
                std::unique_ptr<WalletDatabase> database =
                    MakeWalletDatabase(
                        databaseFilename,
                        options,
                        status,
                        error);
                BOOST_REQUIRE_MESSAGE(database, error);
                BOOST_REQUIRE(
                    status == DatabaseStatus::SUCCESS);
                BOOST_REQUIRE(
                    database->Format() == format);
                return database;
            };
            auto restartBerkeleyEnvironment = [&] {
                if (format != DatabaseFormat::BERKELEY) {
                    return;
                }
                bitdb.Flush(true);
                {
                    LOCK(bitdb.cs_db);
                    BOOST_REQUIRE(
                        bitdb.mapFileUseCount.empty());
                    for (const auto& database :
                        bitdb.mapDb) {
                        BOOST_REQUIRE(
                            database.second == nullptr);
                    }
                    BOOST_REQUIRE(
                        bitdb.migrationLogPins.empty());
                    bitdb.mapDb.clear();
                }
                bitdb.Close();
                bitdb.Reset();
            };

            {
                CWallet wallet(
                    makeDatabase(filename, true));
                bool firstRun;
                BOOST_REQUIRE(
                    wallet.LoadWallet(firstRun) ==
                    DB_LOAD_OK);
                BOOST_REQUIRE(firstRun);

                wallet.GenerateNewMnemonic();
                CPubKey defaultKey;
                {
                    LOCK(wallet.cs_wallet);
                    defaultKey = wallet.GenerateNewKey();
                }
                BOOST_REQUIRE(
                    wallet.SetDefaultKey(defaultKey));

                const MnemonicContainer& mnemonic =
                    wallet.GetMnemonicContainer();
                BOOST_REQUIRE(
                    mnemonic.GetMnemonic(
                        expectedMnemonic));
                expectedSeed = mnemonic.GetSeed();
                BOOST_REQUIRE(!expectedMnemonic.empty());
                BOOST_REQUIRE(!expectedSeed.empty());

                BOOST_REQUIRE(
                    wallet.EncryptWallet(passphrase));
                BOOST_CHECK(
                    wallet.GetMnemonicContainer().IsCrypted());
                std::string backupError{"unchanged"};
                BOOST_REQUIRE_MESSAGE(
                    wallet.BackupWallet(
                        backupPath.string(),
                        backupError),
                    backupError);
                BOOST_CHECK(backupError.empty());
            }

            restartBerkeleyEnvironment();
            {
                CWallet wallet(
                    makeDatabase(
                        backupFilename,
                        false));
                bool firstRun;
                BOOST_REQUIRE(
                    wallet.LoadWallet(firstRun) ==
                    DB_LOAD_OK);
                BOOST_CHECK(!firstRun);
                BOOST_CHECK(
                    wallet.GetVersion() >= FEATURE_HD);
                BOOST_REQUIRE(
                    wallet.GetMnemonicContainer().IsCrypted());
                BOOST_REQUIRE(wallet.IsLocked());
                BOOST_REQUIRE(
                    wallet.Unlock(passphrase));

                MnemonicContainer decrypted;
                BOOST_REQUIRE(
                    wallet.DecryptMnemonicContainer(
                        decrypted));
                SecureString actualMnemonic;
                BOOST_REQUIRE(
                    decrypted.GetMnemonic(
                        actualMnemonic));
                const bool mnemonicMatches =
                    actualMnemonic == expectedMnemonic;
                const bool seedMatches =
                    decrypted.GetSeed() == expectedSeed;
                BOOST_CHECK(mnemonicMatches);
                BOOST_CHECK(seedMatches);
                BOOST_REQUIRE(
                    wallet.GetDatabase().PeriodicFlush());
            }

            restartBerkeleyEnvironment();
            {
                CWallet wallet(
                    makeDatabase(filename, false));
                bool firstRun;
                BOOST_REQUIRE(
                    wallet.LoadWallet(firstRun) ==
                    DB_LOAD_OK);
                BOOST_CHECK(!firstRun);
                BOOST_CHECK(
                    wallet.GetVersion() >= FEATURE_HD);
                BOOST_REQUIRE(
                    wallet.GetMnemonicContainer().IsCrypted());
                BOOST_REQUIRE(
                    wallet.Unlock(passphrase));

                MnemonicContainer decrypted;
                BOOST_REQUIRE(
                    wallet.DecryptMnemonicContainer(
                        decrypted));
                SecureString actualMnemonic;
                BOOST_REQUIRE(
                    decrypted.GetMnemonic(
                        actualMnemonic));
                const bool mnemonicMatches =
                    actualMnemonic == expectedMnemonic;
                const bool seedMatches =
                    decrypted.GetSeed() == expectedSeed;
                BOOST_CHECK(mnemonicMatches);
                BOOST_CHECK(seedMatches);

                BOOST_CHECK(!wallet.IsLocked());
                BOOST_CHECK(
                    !wallet.ChangeWalletPassphrase(
                        wrongPassphrase,
                        newPassphrase));
                if (format == DatabaseFormat::BERKELEY) {
                    BOOST_CHECK(wallet.IsLocked());
                    BOOST_REQUIRE(
                        wallet.Unlock(passphrase));
                } else {
                    BOOST_CHECK(!wallet.IsLocked());
                }
                BOOST_REQUIRE(
                    wallet.ChangeWalletPassphrase(
                        passphrase,
                        newPassphrase));
                BOOST_CHECK(!wallet.IsLocked());
                BOOST_REQUIRE(wallet.Lock());
                BOOST_REQUIRE(
                    wallet.ChangeWalletPassphrase(
                        newPassphrase,
                        finalPassphrase));
                BOOST_CHECK(wallet.IsLocked());
                BOOST_REQUIRE(
                    wallet.GetDatabase().PeriodicFlush());
            }

            {
                CWallet wallet(
                    makeDatabase(filename, false));
                bool firstRun;
                BOOST_REQUIRE(
                    wallet.LoadWallet(firstRun) ==
                    DB_LOAD_OK);
                BOOST_CHECK(!firstRun);
                BOOST_CHECK(
                    !wallet.Unlock(passphrase));
                BOOST_CHECK(
                    !wallet.Unlock(newPassphrase));
                BOOST_REQUIRE(
                    wallet.Unlock(finalPassphrase));

                MnemonicContainer decrypted;
                BOOST_REQUIRE(
                    wallet.DecryptMnemonicContainer(
                        decrypted));
                SecureString actualMnemonic;
                BOOST_REQUIRE(
                    decrypted.GetMnemonic(
                        actualMnemonic));
                const bool mnemonicMatches =
                    actualMnemonic == expectedMnemonic;
                const bool seedMatches =
                    decrypted.GetSeed() == expectedSeed;
                BOOST_CHECK(mnemonicMatches);
                BOOST_CHECK(seedMatches);
                BOOST_REQUIRE(
                    wallet.GetDatabase().PeriodicFlush());
            }

            if (format == DatabaseFormat::BERKELEY) {
                BOOST_CHECK(fs::remove(backupPath));
                BOOST_CHECK(bitdb.RemoveDb(filename));
            }
#ifdef USE_SQLITE
            else {
                RemoveSQLiteTestFiles(filename);
                RemoveSQLiteTestFiles(backupFilename);
            }
#endif
        }
    }
}

#ifdef USE_SQLITE
BOOST_FIXTURE_TEST_CASE(
    sqlite_wallet_encryption_failure_contract,
    WalletDatabasePathTestingSetup)
{
    const SecureString passphrase{"sqlite encryption passphrase"};
    const SecureString newPassphrase{"sqlite replacement passphrase"};

    auto makeDatabase =
        [](const std::string& filename, bool create)
        -> std::unique_ptr<WalletDatabase> {
        DatabaseOptions options;
        options.require_create = create;
        options.require_existing = !create;
        options.require_format = DatabaseFormat::SQLITE;
        options.recover = false;
        DatabaseStatus status{
            DatabaseStatus::FAILED_LOAD};
        std::string error;
        std::unique_ptr<WalletDatabase> database =
            MakeWalletDatabase(
                filename,
                options,
                status,
                error);
        BOOST_REQUIRE_MESSAGE(database, error);
        BOOST_REQUIRE(
            status == DatabaseStatus::SUCCESS);
        return database;
    };
    auto createPlainWallet =
        [&](const std::string& filename) {
            RemoveSQLiteTestFiles(filename);
            auto wallet = std::make_unique<CWallet>(
                makeDatabase(filename, true));
            bool firstRun = false;
            BOOST_REQUIRE(
                wallet->LoadWallet(firstRun) ==
                DB_LOAD_OK);
            BOOST_REQUIRE(firstRun);
            CPubKey pubkey;
            {
                LOCK(wallet->cs_wallet);
                pubkey = wallet->GenerateNewKey();
            }
            BOOST_REQUIRE(wallet->SetDefaultKey(pubkey));
            return std::make_pair(
                std::move(wallet),
                pubkey);
        };
    auto checkPlainWallet =
        [&](const std::string& filename,
            const CPubKey& pubkey) {
            std::unique_ptr<WalletDatabase> database =
                makeDatabase(filename, false);
            {
                std::unique_ptr<DatabaseBatch> batch =
                    database->MakeBatch();
                BOOST_REQUIRE(batch);
                BOOST_CHECK(
                    batch->ExistsWithStatus(
                        std::make_pair(
                            std::string("key"),
                            pubkey)) ==
                    DatabaseReadStatus::SUCCESS);
                BOOST_CHECK(
                    batch->ExistsWithStatus(
                        std::make_pair(
                            std::string("ckey"),
                            pubkey)) ==
                    DatabaseReadStatus::NOT_FOUND);
            }
            CWallet wallet(std::move(database));
            bool firstRun = true;
            BOOST_REQUIRE(
                wallet.LoadWallet(firstRun) ==
                DB_LOAD_OK);
            BOOST_CHECK(!firstRun);
            BOOST_CHECK(!wallet.IsCrypted());
            BOOST_CHECK(wallet.HaveKey(pubkey.GetID()));
        };
    auto checkEncryptedWallet =
        [&](const std::string& filename,
            const SecureString& expectedPassphrase,
            const SecureString* rejectedPassphrase =
                nullptr) {
            CWallet wallet(
                makeDatabase(filename, false));
            bool firstRun = true;
            BOOST_REQUIRE(
                wallet.LoadWallet(firstRun) ==
                DB_LOAD_OK);
            BOOST_CHECK(!firstRun);
            BOOST_REQUIRE(wallet.IsCrypted());
            BOOST_REQUIRE(wallet.IsLocked());
            if (rejectedPassphrase) {
                BOOST_CHECK(
                    !wallet.Unlock(*rejectedPassphrase));
            }
            BOOST_REQUIRE(
                wallet.Unlock(expectedPassphrase));
        };

    {
        ShutdownRequestReset shutdownReset;
        const std::string filename{
            "sqlite_encryption_commit_failure.dat"};
        auto walletAndKey =
            createPlainWallet(filename);
        BOOST_REQUIRE(
            SetSQLiteNextBatchStatementExecutorForTesting(
                walletAndKey.first->GetDatabase(),
                std::make_unique<
                    BlockingSQLiteStatementExecutor>(
                    std::set<std::string>{
                        "COMMIT TRANSACTION"})));
        BOOST_CHECK(
            !walletAndKey.first->EncryptWallet(
                passphrase));
        BOOST_CHECK(ShutdownRequested());
        walletAndKey.first.reset();
        checkPlainWallet(
            filename,
            walletAndKey.second);
        RemoveSQLiteTestFiles(filename);
    }

    {
        ShutdownRequestReset shutdownReset;
        const std::string filename{
            "sqlite_encryption_erase_failure.dat"};
        auto walletAndKey =
            createPlainWallet(filename);
        InjectSQLiteEraseFailureForTesting(0);
        BOOST_CHECK(
            !walletAndKey.first->EncryptWallet(
                passphrase));
        BOOST_CHECK_EQUAL(
            GetSQLiteEraseAttemptsForTesting(),
            2);
        BOOST_CHECK(ShutdownRequested());
        walletAndKey.first.reset();
        checkPlainWallet(
            filename,
            walletAndKey.second);
        RemoveSQLiteTestFiles(filename);
    }

    {
        ShutdownRequestReset shutdownReset;
        const std::string filename{
            "sqlite_encryption_applied_commit.dat"};
        auto walletAndKey =
            createPlainWallet(filename);
        BOOST_REQUIRE(
            SetSQLiteNextBatchStatementExecutorForTesting(
                walletAndKey.first->GetDatabase(),
                std::make_unique<
                    CommitThenFailSQLiteStatementExecutor>()));
        BOOST_CHECK(
            !walletAndKey.first->EncryptWallet(
                passphrase));
        BOOST_CHECK(
            walletAndKey.first->IsCrypted());
        BOOST_CHECK(ShutdownRequested());
        walletAndKey.first.reset();
        checkEncryptedWallet(
            filename,
            passphrase);
        RemoveSQLiteTestFiles(filename);
    }

    {
        ShutdownRequestReset shutdownReset;
        const std::string filename{
            "sqlite_passphrase_commit_failure.dat"};
        auto walletAndKey =
            createPlainWallet(filename);
        BOOST_REQUIRE(
            walletAndKey.first->EncryptWallet(
                passphrase));
        BOOST_REQUIRE(
            walletAndKey.first->Unlock(
                passphrase));
        BOOST_REQUIRE(
            SetSQLiteNextBatchStatementExecutorForTesting(
                walletAndKey.first->GetDatabase(),
                std::make_unique<
                    BlockingSQLiteStatementExecutor>(
                    std::set<std::string>{
                        "COMMIT TRANSACTION"})));
        BOOST_CHECK(
            !walletAndKey.first->ChangeWalletPassphrase(
                passphrase,
                newPassphrase));
        BOOST_CHECK(
            !walletAndKey.first->IsLocked());
        BOOST_CHECK(!ShutdownRequested());
        walletAndKey.first.reset();
        checkEncryptedWallet(
            filename,
            passphrase,
            &newPassphrase);
        RemoveSQLiteTestFiles(filename);
    }

    {
        ShutdownRequestReset shutdownReset;
        const std::string filename{
            "sqlite_passphrase_applied_commit.dat"};
        auto walletAndKey =
            createPlainWallet(filename);
        BOOST_REQUIRE(
            walletAndKey.first->EncryptWallet(
                passphrase));
        BOOST_REQUIRE(
            walletAndKey.first->Unlock(
                passphrase));
        BOOST_REQUIRE(
            SetSQLiteNextBatchStatementExecutorForTesting(
                walletAndKey.first->GetDatabase(),
                std::make_unique<
                    CommitThenFailSQLiteStatementExecutor>()));
        bool indeterminate = false;
        BOOST_CHECK(
            !walletAndKey.first->ChangeWalletPassphrase(
                passphrase,
                newPassphrase,
                &indeterminate));
        BOOST_CHECK(indeterminate);
        BOOST_CHECK(
            !walletAndKey.first->IsLocked());
        BOOST_CHECK(ShutdownRequested());
        walletAndKey.first.reset();
        checkEncryptedWallet(
            filename,
            newPassphrase,
            &passphrase);
        RemoveSQLiteTestFiles(filename);
    }
}
#endif
