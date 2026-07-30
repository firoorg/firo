// Copyright (c) 2020-present The Bitcoin Core developers
// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "config/bitcoin-config.h"

#ifdef USE_SQLITE

#include "wallet/sqlite.h"

#include "chainparams.h"
#include "crypto/common.h"
#include "support/cleanse.h"
#include "util.h"

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#ifdef WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/syscall.h>
#elif defined(__APPLE__)
#include <sys/stdio.h>
#endif
#include <unistd.h>
#endif

namespace
{
constexpr int SQLITE_BUSY_TIMEOUT_MILLISECONDS = 5000;
constexpr int32_t WALLET_SCHEMA_VERSION = 0;

std::mutex g_sqlite_mutex;
size_t g_sqlite_owner_count{0};
bool g_sqlite_initialized{false};
std::atomic<bool> g_sqlite_has_abandoned_connection{false};
sqlite3* g_sqlite_first_abandoned_connection{nullptr};
size_t g_sqlite_abandoned_connection_count{0};
std::atomic<bool> g_fail_post_publish_once{false};
std::atomic<bool> g_report_publish_error_after_rename_once{false};
std::atomic<int> g_fail_close_after_successes{-1};

bool ConsumePostPublishFailure()
{
    return g_fail_post_publish_once.exchange(false);
}

bool ConsumePublishErrorAfterRename()
{
    return g_report_publish_error_after_rename_once.exchange(false);
}

bool ConsumeCloseFailure()
{
    int remaining = g_fail_close_after_successes.load();
    while (remaining >= 0) {
        const int next = remaining == 0 ? -1 : remaining - 1;
        if (g_fail_close_after_successes.compare_exchange_weak(
                remaining,
                next)) {
            return remaining == 0;
        }
    }
    return false;
}

void LogSQLiteError(const char* context, sqlite3* database, int result) noexcept
{
    const char* message = database ? sqlite3_errmsg(database) : sqlite3_errstr(result);
    LogPrintf("%s: SQLite error %d: %s\n", context, result, message ? message : "unknown error");
}

bool AcquireSQLite(std::string& error)
{
    std::lock_guard<std::mutex> lock(g_sqlite_mutex);
    if (g_sqlite_has_abandoned_connection.load()) {
        error =
            "SQLite is quarantined after a connection lifecycle failure; "
            "restart the process before opening another SQLite wallet.";
        return false;
    }
    if (!g_sqlite_initialized) {
        int result = sqlite3_config(SQLITE_CONFIG_SERIALIZED);
        if (result != SQLITE_OK) {
            error = strprintf("Failed to configure serialized SQLite threading mode (error %d).", result);
            return false;
        }
        result = sqlite3_initialize();
        if (result != SQLITE_OK) {
            error = strprintf("Failed to initialize SQLite (error %d).", result);
            sqlite3_shutdown();
            return false;
        }
        g_sqlite_initialized = true;
    }
    ++g_sqlite_owner_count;
    return true;
}

void ReleaseSQLite() noexcept
{
    std::lock_guard<std::mutex> lock(g_sqlite_mutex);
    if (g_sqlite_owner_count == 0) {
        return;
    }
    --g_sqlite_owner_count;
    if (g_sqlite_owner_count == 0 &&
        !g_sqlite_has_abandoned_connection.load()) {
        const int result = sqlite3_shutdown();
        if (result != SQLITE_OK) {
            LogPrintf("SQLiteDatabase: Failed to shut down SQLite (error %d).\n", result);
            g_sqlite_has_abandoned_connection.store(true);
        } else {
            g_sqlite_initialized = false;
        }
    }
}

void CleanseStream(CDataStream& stream) noexcept
{
    if (!stream.empty()) {
        memory_cleanse(stream.data(), stream.size());
    }
}

class StreamCleanser final
{
private:
    CDataStream& m_stream;

public:
    explicit StreamCleanser(CDataStream& stream)
        : m_stream(stream)
    {
    }

    ~StreamCleanser() { CleanseStream(m_stream); }

    StreamCleanser(const StreamCleanser&) = delete;
    StreamCleanser& operator=(const StreamCleanser&) = delete;
};

class ByteVectorCleanser final
{
private:
    std::vector<unsigned char>& m_vector;
    bool m_active{true};

public:
    explicit ByteVectorCleanser(std::vector<unsigned char>& vector)
        : m_vector(vector)
    {
    }

    ~ByteVectorCleanser()
    {
        if (m_active && !m_vector.empty()) {
            memory_cleanse(m_vector.data(), m_vector.size());
        }
    }

    void Release() noexcept { m_active = false; }

    ByteVectorCleanser(const ByteVectorCleanser&) = delete;
    ByteVectorCleanser& operator=(const ByteVectorCleanser&) = delete;
};

class SQLiteStatement final
{
private:
    sqlite3_stmt* m_statement{nullptr};

public:
    SQLiteStatement() = default;

    ~SQLiteStatement()
    {
        if (m_statement) {
            sqlite3_clear_bindings(m_statement);
            sqlite3_reset(m_statement);
            const int result = sqlite3_finalize(m_statement);
            if (result != SQLITE_OK) {
                LogPrintf("SQLiteStatement: Failed to finalize statement (error %d).\n", result);
            }
        }
    }

    SQLiteStatement(const SQLiteStatement&) = delete;
    SQLiteStatement& operator=(const SQLiteStatement&) = delete;

    sqlite3_stmt** Address() { return &m_statement; }
    sqlite3_stmt* Get() const { return m_statement; }
    sqlite3_stmt* Release()
    {
        sqlite3_stmt* const statement = m_statement;
        m_statement = nullptr;
        return statement;
    }
};

bool PrepareStatement(
    sqlite3* database,
    const char* sql,
    SQLiteStatement& statement,
    const char* context,
    std::string* error = nullptr)
{
    const int result = sqlite3_prepare_v2(database, sql, -1, statement.Address(), nullptr);
    if (result == SQLITE_OK) {
        return true;
    }
    if (error) {
        *error = strprintf("%s: %s", context, sqlite3_errmsg(database));
    } else {
        LogSQLiteError(context, database, result);
    }
    return false;
}

bool BindBlob(
    sqlite3_stmt* statement,
    int index,
    const void* data,
    size_t size,
    const char* description)
{
    if (size > static_cast<size_t>(INT_MAX)) {
        LogPrintf("SQLiteDatabase: Refusing oversized %s BLOB binding.\n", description);
        return false;
    }
    const void* const binding = data ? data : static_cast<const void*>("");
    const int result = sqlite3_bind_blob(
        statement,
        index,
        binding,
        static_cast<int>(size),
        SQLITE_STATIC);
    if (result != SQLITE_OK) {
        LogPrintf("SQLiteDatabase: Failed to bind %s BLOB (error %d).\n", description, result);
        return false;
    }
    return true;
}

bool BindBlob(
    sqlite3_stmt* statement,
    int index,
    const CDataStream& stream,
    const char* description)
{
    return BindBlob(
        statement,
        index,
        stream.empty() ? nullptr : stream.data(),
        stream.size(),
        description);
}

bool ExecuteSQL(sqlite3* database, const char* statement, std::string* error = nullptr)
{
    const int result = sqlite3_exec(database, statement, nullptr, nullptr, nullptr);
    if (result == SQLITE_OK) {
        return true;
    }
    if (error) {
        *error = strprintf("Failed to execute SQLite statement: %s", sqlite3_errmsg(database));
    } else {
        LogSQLiteError("SQLiteDatabase: Failed to execute statement", database, result);
    }
    return false;
}

std::optional<int64_t> ReadPragmaInteger(
    sqlite3* database,
    const char* statement,
    const char* description,
    std::string& error)
{
    SQLiteStatement prepared;
    if (!PrepareStatement(database, statement, prepared, description, &error)) {
        return std::nullopt;
    }
    const int result = sqlite3_step(prepared.Get());
    if (result != SQLITE_ROW || sqlite3_column_type(prepared.Get(), 0) != SQLITE_INTEGER) {
        error = strprintf("Failed to read %s: %s", description, sqlite3_errmsg(database));
        return std::nullopt;
    }
    return sqlite3_column_int64(prepared.Get(), 0);
}

std::optional<std::string> ReadPragmaText(
    sqlite3* database,
    const char* statement,
    const char* description,
    std::string& error)
{
    SQLiteStatement prepared;
    if (!PrepareStatement(database, statement, prepared, description, &error)) {
        return std::nullopt;
    }
    const int result = sqlite3_step(prepared.Get());
    if (result != SQLITE_ROW || sqlite3_column_type(prepared.Get(), 0) != SQLITE_TEXT) {
        error = strprintf("Failed to read %s: %s", description, sqlite3_errmsg(database));
        return std::nullopt;
    }
    const unsigned char* const text = sqlite3_column_text(prepared.Get(), 0);
    if (!text) {
        error = strprintf("Failed to read %s.", description);
        return std::nullopt;
    }
    return reinterpret_cast<const char*>(text);
}

uint32_t ExpectedApplicationId()
{
    return ReadBE32(Params().MessageStart());
}

struct SQLiteFileIdentity {
#ifndef WIN32
    dev_t device{0};
    ino_t inode{0};
#endif
    bool valid{false};
};

bool PathIdentityMatches(
    const fs::path& path,
    const SQLiteFileIdentity& identity) noexcept
{
#ifdef WIN32
    (void)path;
    (void)identity;
    return false;
#else
    if (!identity.valid) {
        return false;
    }
    struct stat metadata{};
    return lstat(path.string().c_str(), &metadata) == 0 &&
           S_ISREG(metadata.st_mode) &&
           metadata.st_dev == identity.device &&
           metadata.st_ino == identity.inode;
#endif
}

bool DescriptorIdentityMatches(
    int descriptor,
    const SQLiteFileIdentity& identity) noexcept
{
#ifdef WIN32
    (void)descriptor;
    (void)identity;
    return false;
#else
    if (descriptor < 0 || !identity.valid) {
        return false;
    }
    struct stat metadata{};
    return fstat(descriptor, &metadata) == 0 &&
           S_ISREG(metadata.st_mode) &&
           metadata.st_dev == identity.device &&
           metadata.st_ino == identity.inode;
#endif
}

bool ConnectionIdentityMatches(
    sqlite3* database,
    const fs::path& path,
    const SQLiteFileIdentity& identity,
    std::string& error)
{
    if (!PathIdentityMatches(path, identity)) {
        error = strprintf(
            "Refusing SQLite wallet '%s': its file identity changed while opening.",
            path.string());
        return false;
    }

    int moved = 1;
    const int result = sqlite3_file_control(
        database,
        "main",
        SQLITE_FCNTL_HAS_MOVED,
        &moved);
    if (result != SQLITE_OK || moved != 0) {
        error = strprintf(
            "Refusing SQLite wallet '%s': SQLite could not prove that its "
            "open handle still names the preflighted file (error %d).",
            path.string(),
            result);
        return false;
    }
    return true;
}

bool VerifySchema(sqlite3* database, std::string& error)
{
    {
        SQLiteStatement objects;
        if (!PrepareStatement(
                database,
                "SELECT type, name, tbl_name, rootpage, sql FROM sqlite_master "
                "ORDER BY type, name",
                objects,
                "Failed to inspect SQLite schema objects",
                &error)) {
            return false;
        }

        bool found_index = false;
        bool found_table = false;
        while (true) {
            const int result = sqlite3_step(objects.Get());
            if (result == SQLITE_DONE) {
                break;
            }
            if (result != SQLITE_ROW) {
                error = strprintf("Failed to inspect SQLite schema objects: %s", sqlite3_errmsg(database));
                return false;
            }
            const unsigned char* const type = sqlite3_column_text(objects.Get(), 0);
            const unsigned char* const name = sqlite3_column_text(objects.Get(), 1);
            const unsigned char* const table = sqlite3_column_text(objects.Get(), 2);
            const unsigned char* const sql = sqlite3_column_text(objects.Get(), 4);
            static constexpr const char* CANONICAL_SCHEMA =
                "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)";
            if (!type || !name || !table ||
                sqlite3_column_int64(objects.Get(), 3) <= 0) {
                error = "SQLite wallet schema contains an unexpected object.";
                return false;
            }

            const char* const object_type =
                reinterpret_cast<const char*>(type);
            const char* const object_name =
                reinterpret_cast<const char*>(name);
            const char* const object_table =
                reinterpret_cast<const char*>(table);
            if (std::strcmp(object_type, "index") == 0 &&
                std::strcmp(object_name, "sqlite_autoindex_main_1") == 0 &&
                std::strcmp(object_table, "main") == 0 &&
                sqlite3_column_type(objects.Get(), 4) == SQLITE_NULL &&
                !found_index) {
                found_index = true;
                continue;
            }
            if (std::strcmp(object_type, "table") == 0 &&
                std::strcmp(object_name, "main") == 0 &&
                std::strcmp(object_table, "main") == 0 &&
                sql &&
                std::strcmp(
                    reinterpret_cast<const char*>(sql),
                    CANONICAL_SCHEMA) == 0 &&
                !found_table) {
                found_table = true;
                continue;
            }
            if (std::strcmp(object_name, "main") == 0) {
                error = "SQLite wallet main table does not use the canonical schema definition.";
            } else {
                error = "SQLite wallet schema contains an unexpected object.";
            }
            return false;
        }
        if (!found_index || !found_table) {
            if (!found_table) {
                error = "SQLite wallet schema must contain exactly one canonical main table.";
            } else {
                error = "SQLite wallet schema is missing its canonical primary-key index.";
            }
            return false;
        }
    }

    SQLiteStatement columns;
    if (!PrepareStatement(
            database,
            "PRAGMA table_xinfo(main)",
            columns,
            "Failed to inspect SQLite wallet columns",
            &error)) {
        return false;
    }

    struct ExpectedColumn {
        int id;
        const char* name;
        int primary_key;
    };
    static constexpr ExpectedColumn EXPECTED_COLUMNS[]{
        {0, "key", 1},
        {1, "value", 0},
    };

    int column = 0;
    while (true) {
        const int result = sqlite3_step(columns.Get());
        if (result == SQLITE_DONE) {
            break;
        }
        if (result != SQLITE_ROW) {
            error = strprintf("Failed to inspect SQLite wallet columns: %s", sqlite3_errmsg(database));
            return false;
        }
        if (column >= static_cast<int>(sizeof(EXPECTED_COLUMNS) / sizeof(EXPECTED_COLUMNS[0]))) {
            error = "SQLite wallet main table has extra columns.";
            return false;
        }

        const unsigned char* const name = sqlite3_column_text(columns.Get(), 1);
        const unsigned char* const type = sqlite3_column_text(columns.Get(), 2);
        const ExpectedColumn& expected = EXPECTED_COLUMNS[column];
        if (sqlite3_column_int(columns.Get(), 0) != expected.id ||
            !name ||
            std::strcmp(reinterpret_cast<const char*>(name), expected.name) != 0 ||
            !type ||
            std::strcmp(reinterpret_cast<const char*>(type), "BLOB") != 0 ||
            sqlite3_column_int(columns.Get(), 3) != 1 ||
            sqlite3_column_type(columns.Get(), 4) != SQLITE_NULL ||
            sqlite3_column_int(columns.Get(), 5) != expected.primary_key ||
            sqlite3_column_int(columns.Get(), 6) != 0) {
            error = "SQLite wallet main table does not have the exact key/value BLOB schema.";
            return false;
        }
        ++column;
    }

    if (column != static_cast<int>(sizeof(EXPECTED_COLUMNS) / sizeof(EXPECTED_COLUMNS[0]))) {
        error = "SQLite wallet main table is missing a required column.";
        return false;
    }
    return true;
}

bool VerifyBlobRecords(sqlite3* database, std::string& error)
{
    SQLiteStatement statement;
    if (!PrepareStatement(
            database,
            "SELECT 1 FROM main "
            "WHERE typeof(key) <> 'blob' OR typeof(value) <> 'blob' LIMIT 1",
            statement,
            "Failed to inspect SQLite wallet record types",
            &error)) {
        return false;
    }
    const int result = sqlite3_step(statement.Get());
    if (result == SQLITE_DONE) {
        return true;
    }
    if (result == SQLITE_ROW) {
        error = "SQLite wallet contains a key or value that is not stored as a BLOB.";
        return false;
    }
    error = strprintf("Failed to inspect SQLite wallet record types: %s", sqlite3_errmsg(database));
    return false;
}

bool VerifyIntegrity(sqlite3* database, std::string& error)
{
    SQLiteStatement statement;
    if (!PrepareStatement(
            database,
            "PRAGMA integrity_check",
            statement,
            "Failed to prepare SQLite integrity check",
            &error)) {
        return false;
    }

    int rows = 0;
    bool valid = true;
    while (true) {
        const int result = sqlite3_step(statement.Get());
        if (result == SQLITE_DONE) {
            break;
        }
        if (result != SQLITE_ROW) {
            error = strprintf("Failed to execute SQLite integrity check: %s", sqlite3_errmsg(database));
            return false;
        }
        ++rows;
        const unsigned char* const message = sqlite3_column_text(statement.Get(), 0);
        if (!message ||
            std::strcmp(reinterpret_cast<const char*>(message), "ok") != 0) {
            valid = false;
        }
    }

    if (!valid || rows != 1) {
        error = "SQLite wallet failed its full integrity check.";
        return false;
    }
    return true;
}

bool VerifyDatabase(sqlite3* database, std::string& error)
{
    const std::optional<int64_t> application_id = ReadPragmaInteger(
        database,
        "PRAGMA application_id",
        "SQLite wallet application ID",
        error);
    if (!application_id) {
        return false;
    }

    const int32_t expected_signed_id = static_cast<int32_t>(ExpectedApplicationId());
    if (*application_id != expected_signed_id) {
        error = strprintf(
            "SQLite wallet has application ID %d; expected %d for the active network.",
            *application_id,
            expected_signed_id);
        return false;
    }

    const std::optional<int64_t> user_version = ReadPragmaInteger(
        database,
        "PRAGMA user_version",
        "SQLite wallet schema version",
        error);
    if (!user_version) {
        return false;
    }
    if (*user_version != WALLET_SCHEMA_VERSION) {
        error = strprintf(
            "SQLite wallet schema version %d is unsupported; expected %d.",
            *user_version,
            WALLET_SCHEMA_VERSION);
        return false;
    }

    return VerifySchema(database, error) &&
           VerifyBlobRecords(database, error) &&
           VerifyIntegrity(database, error);
}

bool SetConnectionPragmas(sqlite3* database, std::string& error)
{
    const std::optional<std::string> journal_mode = ReadPragmaText(
        database,
        "PRAGMA journal_mode = DELETE",
        "SQLite rollback journal mode",
        error);
    if (!journal_mode || *journal_mode != "delete") {
        if (error.empty()) {
            error = "Failed to set SQLite rollback journal mode to DELETE.";
        }
        return false;
    }

    if (!ExecuteSQL(database, "PRAGMA synchronous = EXTRA", &error) ||
        !ExecuteSQL(database, "PRAGMA fullfsync = ON", &error) ||
        !ExecuteSQL(database, "PRAGMA journal_size_limit = 0", &error) ||
        !ExecuteSQL(database, "PRAGMA temp_store = MEMORY", &error)) {
        return false;
    }

    const std::optional<int64_t> synchronous = ReadPragmaInteger(
        database,
        "PRAGMA synchronous",
        "SQLite synchronous mode",
        error);
    const std::optional<int64_t> fullfsync = ReadPragmaInteger(
        database,
        "PRAGMA fullfsync",
        "SQLite fullfsync mode",
        error);
    const std::optional<int64_t> journal_limit = ReadPragmaInteger(
        database,
        "PRAGMA journal_size_limit",
        "SQLite journal size limit",
        error);
    const std::optional<int64_t> temp_store = ReadPragmaInteger(
        database,
        "PRAGMA temp_store",
        "SQLite temporary storage mode",
        error);
    if (!synchronous || *synchronous != 3 ||
        !fullfsync || *fullfsync != 1 ||
        !journal_limit || *journal_limit != 0 ||
        !temp_store || *temp_store != 2) {
        if (error.empty()) {
            error = "Failed to apply required SQLite durability settings.";
        }
        return false;
    }

    const std::optional<std::string> locking_mode = ReadPragmaText(
        database,
        "PRAGMA locking_mode = EXCLUSIVE",
        "SQLite locking mode",
        error);
    if (!locking_mode || *locking_mode != "exclusive") {
        if (error.empty()) {
            error = "Failed to set SQLite locking mode to EXCLUSIVE.";
        }
        return false;
    }

    if (!ExecuteSQL(database, "BEGIN EXCLUSIVE TRANSACTION", &error)) {
        error = "Unable to obtain the exclusive SQLite wallet lock; another process may be using the wallet.";
        return false;
    }
    if (!ExecuteSQL(database, "COMMIT TRANSACTION", &error)) {
        ExecuteSQL(database, "ROLLBACK TRANSACTION");
        return false;
    }
    return true;
}

bool CloseSQLiteConnection(sqlite3*& database) noexcept;
void AbandonSQLiteConnection(sqlite3*& database) noexcept;
bool CloseOrAbandonSQLiteConnection(
    sqlite3*& database,
    bool* cleanup_allowed = nullptr) noexcept;

bool OpenSQLiteConnection(
    const fs::path& path,
    sqlite3*& database,
    std::string& error,
    const SQLiteFileIdentity* expected_identity = nullptr,
    bool* cleanup_allowed = nullptr)
{
    database = nullptr;
    const int flags = SQLITE_OPEN_FULLMUTEX |
                      SQLITE_OPEN_NOFOLLOW |
                      SQLITE_OPEN_READWRITE;
    int result = sqlite3_open_v2(path.string().c_str(), &database, flags, nullptr);
    if (result != SQLITE_OK) {
        error = strprintf(
            "Failed to open SQLite wallet '%s': %s",
            path.string(),
            database ? sqlite3_errmsg(database) : sqlite3_errstr(result));
        CloseOrAbandonSQLiteConnection(database, cleanup_allowed);
        return false;
    }
    if (expected_identity &&
        !ConnectionIdentityMatches(
            database,
            path,
            *expected_identity,
            error)) {
        CloseOrAbandonSQLiteConnection(database, cleanup_allowed);
        return false;
    }

    result = sqlite3_extended_result_codes(database, 1);
    if (result == SQLITE_OK) {
        result = sqlite3_busy_timeout(database, SQLITE_BUSY_TIMEOUT_MILLISECONDS);
    }
    if (result != SQLITE_OK) {
        error = strprintf("Failed to configure SQLite wallet connection: %s", sqlite3_errmsg(database));
        CloseOrAbandonSQLiteConnection(database, cleanup_allowed);
        return false;
    }

    if (sqlite3_db_readonly(database, "main") != 0) {
        error = "SQLite wallet unexpectedly opened read-only.";
        CloseOrAbandonSQLiteConnection(database, cleanup_allowed);
        return false;
    }
    return true;
}

bool CloseSQLiteConnection(sqlite3*& database) noexcept
{
    if (!database) {
        return true;
    }
    if (ConsumeCloseFailure()) {
        LogPrintf("SQLiteDatabase: Injected connection close failure.\n");
        return false;
    }
    const int result = sqlite3_close(database);
    if (result == SQLITE_OK) {
        database = nullptr;
        return true;
    }
    LogSQLiteError("SQLiteDatabase: Failed to close connection", database, result);
    return false;
}

void AbandonSQLiteConnection(sqlite3*& database) noexcept
{
    if (!database) {
        return;
    }
    g_sqlite_has_abandoned_connection.store(true);
    {
        std::lock_guard<std::mutex> lock(g_sqlite_mutex);
        ++g_sqlite_abandoned_connection_count;
        if (!g_sqlite_first_abandoned_connection) {
            g_sqlite_first_abandoned_connection = database;
        }
    }
    LogPrintf(
        "SQLiteDatabase: Abandoning a connection that could not be closed; "
        "SQLite will remain initialized until process exit.\n");
    // The first pointer is retained for diagnostics and test recovery without
    // allocating in this noexcept failure path. Any later connection is
    // deliberately leaked as well; the lifecycle quarantine prevents
    // sqlite3_shutdown() and new SQLite owners.
    database = nullptr;
}

bool CloseOrAbandonSQLiteConnection(
    sqlite3*& database,
    bool* cleanup_allowed) noexcept
{
    if (CloseSQLiteConnection(database)) {
        return true;
    }
    if (cleanup_allowed) {
        *cleanup_allowed = false;
    }
    AbandonSQLiteConnection(database);
    return false;
}

bool CreateSchema(sqlite3* database, std::string& error)
{
    if (!ExecuteSQL(database, "BEGIN IMMEDIATE TRANSACTION", &error)) {
        return false;
    }

    const int32_t signed_application_id = static_cast<int32_t>(ExpectedApplicationId());
    const std::string application_statement =
        strprintf("PRAGMA application_id = %d", signed_application_id);
    const std::string version_statement =
        strprintf("PRAGMA user_version = %d", WALLET_SCHEMA_VERSION);
    const bool created =
        ExecuteSQL(
            database,
            "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)",
            &error) &&
        ExecuteSQL(database, application_statement.c_str(), &error) &&
        ExecuteSQL(database, version_statement.c_str(), &error);
    if (!created) {
        ExecuteSQL(database, "ROLLBACK TRANSACTION");
        return false;
    }
    if (!ExecuteSQL(database, "COMMIT TRANSACTION", &error)) {
        ExecuteSQL(database, "ROLLBACK TRANSACTION");
        return false;
    }
    return true;
}

bool GetPathStatus(
    const fs::path& path,
    fs::file_status& status,
    std::string& error)
{
    try {
        status = fs::symlink_status(path);
        return true;
    } catch (const fs::filesystem_error& filesystem_error) {
        error = strprintf(
            "Failed to inspect SQLite wallet path '%s': %s",
            path.string(),
            filesystem_error.what());
        return false;
    }
}

bool VerifySQLiteHeaderDescriptor(
    int descriptor,
    const fs::path& path,
    SQLiteFileIdentity& identity,
    std::string& error)
{
#ifdef WIN32
    (void)descriptor;
    (void)identity;
    error = strprintf(
        "Cannot verify SQLite wallet '%s' without following reparse points on Windows.",
        path.string());
    return false;
#else
    identity = {};
    std::array<unsigned char, 100> header{};
    size_t offset = 0;
    int failure = 0;
    struct stat metadata{};
    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode)) {
        failure = errno != 0 ? errno : EINVAL;
    } else if (metadata.st_uid != geteuid() ||
               metadata.st_nlink != 1 ||
               (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        error = strprintf(
            "Refusing SQLite wallet '%s': the database must be an "
            "owner-private, single-link regular file.",
            path.string());
        return false;
    } else {
        identity.device = metadata.st_dev;
        identity.inode = metadata.st_ino;
        identity.valid = true;
    }
    while (failure == 0 && offset < header.size()) {
        const ssize_t count = pread(
            descriptor,
            header.data() + offset,
            header.size() - offset,
            static_cast<off_t>(offset));
        if (count > 0) {
            offset += static_cast<size_t>(count);
        } else if (count == 0) {
            break;
        } else if (errno != EINTR) {
            failure = errno;
        }
    }
    if (failure != 0) {
        error = strprintf(
            "Failed to read SQLite wallet header '%s': %s",
            path.string(),
            std::strerror(failure));
        return false;
    }
    if (offset != header.size()) {
        error = strprintf(
            "SQLite wallet '%s' has a truncated database header.",
            path.string());
        return false;
    }

    static constexpr unsigned char SQLITE_MAGIC[]{
        'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f',
        'o', 'r', 'm', 'a', 't', ' ', '3', '\0'};
    if (!std::equal(
            SQLITE_MAGIC,
            SQLITE_MAGIC + sizeof(SQLITE_MAGIC),
            header.begin())) {
        error = strprintf(
            "SQLite wallet '%s' has an invalid database header.",
            path.string());
        return false;
    }
    if (header[18] != 1 || header[19] != 1) {
        error = strprintf(
            "SQLite wallet '%s' uses unsupported WAL journal header bytes.",
            path.string());
        return false;
    }

    const uint32_t user_version = ReadBE32(header.data() + 60);
    if (user_version != static_cast<uint32_t>(WALLET_SCHEMA_VERSION)) {
        error = strprintf(
            "SQLite wallet '%s' has schema version %u; expected %d.",
            path.string(),
            user_version,
            WALLET_SCHEMA_VERSION);
        return false;
    }
    const uint32_t application_id = ReadBE32(header.data() + 68);
    if (application_id != ExpectedApplicationId()) {
        error = strprintf(
            "SQLite wallet '%s' has application ID %u; expected %u for the active network.",
            path.string(),
            application_id,
            ExpectedApplicationId());
        return false;
    }
    return true;
#endif
}

bool PreflightSQLiteHeader(
    const fs::path& path,
    SQLiteFileIdentity& identity,
    std::string& error,
    int* retained_descriptor = nullptr)
{
#ifdef WIN32
    (void)retained_descriptor;
    return VerifySQLiteHeaderDescriptor(-1, path, identity, error);
#else
    int flags = retained_descriptor ? O_RDWR : O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int descriptor = open(path.string().c_str(), flags);
    if (descriptor < 0) {
        error = strprintf(
            "Failed to preflight SQLite wallet '%s': %s",
            path.string(),
            std::strerror(errno));
        return false;
    }

    if (retained_descriptor &&
        flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
        const int saved_errno = errno;
        close(descriptor);
        error = strprintf(
            "Unable to claim SQLite wallet '%s'; another Firo process may "
            "already own it: %s",
            path.string(),
            std::strerror(saved_errno));
        return false;
    }

    if (!VerifySQLiteHeaderDescriptor(
            descriptor,
            path,
            identity,
            error)) {
        close(descriptor);
        return false;
    }

    if (retained_descriptor) {
        *retained_descriptor = descriptor;
        return true;
    }
    if (close(descriptor) != 0) {
        error = strprintf(
            "Failed to close SQLite wallet preflight descriptor '%s': %s",
            path.string(),
            std::strerror(errno));
        return false;
    }
    return true;
#endif
}

bool CheckAuxiliaryFiles(
    const fs::path& path,
    bool allow_regular_journal,
    std::string& error)
{
    const fs::path journal_path(path.string() + "-journal");
    fs::file_status journal_status;
    if (!GetPathStatus(journal_path, journal_status, error)) {
        return false;
    }
    if (journal_status.type() != fs::file_not_found &&
        (!allow_regular_journal || journal_status.type() != fs::regular_file)) {
        error = strprintf(
            "Refusing SQLite wallet '%s': its rollback journal is not an allowed regular file.",
            path.string());
        return false;
    }
#ifndef WIN32
    if (journal_status.type() == fs::regular_file) {
        struct stat journal_metadata{};
        if (lstat(journal_path.string().c_str(), &journal_metadata) != 0 ||
            !S_ISREG(journal_metadata.st_mode) ||
            journal_metadata.st_uid != geteuid() ||
            journal_metadata.st_nlink != 1 ||
            (journal_metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
            error = strprintf(
                "Refusing SQLite wallet '%s': its rollback journal must be "
                "an owner-private, single-link regular file.",
                path.string());
            return false;
        }
    }
#endif

    for (const char* suffix : {"-wal", "-shm"}) {
        const fs::path auxiliary_path(path.string() + suffix);
        fs::file_status auxiliary_status;
        if (!GetPathStatus(auxiliary_path, auxiliary_status, error)) {
            return false;
        }
        if (auxiliary_status.type() != fs::file_not_found) {
            error = strprintf(
                "Refusing SQLite wallet '%s': unexpected '%s' state exists.",
                path.string(),
                suffix);
            return false;
        }
    }
    return true;
}

enum class CandidateResult {
    SUCCESS,
    ERROR,
};

struct OwnedCandidate {
    fs::path path;
    SQLiteFileIdentity identity;
    int descriptor{-1};
    bool valid{false};
    bool cleanup_allowed{true};

    ~OwnedCandidate()
    {
        if (descriptor >= 0) {
#ifdef WIN32
            _close(descriptor);
#else
            close(descriptor);
#endif
        }
    }

    OwnedCandidate() = default;
    OwnedCandidate(const OwnedCandidate&) = delete;
    OwnedCandidate& operator=(const OwnedCandidate&) = delete;
};

CandidateResult CreateOwnedCandidate(
    const fs::path& final_path,
    OwnedCandidate& candidate,
    std::string& error)
{
#ifdef WIN32
    error = strprintf(
        "Secure SQLite candidate creation for '%s' is unavailable on Windows: "
        "an owner-only DACL and reparse-safe publication are required.",
        final_path.string());
    return CandidateResult::ERROR;
#else
    static std::atomic<uint64_t> candidate_counter{0};
    const fs::path parent =
        final_path.parent_path().empty() ? fs::path(".") : final_path.parent_path();
    for (int attempt = 0; attempt < 128; ++attempt) {
        const std::string candidate_name = strprintf(
            ".%s.sqlite-%d-%d-%d.tmp",
            final_path.filename().string(),
            static_cast<int64_t>(getpid()),
            GetTimeMicros(),
            candidate_counter.fetch_add(1));
        candidate.path = parent / candidate_name;

        int flags = O_CREAT | O_EXCL | O_RDWR;
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
        const int descriptor =
            open(candidate.path.string().c_str(), flags, S_IRUSR | S_IWUSR);
        if (descriptor < 0) {
            if (errno == EEXIST) {
                continue;
            }
            error = strprintf(
                "Failed to create SQLite candidate '%s': %s",
                candidate.path.string(),
                std::strerror(errno));
            return CandidateResult::ERROR;
        }

        struct stat metadata{};
        int saved_errno = 0;
        bool valid = fstat(descriptor, &metadata) == 0;
        if (!valid) {
            saved_errno = errno;
        } else if (!S_ISREG(metadata.st_mode) ||
                   metadata.st_nlink != 1) {
            valid = false;
            saved_errno = EINVAL;
        } else {
            candidate.identity.device = metadata.st_dev;
            candidate.identity.inode = metadata.st_ino;
            candidate.identity.valid = true;
            candidate.valid = true;
            if (fchmod(descriptor, S_IRUSR | S_IWUSR) != 0) {
                valid = false;
                saved_errno = errno;
            } else if (flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
                valid = false;
                saved_errno = errno;
            }
        }
        if (!valid) {
            error = strprintf(
                "Failed to secure SQLite candidate '%s': %s",
                candidate.path.string(),
                std::strerror(saved_errno));
            close(descriptor);
            if (candidate.valid &&
                PathIdentityMatches(candidate.path, candidate.identity)) {
                unlink(candidate.path.string().c_str());
            }
            return CandidateResult::ERROR;
        }

        candidate.descriptor = descriptor;
        return CandidateResult::SUCCESS;
    }
    error = strprintf(
        "Failed to allocate a collision-free SQLite candidate for '%s'.",
        final_path.string());
    return CandidateResult::ERROR;
#endif
}

bool CandidateIdentityMatches(const OwnedCandidate& candidate) noexcept
{
#ifdef WIN32
    return false;
#else
    if (!candidate.valid) {
        return false;
    }
    return PathIdentityMatches(candidate.path, candidate.identity);
#endif
}

bool SyncDirectory(const fs::path& directory, std::string& error)
{
#ifdef WIN32
    error = "Secure SQLite directory publication sync is unavailable on Windows.";
    return false;
#else
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
    const int descriptor = open(directory.string().c_str(), flags);
    if (descriptor < 0) {
        error = strprintf(
            "Failed to open SQLite publication directory '%s': %s",
            directory.string(),
            std::strerror(errno));
        return false;
    }
    bool success = true;
    if (fsync(descriptor) != 0 &&
        errno != EINVAL &&
        errno != ENOTSUP) {
        error = strprintf(
            "Failed to synchronize SQLite publication directory '%s': %s",
            directory.string(),
            std::strerror(errno));
        success = false;
    }
    if (close(descriptor) != 0 && success) {
        error = strprintf(
            "Failed to close SQLite publication directory '%s': %s",
            directory.string(),
            std::strerror(errno));
        success = false;
    }
    return success;
#endif
}

bool RemoveOwnedPath(
    const fs::path& path,
    const SQLiteFileIdentity& identity,
    std::string& error) noexcept
{
#ifdef WIN32
    (void)path;
    (void)identity;
    error = "Secure removal of an owned SQLite path is unavailable on Windows.";
    return false;
#else
    if (!PathIdentityMatches(path, identity)) {
        error = strprintf(
            "Refusing to remove SQLite path '%s': its ownership identity changed.",
            path.string());
        return false;
    }
    if (unlink(path.string().c_str()) != 0) {
        error = strprintf(
            "Failed to remove owned SQLite path '%s': %s",
            path.string(),
            std::strerror(errno));
        return false;
    }
    return true;
#endif
}

void RemoveOwnedCandidate(const OwnedCandidate& candidate) noexcept
{
#ifndef WIN32
    std::string error;
    struct stat metadata{};
    if (lstat(candidate.path.string().c_str(), &metadata) != 0) {
        if (errno != ENOENT) {
            LogPrintf(
                "SQLiteDatabase: Failed to inspect candidate '%s': %s\n",
                candidate.path.string(),
                std::strerror(errno));
        }
        return;
    }
    if (!candidate.cleanup_allowed ||
        g_sqlite_has_abandoned_connection.load()) {
        LogPrintf(
            "SQLiteDatabase: Leaving candidate '%s' because a connection "
            "lifecycle failure made cleanup unsafe.\n",
            candidate.path.string());
        return;
    }
    if (!candidate.valid ||
        !PathIdentityMatches(candidate.path, candidate.identity)) {
        LogPrintf(
            "SQLiteDatabase: Leaving candidate '%s' because its ownership identity changed.\n",
            candidate.path.string());
        return;
    }

    if (!CheckAuxiliaryFiles(candidate.path, false, error)) {
        LogPrintf(
            "SQLiteDatabase: Leaving candidate '%s' because auxiliary state "
            "exists and its provenance cannot be proven: %s\n",
            candidate.path.string(),
            error);
        return;
    }
    if (!RemoveOwnedPath(candidate.path, candidate.identity, error)) {
        LogPrintf(
            "SQLiteDatabase: Failed to remove candidate '%s': %s\n",
            candidate.path.string(),
            error);
        return;
    }

    const fs::path parent =
        candidate.path.parent_path().empty() ?
            fs::path(".") :
            candidate.path.parent_path();
    if (!SyncDirectory(parent, error)) {
        LogPrintf(
            "SQLiteDatabase: Failed to synchronize candidate cleanup: %s\n",
            error);
    }
#else
    (void)candidate;
#endif
}

bool RemovePublishedCandidate(
    const OwnedCandidate& candidate,
    const fs::path& final_path,
    std::string& error) noexcept
{
#ifdef WIN32
    (void)candidate;
    (void)final_path;
    error = "Secure removal of a published SQLite candidate is unavailable on Windows.";
    return false;
#else
    struct stat metadata{};
    if (lstat(final_path.string().c_str(), &metadata) != 0) {
        if (errno == ENOENT) {
            return true;
        }
        error = strprintf(
            "Failed to inspect published SQLite path '%s': %s",
            final_path.string(),
            std::strerror(errno));
        return false;
    }
    if (!candidate.cleanup_allowed ||
        g_sqlite_has_abandoned_connection.load()) {
        error = strprintf(
            "Refusing to remove published SQLite path '%s' after a "
            "connection lifecycle failure.",
            final_path.string());
        return false;
    }
    if (!candidate.valid ||
        !PathIdentityMatches(final_path, candidate.identity)) {
        error = strprintf(
            "Refusing to remove published SQLite path '%s': its ownership identity changed.",
            final_path.string());
        return false;
    }

    if (!CheckAuxiliaryFiles(final_path, false, error)) {
        error = strprintf(
            "Refusing to remove published SQLite path '%s' while auxiliary "
            "state of unproven provenance exists: %s",
            final_path.string(),
            error);
        return false;
    }
    if (!RemoveOwnedPath(final_path, candidate.identity, error)) {
        return false;
    }

    const fs::path parent =
        final_path.parent_path().empty() ?
            fs::path(".") :
            final_path.parent_path();
    std::string sync_error;
    if (!SyncDirectory(parent, sync_error)) {
        error = sync_error;
        return false;
    }
    return true;
#endif
}

enum class PublishResult {
    SUCCESS,
    EXISTS,
    ERROR,
    PUBLISHED_ERROR,
};

PublishResult PublishCandidate(
    const OwnedCandidate& candidate,
    const fs::path& final_path,
    std::string& error)
{
#ifdef WIN32
    error = "Secure SQLite no-replace publication is unavailable on Windows.";
    return PublishResult::ERROR;
#else
    if (!CandidateIdentityMatches(candidate)) {
        error = strprintf(
            "Refusing to publish SQLite candidate '%s': its identity changed.",
            candidate.path.string());
        return PublishResult::ERROR;
    }

    struct stat candidate_metadata{};
    int candidate_error = 0;
    if (candidate.descriptor < 0) {
        candidate_error = EBADF;
    } else if (fstat(candidate.descriptor, &candidate_metadata) != 0) {
        candidate_error = errno;
    } else if (!S_ISREG(candidate_metadata.st_mode) ||
               candidate_metadata.st_dev != candidate.identity.device ||
               candidate_metadata.st_ino != candidate.identity.inode ||
               candidate_metadata.st_uid != geteuid() ||
               candidate_metadata.st_nlink != 1 ||
               (candidate_metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        candidate_error = EINVAL;
    } else if (fsync(candidate.descriptor) != 0) {
        candidate_error = errno;
    }
    if (candidate_error != 0) {
        error = strprintf(
            "Failed to synchronize owned SQLite candidate '%s': %s",
            candidate.path.string(),
            std::strerror(candidate_error));
        return PublishResult::ERROR;
    }
    if (!CheckAuxiliaryFiles(final_path, false, error)) {
        return PublishResult::ERROR;
    }

#if defined(__linux__) && defined(SYS_renameat2)
    int rename_result = static_cast<int>(syscall(
        SYS_renameat2,
        AT_FDCWD,
        candidate.path.string().c_str(),
        AT_FDCWD,
        final_path.string().c_str(),
        1U /* RENAME_NOREPLACE */));
#elif defined(__APPLE__)
    int rename_result = renameatx_np(
        AT_FDCWD,
        candidate.path.string().c_str(),
        AT_FDCWD,
        final_path.string().c_str(),
        RENAME_EXCL);
#else
    error =
        "Atomic no-replace SQLite publication is unavailable on this platform.";
    return PublishResult::ERROR;
#endif
    if (rename_result == 0 &&
        ConsumePublishErrorAfterRename()) {
        errno = EIO;
        rename_result = -1;
    }
    if (rename_result != 0) {
        const int rename_error = errno;
        const bool final_matches =
            PathIdentityMatches(
                final_path,
                candidate.identity);
        const bool source_matches =
            PathIdentityMatches(
                candidate.path,
                candidate.identity);
        if (final_matches) {
            error = strprintf(
                "SQLite candidate publication as '%s' reported an error, "
                "but the final path now names the owned candidate: %s",
                final_path.string(),
                std::strerror(rename_error));
            return PublishResult::PUBLISHED_ERROR;
        }
        if (rename_error == EEXIST && source_matches) {
            return PublishResult::EXISTS;
        }
        error = strprintf(
            "Failed to atomically publish SQLite candidate '%s' as '%s': %s",
            candidate.path.string(),
            final_path.string(),
            std::strerror(rename_error));
        return PublishResult::ERROR;
    }

    struct stat published{};
    if (lstat(final_path.string().c_str(), &published) != 0 ||
        !S_ISREG(published.st_mode) ||
        published.st_dev != candidate.identity.device ||
        published.st_ino != candidate.identity.inode ||
        published.st_uid != geteuid() ||
        published.st_nlink != 1 ||
        (published.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        error = strprintf(
            "Published SQLite wallet '%s' does not match its owned candidate.",
            final_path.string());
        return PublishResult::PUBLISHED_ERROR;
    }

    const fs::path parent =
        final_path.parent_path().empty() ? fs::path(".") : final_path.parent_path();
    if (!SyncDirectory(parent, error)) {
        return PublishResult::PUBLISHED_ERROR;
    }
    return PublishResult::SUCCESS;
#endif
}

class SQLiteDatabase;

class SQLiteCursor final : public DatabaseCursor
{
private:
    std::shared_lock<std::shared_mutex> m_connection_lock;
    sqlite3_stmt* m_statement{nullptr};
    std::vector<unsigned char> m_start_key;

public:
    SQLiteCursor(
        std::shared_lock<std::shared_mutex> connection_lock,
        sqlite3_stmt* statement,
        std::vector<unsigned char> start_key) noexcept
        : m_connection_lock(std::move(connection_lock)),
          m_statement(statement),
          m_start_key(std::move(start_key))
    {
    }

    ~SQLiteCursor() noexcept override
    {
        if (m_statement) {
            sqlite3_clear_bindings(m_statement);
            sqlite3_reset(m_statement);
            const int result = sqlite3_finalize(m_statement);
            if (result != SQLITE_OK) {
                LogPrintf("SQLiteCursor: Failed to finalize cursor (error %d).\n", result);
            }
        }
        if (!m_start_key.empty()) {
            memory_cleanse(m_start_key.data(), m_start_key.size());
        }
    }

    Status Next(CDataStream& key, CDataStream& value) override
    {
        if (!m_statement) {
            return Status::FAIL;
        }
        const int result = sqlite3_step(m_statement);
        if (result == SQLITE_DONE) {
            return Status::DONE;
        }
        if (result != SQLITE_ROW ||
            sqlite3_column_type(m_statement, 0) != SQLITE_BLOB ||
            sqlite3_column_type(m_statement, 1) != SQLITE_BLOB) {
            LogPrintf("SQLiteCursor: Failed to read a BLOB record (error %d).\n", result);
            return Status::FAIL;
        }

        key.SetType(SER_DISK);
        key.clear();
        const int key_size = sqlite3_column_bytes(m_statement, 0);
        const void* const key_data = sqlite3_column_blob(m_statement, 0);
        if (key_size > 0) {
            if (!key_data) {
                return Status::FAIL;
            }
            key.write(static_cast<const char*>(key_data), key_size);
        }

        value.SetType(SER_DISK);
        value.clear();
        const int value_size = sqlite3_column_bytes(m_statement, 1);
        const void* const value_data = sqlite3_column_blob(m_statement, 1);
        if (value_size > 0) {
            if (!value_data) {
                return Status::FAIL;
            }
            value.write(static_cast<const char*>(value_data), value_size);
        }
        return Status::MORE;
    }
};

class SQLiteBatch;

class SQLiteDatabase final : public WalletDatabase
{
    friend class SQLiteBatch;

private:
    const std::string m_filename;
    const fs::path m_path;
    sqlite3* m_database{nullptr};
    int m_identity_descriptor{-1};
    SQLiteFileIdentity m_identity;
    bool m_sqlite_acquired{false};
    bool* m_failed_creation_cleanup_allowed{nullptr};
    std::atomic<bool> m_usable{true};
    std::atomic<bool> m_poisoned{false};

    mutable std::shared_mutex m_connection_mutex;
    std::mutex m_writer_mutex;
    std::mutex m_state_mutex;
    size_t m_batch_count{0};
    bool m_open{false};

    void Poison() noexcept
    {
        m_poisoned.store(true);
        m_usable.store(false);
    }

    bool OpenExistingLocked(
        std::string& error,
        bool* cleanup_allowed = nullptr)
    {
        if (m_poisoned.load() || m_database) {
            error = strprintf(
                "SQLite wallet '%s' is quarantined after an unrecoverable connection error.",
                m_filename);
            Poison();
            return false;
        }
        SQLiteFileIdentity identity;
        if (m_identity_descriptor < 0) {
            int descriptor = -1;
            if (!PreflightSQLiteHeader(
                    m_path,
                    identity,
                    error,
                    &descriptor)) {
                Poison();
                return false;
            }
            m_identity_descriptor = descriptor;
            m_identity = identity;
        } else if (!VerifySQLiteHeaderDescriptor(
                       m_identity_descriptor,
                       m_path,
                       identity,
                       error) ||
                   !PathIdentityMatches(m_path, identity) ||
                   !DescriptorIdentityMatches(
                       m_identity_descriptor,
                       m_identity)) {
            if (error.empty()) {
                error = strprintf(
                    "Refusing SQLite wallet '%s': its retained file identity changed.",
                    m_path.string());
            }
            Poison();
            return false;
        }
        if (!CheckAuxiliaryFiles(m_path, true, error) ||
            !OpenSQLiteConnection(
                m_path,
                m_database,
                error,
                &m_identity,
                cleanup_allowed)) {
            Poison();
            return false;
        }
        if (!VerifyDatabase(m_database, error)) {
            error = strprintf(
                "Failed to verify SQLite wallet '%s': %s",
                m_path.string(),
                error);
            CloseOrAbandonSQLiteConnection(
                m_database,
                cleanup_allowed);
            Poison();
            return false;
        }
        if (!SetConnectionPragmas(m_database, error)) {
            CloseOrAbandonSQLiteConnection(
                m_database,
                cleanup_allowed);
            Poison();
            return false;
        }
        if (!ConnectionIdentityMatches(
                m_database,
                m_path,
                m_identity,
                error) ||
            !VerifyDatabase(m_database, error)) {
            error = strprintf(
                "Failed to verify locked SQLite wallet '%s': %s",
                m_path.string(),
                error);
            CloseOrAbandonSQLiteConnection(
                m_database,
                cleanup_allowed);
            Poison();
            return false;
        }
        m_usable.store(true);
        return true;
    }

    bool CreateLocked(
        OwnedCandidate& candidate,
        PublishResult& publish_result,
        std::string& error)
    {
        if (!OpenSQLiteConnection(
                candidate.path,
                m_database,
                error,
                &candidate.identity,
                &candidate.cleanup_allowed) ||
            !SetConnectionPragmas(m_database, error) ||
            !ConnectionIdentityMatches(
                m_database,
                candidate.path,
                candidate.identity,
                error) ||
            !CreateSchema(m_database, error) ||
            !VerifyDatabase(m_database, error)) {
            CloseOrAbandonSQLiteConnection(
                m_database,
                &candidate.cleanup_allowed);
            Poison();
            return false;
        }

        if (!CloseOrAbandonSQLiteConnection(
                m_database,
                &candidate.cleanup_allowed)) {
            Poison();
            return false;
        }
        if (!CheckAuxiliaryFiles(candidate.path, false, error)) {
            Poison();
            return false;
        }
        publish_result = PublishCandidate(candidate, m_path, error);
        if (publish_result != PublishResult::SUCCESS) {
            Poison();
            return false;
        }
        if (!DescriptorIdentityMatches(
                candidate.descriptor,
                candidate.identity)) {
            error = strprintf(
                "Published SQLite wallet '%s' lost its retained candidate identity.",
                m_path.string());
            Poison();
            return false;
        }
#ifdef WIN32
        m_identity_descriptor = _dup(candidate.descriptor);
#elif defined(F_DUPFD_CLOEXEC)
        m_identity_descriptor =
            fcntl(candidate.descriptor, F_DUPFD_CLOEXEC, 0);
#else
        error =
            "Unable to retain a close-on-exec SQLite wallet identity descriptor.";
        Poison();
        return false;
#endif
        if (m_identity_descriptor < 0) {
            error = strprintf(
                "Failed to retain the published SQLite wallet identity for '%s': %s",
                m_path.string(),
                std::strerror(errno));
            Poison();
            return false;
        }
        m_identity = candidate.identity;
        if (!OpenExistingLocked(
                error,
                &candidate.cleanup_allowed)) {
            Poison();
            return false;
        }
        if (ConsumePostPublishFailure()) {
            error = "Injected failure after publishing SQLite wallet candidate.";
            CloseOrAbandonSQLiteConnection(
                m_database,
                &candidate.cleanup_allowed);
            Poison();
            return false;
        }
        m_usable.store(true);
        return true;
    }

    bool ResetAfterFailedRollback()
    {
        {
            std::lock_guard<std::mutex> state_lock(m_state_mutex);
            m_open = false;
        }
        if (!CloseOrAbandonSQLiteConnection(m_database)) {
            Poison();
            LogPrintf(
                "SQLiteDatabase: Quarantining '%s' after a busy connection close.\n",
                m_filename);
            return false;
        }

        std::string error;
        if (!OpenExistingLocked(error)) {
            LogPrintf(
                "SQLiteDatabase: Failed to recover connection for '%s': %s\n",
                m_filename,
                error);
            return false;
        }
        {
            std::lock_guard<std::mutex> state_lock(m_state_mutex);
            m_open = true;
        }
        return true;
    }

    void BatchClosed() noexcept
    {
        std::lock_guard<std::mutex> lock(m_state_mutex);
        if (m_batch_count != 0) {
            --m_batch_count;
        }
    }

public:
    SQLiteDatabase(std::string filename, fs::path path)
        : m_filename(std::move(filename)),
          m_path(std::move(path))
    {
        std::string error;
        if (!AcquireSQLite(error)) {
            throw std::runtime_error(error);
        }
        m_sqlite_acquired = true;
    }

    ~SQLiteDatabase() noexcept override
    {
        try {
            std::unique_lock<std::mutex> writer_lock(m_writer_mutex);
            std::unique_lock<std::shared_mutex> connection_lock(m_connection_mutex);
            CloseOrAbandonSQLiteConnection(
                m_database,
                m_failed_creation_cleanup_allowed);
            if (m_identity_descriptor >= 0) {
#ifdef WIN32
                _close(m_identity_descriptor);
#else
                close(m_identity_descriptor);
#endif
                m_identity_descriptor = -1;
            }
        } catch (const std::exception& exception) {
            if (m_failed_creation_cleanup_allowed) {
                *m_failed_creation_cleanup_allowed = false;
            }
            if (m_database) {
                AbandonSQLiteConnection(m_database);
            } else {
                g_sqlite_has_abandoned_connection.store(true);
            }
            LogPrintf("SQLiteDatabase: Exception during destruction: %s\n", exception.what());
        } catch (...) {
            if (m_failed_creation_cleanup_allowed) {
                *m_failed_creation_cleanup_allowed = false;
            }
            if (m_database) {
                AbandonSQLiteConnection(m_database);
            } else {
                g_sqlite_has_abandoned_connection.store(true);
            }
            LogPrintf("SQLiteDatabase: Unknown exception during destruction.\n");
        }
        if (m_sqlite_acquired) {
            ReleaseSQLite();
        }
    }

    bool InitializeExisting(std::string& error)
    {
        std::unique_lock<std::shared_mutex> lock(m_connection_mutex);
        const bool initialized = OpenExistingLocked(error);
        std::lock_guard<std::mutex> state_lock(m_state_mutex);
        m_open = initialized;
        return initialized;
    }

    bool InitializeCreated(
        OwnedCandidate& candidate,
        PublishResult& publish_result,
        std::string& error)
    {
        m_failed_creation_cleanup_allowed =
            &candidate.cleanup_allowed;
        std::unique_lock<std::shared_mutex> lock(m_connection_mutex);
        const bool initialized =
            CreateLocked(candidate, publish_result, error);
        if (initialized) {
            m_failed_creation_cleanup_allowed = nullptr;
        }
        std::lock_guard<std::mutex> state_lock(m_state_mutex);
        m_open = initialized;
        return initialized;
    }

    const std::string& Filename() const override { return m_filename; }
    DatabaseFormat Format() const override { return DatabaseFormat::SQLITE; }
    std::unique_ptr<DatabaseBatch> MakeBatch(const DatabaseBatchOptions& options) override;
    bool Rewrite(const char* skip) override;
    bool Backup(const std::string& destination) override;
    bool PeriodicFlush() override;
    void Flush(bool shutdown) override;
};

enum class SQLiteTransactionState {
    NONE,
    ACTIVE,
    AUTO_ROLLED_BACK,
};

class SQLiteBatch final : public DatabaseBatch
{
private:
    SQLiteDatabase& m_database;
    const bool m_read_only;
    const bool m_flush_on_close;
    std::unique_ptr<SQLiteStatementExecutor> m_executor{
        std::make_unique<SQLiteStatementExecutor>()};
    std::unique_lock<std::mutex> m_transaction_writer;
    std::unique_lock<std::shared_mutex> m_transaction_connection;
    std::atomic<SQLiteTransactionState> m_transaction{
        SQLiteTransactionState::NONE};
    std::atomic<bool> m_closed{false};

    bool IsActive() const
    {
        return m_transaction.load() == SQLiteTransactionState::ACTIVE;
    }

    bool IsQuarantined() const
    {
        return m_transaction.load() ==
               SQLiteTransactionState::AUTO_ROLLED_BACK;
    }

    void ReleaseTransactionGates() noexcept
    {
        if (m_transaction.load() != SQLiteTransactionState::ACTIVE) {
            if (m_transaction_connection.owns_lock()) {
                m_transaction_connection.unlock();
            }
            if (m_transaction_writer.owns_lock()) {
                m_transaction_writer.unlock();
            }
        }
    }

    void ReconcileAfterError()
    {
        if (IsActive() &&
            m_database.m_database &&
            sqlite3_get_autocommit(m_database.m_database) != 0) {
            m_transaction.store(SQLiteTransactionState::AUTO_ROLLED_BACK);
        }
    }

    bool HandleBeginExecutorException() noexcept
    {
        LogPrintf(
            "SQLiteBatch: Statement executor threw while beginning a transaction.\n");
        if (m_database.m_database &&
            sqlite3_get_autocommit(m_database.m_database) == 0) {
            m_transaction.store(SQLiteTransactionState::ACTIVE);
            try {
                if (!m_database.ResetAfterFailedRollback()) {
                    m_database.Poison();
                }
            } catch (...) {
                m_database.Poison();
            }
        }
        m_transaction.store(SQLiteTransactionState::NONE);
        ReleaseTransactionGates();
        return false;
    }

    bool HandleIndeterminateExecutorException(
        const char* operation) noexcept
    {
        LogPrintf(
            "SQLiteBatch: Statement executor threw while %s; quarantining the database.\n",
            operation);
        m_database.Poison();
        m_transaction.store(SQLiteTransactionState::NONE);
        ReleaseTransactionGates();
        return false;
    }

    class TransactionGateReleaser final
    {
    private:
        SQLiteBatch& m_batch;

    public:
        explicit TransactionGateReleaser(SQLiteBatch& batch)
            : m_batch(batch)
        {
        }

        ~TransactionGateReleaser()
        {
            m_batch.ReleaseTransactionGates();
        }
    };

    bool CanUseConnection() const
    {
        return !m_closed.load() &&
               !IsQuarantined() &&
               m_database.m_database &&
               m_database.m_usable.load() &&
               !m_database.m_poisoned.load();
    }

    bool ReadRaw(CDataStream&& key, CDataStream& value) override
    {
        StreamCleanser key_cleanser(key);
        if (m_closed.load() || IsQuarantined()) {
            return false;
        }

        std::shared_lock<std::shared_mutex> connection_lock;
        if (!IsActive()) {
            connection_lock =
                std::shared_lock<std::shared_mutex>(m_database.m_connection_mutex);
        }
        TransactionGateReleaser gate_releaser(*this);
        if (!CanUseConnection()) {
            return false;
        }

        SQLiteStatement statement;
        if (!PrepareStatement(
                m_database.m_database,
                "SELECT value FROM main WHERE key = ?",
                statement,
                "SQLiteBatch: Failed to prepare read") ||
            !BindBlob(statement.Get(), 1, key, "key")) {
            ReconcileAfterError();
            return false;
        }

        const int result = sqlite3_step(statement.Get());
        if (result == SQLITE_DONE) {
            return false;
        }
        if (result != SQLITE_ROW ||
            sqlite3_column_type(statement.Get(), 0) != SQLITE_BLOB) {
            ReconcileAfterError();
            LogSQLiteError(
                "SQLiteBatch: Failed to read record",
                m_database.m_database,
                result);
            return false;
        }

        value.SetType(SER_DISK);
        value.clear();
        const int size = sqlite3_column_bytes(statement.Get(), 0);
        const void* const data = sqlite3_column_blob(statement.Get(), 0);
        if (size > 0) {
            if (!data) {
                return false;
            }
            value.write(static_cast<const char*>(data), size);
        }
        return true;
    }

    bool WriteRaw(CDataStream&& key, CDataStream&& value, bool overwrite) override
    {
        StreamCleanser key_cleanser(key);
        StreamCleanser value_cleanser(value);
        if (m_read_only || m_closed.load() || IsQuarantined()) {
            return false;
        }

        std::unique_lock<std::mutex> writer_lock;
        std::unique_lock<std::shared_mutex> connection_lock;
        if (!IsActive()) {
            writer_lock = std::unique_lock<std::mutex>(m_database.m_writer_mutex);
            connection_lock =
                std::unique_lock<std::shared_mutex>(m_database.m_connection_mutex);
        }
        TransactionGateReleaser gate_releaser(*this);
        if (!CanUseConnection()) {
            return false;
        }

        SQLiteStatement statement;
        const char* const sql = overwrite ?
                                    "INSERT INTO main(key, value) VALUES(?, ?) "
                                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value" :
                                    "INSERT INTO main(key, value) VALUES(?, ?)";
        if (!PrepareStatement(
                m_database.m_database,
                sql,
                statement,
                "SQLiteBatch: Failed to prepare write") ||
            !BindBlob(statement.Get(), 1, key, "key") ||
            !BindBlob(statement.Get(), 2, value, "value")) {
            ReconcileAfterError();
            return false;
        }

        const int result = sqlite3_step(statement.Get());
        if (result != SQLITE_DONE) {
            ReconcileAfterError();
            if ((result & 0xff) != SQLITE_CONSTRAINT) {
                LogSQLiteError(
                    "SQLiteBatch: Failed to write record",
                    m_database.m_database,
                    result);
            }
            return false;
        }
        return true;
    }

    bool EraseRaw(CDataStream&& key) override
    {
        StreamCleanser key_cleanser(key);
        if (m_read_only || m_closed.load() || IsQuarantined()) {
            return false;
        }

        std::unique_lock<std::mutex> writer_lock;
        std::unique_lock<std::shared_mutex> connection_lock;
        if (!IsActive()) {
            writer_lock = std::unique_lock<std::mutex>(m_database.m_writer_mutex);
            connection_lock =
                std::unique_lock<std::shared_mutex>(m_database.m_connection_mutex);
        }
        TransactionGateReleaser gate_releaser(*this);
        if (!CanUseConnection()) {
            return false;
        }

        SQLiteStatement statement;
        if (!PrepareStatement(
                m_database.m_database,
                "DELETE FROM main WHERE key = ?",
                statement,
                "SQLiteBatch: Failed to prepare erase") ||
            !BindBlob(statement.Get(), 1, key, "key")) {
            ReconcileAfterError();
            return false;
        }
        const int result = sqlite3_step(statement.Get());
        if (result != SQLITE_DONE) {
            ReconcileAfterError();
            LogSQLiteError(
                "SQLiteBatch: Failed to erase record",
                m_database.m_database,
                result);
            return false;
        }
        return true;
    }

    bool HasRaw(CDataStream&& key) override
    {
        StreamCleanser key_cleanser(key);
        if (m_closed.load() || IsQuarantined()) {
            return false;
        }

        std::shared_lock<std::shared_mutex> connection_lock;
        if (!IsActive()) {
            connection_lock =
                std::shared_lock<std::shared_mutex>(m_database.m_connection_mutex);
        }
        TransactionGateReleaser gate_releaser(*this);
        if (!CanUseConnection()) {
            return false;
        }

        SQLiteStatement statement;
        if (!PrepareStatement(
                m_database.m_database,
                "SELECT 1 FROM main WHERE key = ?",
                statement,
                "SQLiteBatch: Failed to prepare existence query") ||
            !BindBlob(statement.Get(), 1, key, "key")) {
            ReconcileAfterError();
            return false;
        }
        const int result = sqlite3_step(statement.Get());
        if (result == SQLITE_ROW) {
            return true;
        }
        if (result != SQLITE_DONE) {
            ReconcileAfterError();
            LogSQLiteError(
                "SQLiteBatch: Failed to query record existence",
                m_database.m_database,
                result);
        }
        return false;
    }

public:
    SQLiteBatch(
        SQLiteDatabase& database,
        const DatabaseBatchOptions& options)
        : m_database(database),
          m_read_only(options.mode == DatabaseBatchMode::READ_ONLY),
          m_flush_on_close(options.flush_on_close)
    {
    }

    ~SQLiteBatch() noexcept override { Close(); }

    bool EnsureVersion()
    {
        if (m_read_only || m_closed.load() || IsQuarantined()) {
            return false;
        }

        CDataStream key(SER_DISK, CLIENT_VERSION);
        key << std::string("version");
        CDataStream value(SER_DISK, CLIENT_VERSION);
        value << CLIENT_VERSION;
        StreamCleanser key_cleanser(key);
        StreamCleanser value_cleanser(value);

        std::unique_lock<std::mutex> writer_lock(m_database.m_writer_mutex);
        std::unique_lock<std::shared_mutex> connection_lock(m_database.m_connection_mutex);
        if (!CanUseConnection()) {
            return false;
        }

        SQLiteStatement statement;
        if (!PrepareStatement(
                m_database.m_database,
                "INSERT INTO main(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO NOTHING",
                statement,
                "SQLiteBatch: Failed to prepare wallet version initialization") ||
            !BindBlob(statement.Get(), 1, key, "version key") ||
            !BindBlob(statement.Get(), 2, value, "version value")) {
            return false;
        }
        const int result = sqlite3_step(statement.Get());
        if (result != SQLITE_DONE) {
            LogSQLiteError(
                "SQLiteBatch: Failed to initialize wallet version",
                m_database.m_database,
                result);
            return false;
        }
        return true;
    }

    bool SetExecutor(std::unique_ptr<SQLiteStatementExecutor> executor)
    {
        if (!executor || m_closed.load()) {
            return false;
        }
        m_executor = std::move(executor);
        return true;
    }

    bool GetSynchronousMode(int64_t& mode)
    {
        if (m_closed.load() || IsQuarantined()) {
            return false;
        }
        std::shared_lock<std::shared_mutex> connection_lock;
        if (!IsActive()) {
            connection_lock =
                std::shared_lock<std::shared_mutex>(
                    m_database.m_connection_mutex);
        }
        TransactionGateReleaser gate_releaser(*this);
        if (!CanUseConnection()) {
            return false;
        }

        std::string error;
        const std::optional<int64_t> synchronous = ReadPragmaInteger(
            m_database.m_database,
            "PRAGMA synchronous",
            "SQLite synchronous mode",
            error);
        if (!synchronous) {
            LogPrintf(
                "SQLiteBatch: Failed to read synchronous mode: %s\n",
                error);
            return false;
        }
        mode = *synchronous;
        return true;
    }

    void Flush() override
    {
        if (m_closed.load() || IsQuarantined()) {
            return;
        }

        std::unique_lock<std::mutex> writer_lock;
        std::unique_lock<std::shared_mutex> connection_lock;
        if (!IsActive()) {
            writer_lock = std::unique_lock<std::mutex>(
                m_database.m_writer_mutex,
                std::try_to_lock);
            if (!writer_lock.owns_lock()) {
                return;
            }
            connection_lock =
                std::unique_lock<std::shared_mutex>(
                    m_database.m_connection_mutex,
                    std::try_to_lock);
            if (!connection_lock.owns_lock()) {
                return;
            }
        }
        if (!CanUseConnection()) {
            return;
        }
        const int result = sqlite3_db_cacheflush(m_database.m_database);
        if (result != SQLITE_OK) {
            ReconcileAfterError();
            LogSQLiteError(
                "SQLiteBatch: Failed to flush database cache",
                m_database.m_database,
                result);
        }
        ReleaseTransactionGates();
    }

    void Close() noexcept override
    {
        if (m_closed.exchange(true)) {
            return;
        }
        try {
            if (m_transaction.load() != SQLiteTransactionState::NONE) {
                if (TxnAbort()) {
                    LogPrintf("SQLiteBatch: Aborted transaction during batch close.\n");
                } else if (IsActive()) {
                    LogPrintf("SQLiteBatch: Rollback failed; resetting SQLite connection.\n");
                    m_database.ResetAfterFailedRollback();
                    m_transaction.store(SQLiteTransactionState::NONE);
                    ReleaseTransactionGates();
                }
            }

            if (m_flush_on_close) {
                std::unique_lock<std::mutex> writer_lock(
                    m_database.m_writer_mutex,
                    std::try_to_lock);
                std::unique_lock<std::shared_mutex> connection_lock;
                if (writer_lock.owns_lock()) {
                    connection_lock =
                        std::unique_lock<std::shared_mutex>(
                            m_database.m_connection_mutex,
                            std::try_to_lock);
                }
                if (writer_lock.owns_lock() &&
                    connection_lock.owns_lock() &&
                    m_database.m_database &&
                    m_database.m_usable.load() &&
                    !m_database.m_poisoned.load()) {
                    const int result = sqlite3_db_cacheflush(m_database.m_database);
                    if (result != SQLITE_OK) {
                        LogSQLiteError(
                            "SQLiteBatch: Failed to flush database cache on close",
                            m_database.m_database,
                            result);
                    }
                }
            }
        } catch (const std::exception& exception) {
            LogPrintf("SQLiteBatch: Exception during close: %s\n", exception.what());
            m_database.Poison();
            m_transaction.store(SQLiteTransactionState::NONE);
            ReleaseTransactionGates();
        } catch (...) {
            LogPrintf("SQLiteBatch: Unknown exception during close.\n");
            m_database.Poison();
            m_transaction.store(SQLiteTransactionState::NONE);
            ReleaseTransactionGates();
        }
        if (m_transaction.load() != SQLiteTransactionState::NONE) {
            m_database.Poison();
            m_transaction.store(SQLiteTransactionState::NONE);
            ReleaseTransactionGates();
        }
        m_database.BatchClosed();
    }

    std::unique_ptr<DatabaseCursor> GetCursor() override
    {
        if (m_closed.load() ||
            m_transaction.load() != SQLiteTransactionState::NONE) {
            return nullptr;
        }

        std::shared_lock<std::shared_mutex> connection_lock(m_database.m_connection_mutex);
        if (!CanUseConnection()) {
            return nullptr;
        }

        SQLiteStatement statement;
        const int result = sqlite3_prepare_v2(
            m_database.m_database,
            "SELECT key, value FROM main ORDER BY key",
            -1,
            statement.Address(),
            nullptr);
        if (result != SQLITE_OK) {
            LogSQLiteError(
                "SQLiteBatch: Failed to prepare ordered cursor",
                m_database.m_database,
                result);
            return nullptr;
        }
        std::unique_ptr<SQLiteCursor> cursor =
            std::make_unique<SQLiteCursor>(
                std::move(connection_lock),
                statement.Get(),
                std::vector<unsigned char>{});
        statement.Release();
        return cursor;
    }

    std::unique_ptr<DatabaseCursor> GetCursor(const CDataStream& start_key) override
    {
        if (m_closed.load() ||
            m_transaction.load() != SQLiteTransactionState::NONE ||
            start_key.size() > static_cast<size_t>(INT_MAX)) {
            return nullptr;
        }

        std::shared_lock<std::shared_mutex> connection_lock(m_database.m_connection_mutex);
        if (!CanUseConnection()) {
            return nullptr;
        }

        std::vector<unsigned char> start(
            start_key.begin(),
            start_key.end());
        ByteVectorCleanser start_cleanser(start);
        SQLiteStatement statement;
        int result = sqlite3_prepare_v2(
            m_database.m_database,
            "SELECT key, value FROM main WHERE key >= ? ORDER BY key",
            -1,
            statement.Address(),
            nullptr);
        if (result == SQLITE_OK) {
            result = sqlite3_bind_blob(
                statement.Get(),
                1,
                start.empty() ? static_cast<const void*>("") : start.data(),
                static_cast<int>(start.size()),
                SQLITE_STATIC);
        }
        if (result != SQLITE_OK) {
            LogSQLiteError(
                "SQLiteBatch: Failed to prepare lower-bound cursor",
                m_database.m_database,
                result);
            return nullptr;
        }
        std::unique_ptr<SQLiteCursor> cursor =
            std::make_unique<SQLiteCursor>(
                std::move(connection_lock),
                statement.Get(),
                std::move(start));
        statement.Release();
        start_cleanser.Release();
        return cursor;
    }

    bool TxnBegin() override
    {
        if (m_read_only || m_closed.load() ||
            m_transaction.load() != SQLiteTransactionState::NONE) {
            return false;
        }

        m_transaction_writer =
            std::unique_lock<std::mutex>(m_database.m_writer_mutex);
        m_transaction_connection =
            std::unique_lock<std::shared_mutex>(m_database.m_connection_mutex);
        if (!CanUseConnection() ||
            sqlite3_get_autocommit(m_database.m_database) == 0) {
            m_transaction.store(SQLiteTransactionState::NONE);
            ReleaseTransactionGates();
            return false;
        }

        int result;
        try {
            result = m_executor->Execute(
                m_database.m_database,
                "BEGIN TRANSACTION");
        } catch (...) {
            return HandleBeginExecutorException();
        }
        if (result != SQLITE_OK) {
            if (sqlite3_get_autocommit(m_database.m_database) == 0) {
                m_transaction.store(SQLiteTransactionState::ACTIVE);
            } else {
                m_transaction.store(SQLiteTransactionState::NONE);
            }
            LogSQLiteError(
                "SQLiteBatch: Failed to begin transaction",
                m_database.m_database,
                result);
            ReleaseTransactionGates();
            return false;
        }
        m_transaction.store(SQLiteTransactionState::ACTIVE);
        return true;
    }

    bool TxnCommit() override
    {
        if (m_closed.load() || !IsActive() ||
            !m_transaction_writer.owns_lock() ||
            !m_transaction_connection.owns_lock()) {
            return false;
        }

        int result;
        try {
            result = m_executor->Execute(
                m_database.m_database,
                "COMMIT TRANSACTION");
        } catch (...) {
            return HandleIndeterminateExecutorException(
                "committing a transaction");
        }
        if (result != SQLITE_OK) {
            ReconcileAfterError();
            LogSQLiteError(
                "SQLiteBatch: Failed to commit transaction",
                m_database.m_database,
                result);
            ReleaseTransactionGates();
            return false;
        }

        m_transaction.store(SQLiteTransactionState::NONE);
        ReleaseTransactionGates();
        return true;
    }

    bool TxnAbort() override
    {
        if (IsQuarantined()) {
            m_transaction_writer =
                std::unique_lock<std::mutex>(m_database.m_writer_mutex);
            m_transaction_connection =
                std::unique_lock<std::shared_mutex>(m_database.m_connection_mutex);
            const bool recovered = m_database.ResetAfterFailedRollback();
            if (recovered) {
                m_transaction.store(SQLiteTransactionState::NONE);
            }
            ReleaseTransactionGates();
            return recovered;
        }
        if (!IsActive() ||
            !m_transaction_writer.owns_lock() ||
            !m_transaction_connection.owns_lock()) {
            return false;
        }

        int result;
        try {
            result = m_executor->Execute(
                m_database.m_database,
                "ROLLBACK TRANSACTION");
        } catch (...) {
            return HandleIndeterminateExecutorException(
                "rolling back a transaction");
        }
        if (result != SQLITE_OK) {
            ReconcileAfterError();
            LogSQLiteError(
                "SQLiteBatch: Failed to roll back transaction",
                m_database.m_database,
                result);
            if (IsQuarantined()) {
                const bool recovered = m_database.ResetAfterFailedRollback();
                if (recovered) {
                    m_transaction.store(SQLiteTransactionState::NONE);
                }
                ReleaseTransactionGates();
                return recovered;
            }
            return false;
        }

        m_transaction.store(SQLiteTransactionState::NONE);
        ReleaseTransactionGates();
        return true;
    }

    bool HasActiveTxn() const override
    {
        return m_transaction.load() != SQLiteTransactionState::NONE;
    }
};

std::unique_ptr<DatabaseBatch> SQLiteDatabase::MakeBatch(
    const DatabaseBatchOptions& options)
{
    if (m_poisoned.load()) {
        throw std::runtime_error(strprintf(
            "SQLite wallet '%s' is quarantined after an unrecoverable connection error.",
            m_filename));
    }
    bool must_reopen = false;
    {
        std::lock_guard<std::mutex> state_lock(m_state_mutex);
        if (m_open) {
            ++m_batch_count;
        } else {
            must_reopen = true;
        }
    }

    if (must_reopen) {
        std::unique_lock<std::mutex> writer_lock(m_writer_mutex);
        std::unique_lock<std::shared_mutex> connection_lock(m_connection_mutex);
        {
            std::lock_guard<std::mutex> state_lock(m_state_mutex);
            must_reopen = !m_open;
        }
        if (must_reopen) {
            std::string error;
            if (!OpenExistingLocked(error)) {
                throw std::runtime_error(error);
            }
            std::lock_guard<std::mutex> state_lock(m_state_mutex);
            m_open = true;
            ++m_batch_count;
        } else {
            std::lock_guard<std::mutex> state_lock(m_state_mutex);
            ++m_batch_count;
        }
    }
    if (m_poisoned.load()) {
        BatchClosed();
        throw std::runtime_error(strprintf(
            "SQLite wallet '%s' is quarantined after an unrecoverable connection error.",
            m_filename));
    }

    std::unique_ptr<SQLiteBatch> batch;
    try {
        batch = std::make_unique<SQLiteBatch>(*this, options);
    } catch (...) {
        BatchClosed();
        throw;
    }
    if (options.mode == DatabaseBatchMode::READ_WRITE_CREATE &&
        !batch->EnsureVersion()) {
        batch->Close();
        throw std::runtime_error("Failed to initialize SQLite wallet version record.");
    }
    return batch;
}

bool SQLiteDatabase::Rewrite(const char* skip)
{
    std::unique_lock<std::mutex> writer_lock(m_writer_mutex);
    std::unique_lock<std::shared_mutex> connection_lock(m_connection_mutex);
    if (!m_database || !m_usable.load() || m_poisoned.load()) {
        return false;
    }

    auto fail_transaction = [this]() {
        if (!m_database) {
            return false;
        }
        if (sqlite3_get_autocommit(m_database) == 0) {
            const int rollback_result =
                sqlite3_exec(m_database, "ROLLBACK TRANSACTION", nullptr, nullptr, nullptr);
            if (rollback_result == SQLITE_OK) {
                return false;
            }
        }

        {
            std::lock_guard<std::mutex> state_lock(m_state_mutex);
            m_open = false;
        }
        if (!CloseOrAbandonSQLiteConnection(m_database)) {
            Poison();
            return false;
        }
        std::string error;
        if (!OpenExistingLocked(error)) {
            LogPrintf(
                "SQLiteDatabase: Failed to recover rewrite connection for '%s': %s\n",
                m_filename,
                error);
            return false;
        }
        {
            std::lock_guard<std::mutex> state_lock(m_state_mutex);
            m_open = true;
        }
        return false;
    };

    const size_t skip_size = skip ? std::strlen(skip) : 0;
    if (skip_size > static_cast<size_t>(INT_MAX)) {
        return false;
    }
    if (!ExecuteSQL(m_database, "VACUUM")) {
        return fail_transaction();
    }
    if (!ExecuteSQL(m_database, "BEGIN IMMEDIATE TRANSACTION")) {
        return fail_transaction();
    }

    bool success = true;
    {
        CDataStream key(SER_DISK, CLIENT_VERSION);
        key << std::string("version");
        CDataStream value(SER_DISK, CLIENT_VERSION);
        value << CLIENT_VERSION;
        StreamCleanser key_cleanser(key);
        StreamCleanser value_cleanser(value);
        SQLiteStatement statement;
        success =
            PrepareStatement(
                m_database,
                "INSERT INTO main(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                statement,
                "SQLiteDatabase: Failed to prepare version rewrite") &&
            BindBlob(statement.Get(), 1, key, "version key") &&
            BindBlob(statement.Get(), 2, value, "version value") &&
            sqlite3_step(statement.Get()) == SQLITE_DONE;
    }

    if (success && skip_size != 0) {
        std::vector<unsigned char> prefix(
            reinterpret_cast<const unsigned char*>(skip),
            reinterpret_cast<const unsigned char*>(skip) + skip_size);
        {
            SQLiteStatement statement;
            success =
                PrepareStatement(
                    m_database,
                    "DELETE FROM main "
                    "WHERE length(key) >= ? AND substr(key, 1, ?) = ?",
                    statement,
                    "SQLiteDatabase: Failed to prepare prefix rewrite") &&
                sqlite3_bind_int(statement.Get(), 1, static_cast<int>(prefix.size())) == SQLITE_OK &&
                sqlite3_bind_int(statement.Get(), 2, static_cast<int>(prefix.size())) == SQLITE_OK &&
                BindBlob(
                    statement.Get(),
                    3,
                    prefix.data(),
                    prefix.size(),
                    "rewrite prefix") &&
                sqlite3_step(statement.Get()) == SQLITE_DONE;
        }
        memory_cleanse(prefix.data(), prefix.size());
    }

    if (!success) {
        return fail_transaction();
    }
    if (!ExecuteSQL(m_database, "COMMIT TRANSACTION")) {
        return fail_transaction();
    }
    return true;
}

bool SQLiteDatabase::Backup(const std::string& destination)
{
#ifdef WIN32
    LogPrintf(
        "SQLiteDatabase: Backup is disabled on Windows until secure "
        "candidate DACL and reparse-point handling is implemented.\n");
    return false;
#else
    fs::path destination_path(destination);
    fs::file_status destination_status;
    std::string error;
    if (!GetPathStatus(destination_path, destination_status, error)) {
        LogPrintf("SQLiteDatabase: Failed to inspect backup destination: %s\n", error);
        return false;
    }
    if (destination_status.type() == fs::directory_file) {
        destination_path /= m_filename;
    } else if (destination_status.type() != fs::file_not_found) {
        return false;
    }
    if (destination_path.empty()) {
        return false;
    }

    std::unique_lock<std::mutex> writer_lock(m_writer_mutex);
    std::shared_lock<std::shared_mutex> connection_lock(m_connection_mutex);
    if (!m_database || !m_usable.load() || m_poisoned.load()) {
        return false;
    }

    fs::file_status target_status;
    if (!GetPathStatus(destination_path, target_status, error) ||
        target_status.type() != fs::file_not_found) {
        return false;
    }
    if (!CheckAuxiliaryFiles(destination_path, false, error)) {
        LogPrintf("SQLiteDatabase: Refusing backup destination: %s\n", error);
        return false;
    }
    OwnedCandidate candidate;
    if (CreateOwnedCandidate(destination_path, candidate, error) !=
        CandidateResult::SUCCESS) {
        LogPrintf("SQLiteDatabase: Failed to create backup candidate: %s\n", error);
        return false;
    }

    bool success = false;
    sqlite3* backup_database = nullptr;
    sqlite3_backup* backup = nullptr;
    PublishResult publish_result = PublishResult::ERROR;
    sqlite3* published_database = nullptr;
    auto close_after_exception = [&]() noexcept {
        if (backup) {
            sqlite3_backup_finish(backup);
            backup = nullptr;
        }
        const bool backup_closed =
            CloseOrAbandonSQLiteConnection(
                backup_database,
                &candidate.cleanup_allowed);
        const bool published_closed =
            CloseOrAbandonSQLiteConnection(
                published_database,
                &candidate.cleanup_allowed);
        if (!backup_closed ||
            !published_closed ||
            !candidate.cleanup_allowed) {
            Poison();
        }
        success = false;
    };

    try {
        if (OpenSQLiteConnection(
                candidate.path,
                backup_database,
                error,
                &candidate.identity,
                &candidate.cleanup_allowed) &&
            SetConnectionPragmas(backup_database, error) &&
            ConnectionIdentityMatches(
                backup_database,
                candidate.path,
                candidate.identity,
                error)) {
            backup = sqlite3_backup_init(
                backup_database,
                "main",
                m_database,
                "main");
            if (backup) {
                const int step_result =
                    sqlite3_backup_step(backup, -1);
                const int finish_result =
                    sqlite3_backup_finish(backup);
                backup = nullptr;
                success =
                    step_result == SQLITE_DONE &&
                    finish_result == SQLITE_OK &&
                    VerifyDatabase(backup_database, error);
                if (!success && error.empty()) {
                    error = strprintf(
                        "Failed to copy SQLite backup (step error %d, finish error %d).",
                        step_result,
                        finish_result);
                }
            } else {
                error = strprintf(
                    "Failed to initialize SQLite backup: %s",
                    sqlite3_errmsg(backup_database));
            }
        }

        if (backup) {
            sqlite3_backup_finish(backup);
            backup = nullptr;
        }
        const bool backup_closed =
            CloseOrAbandonSQLiteConnection(
                backup_database,
                &candidate.cleanup_allowed);
        if (!backup_closed) {
            success = false;
            error = "Failed to close the SQLite backup candidate connection.";
        }
        if (!candidate.cleanup_allowed) {
            success = false;
            Poison();
        }
        if (success &&
            !CheckAuxiliaryFiles(candidate.path, false, error)) {
            success = false;
        }

        if (success) {
            publish_result =
                PublishCandidate(
                    candidate,
                    destination_path,
                    error);
            success =
                publish_result == PublishResult::SUCCESS;
        }
        if (success && ConsumePostPublishFailure()) {
            error =
                "Injected failure after publishing SQLite backup candidate.";
            success = false;
        }

        if (success) {
            SQLiteFileIdentity published_identity;
            success =
                VerifySQLiteHeaderDescriptor(
                    candidate.descriptor,
                    destination_path,
                    published_identity,
                    error) &&
                DescriptorIdentityMatches(
                    candidate.descriptor,
                    candidate.identity) &&
                PathIdentityMatches(
                    destination_path,
                    candidate.identity) &&
                OpenSQLiteConnection(
                    destination_path,
                    published_database,
                    error,
                    &candidate.identity,
                    &candidate.cleanup_allowed) &&
                VerifyDatabase(published_database, error) &&
                SetConnectionPragmas(published_database, error) &&
                ConnectionIdentityMatches(
                    published_database,
                    destination_path,
                    candidate.identity,
                    error) &&
                VerifyDatabase(published_database, error);
            const bool published_closed =
                CloseOrAbandonSQLiteConnection(
                    published_database,
                    &candidate.cleanup_allowed);
            if (!published_closed) {
                success = false;
                error =
                    "Failed to close the published SQLite backup verification connection.";
            }
            if (!candidate.cleanup_allowed) {
                success = false;
                Poison();
            }
        }
    } catch (const std::exception& exception) {
        close_after_exception();
        error = strprintf(
            "SQLite backup failed with an exception: %s",
            exception.what());
    } catch (...) {
        close_after_exception();
        error = "SQLite backup failed with an unknown exception.";
    }

    if (!success &&
        (publish_result == PublishResult::SUCCESS ||
            publish_result == PublishResult::PUBLISHED_ERROR)) {
        std::string cleanup_error;
        if (!RemovePublishedCandidate(
                candidate,
                destination_path,
                cleanup_error)) {
            error += strprintf(
                "%sFailed to remove the published SQLite backup safely: %s",
                error.empty() ? "" : " ",
                cleanup_error);
        }
    }
    RemoveOwnedCandidate(candidate);
    if (!success && !error.empty()) {
        LogPrintf("SQLiteDatabase: Backup failed: %s\n", error);
    }
    return success;
#endif
}

bool SQLiteDatabase::PeriodicFlush()
{
    std::unique_lock<std::mutex> writer_lock(m_writer_mutex, std::try_to_lock);
    if (!writer_lock.owns_lock()) {
        return false;
    }
    std::unique_lock<std::shared_mutex> connection_lock(
        m_connection_mutex,
        std::try_to_lock);
    if (!connection_lock.owns_lock()) {
        return false;
    }
    {
        std::lock_guard<std::mutex> state_lock(m_state_mutex);
        if (m_batch_count != 0) {
            return false;
        }
        m_open = false;
    }
    if (!m_database || !m_usable.load() || m_poisoned.load()) {
        return false;
    }

    const int flush_result = sqlite3_db_cacheflush(m_database);
    if (flush_result != SQLITE_OK) {
        {
            std::lock_guard<std::mutex> state_lock(m_state_mutex);
            m_open = true;
        }
        LogSQLiteError(
            "SQLiteDatabase: Failed periodic cache flush",
            m_database,
            flush_result);
        return false;
    }
    const bool closed = CloseOrAbandonSQLiteConnection(m_database);
    if (!closed) {
        Poison();
    }
    return closed;
}

void SQLiteDatabase::Flush(bool shutdown)
{
    try {
        std::unique_lock<std::mutex> writer_lock(
            m_writer_mutex,
            std::try_to_lock);
        if (!writer_lock.owns_lock()) {
            return;
        }
        std::unique_lock<std::shared_mutex> connection_lock(
            m_connection_mutex,
            std::try_to_lock);
        if (!connection_lock.owns_lock()) {
            return;
        }
        if (!m_database || !m_usable.load() || m_poisoned.load()) {
            return;
        }

        const int result = sqlite3_db_cacheflush(m_database);
        if (result != SQLITE_OK) {
            LogSQLiteError(
                "SQLiteDatabase: Failed cache flush",
                m_database,
                result);
            return;
        }

        bool can_close = false;
        if (shutdown) {
            std::lock_guard<std::mutex> state_lock(m_state_mutex);
            can_close = m_batch_count == 0;
            if (can_close) {
                m_open = false;
            }
        }
        if (can_close &&
            !CloseOrAbandonSQLiteConnection(m_database)) {
            Poison();
        }
    } catch (const std::exception& exception) {
        Poison();
        LogPrintf("SQLiteDatabase: Exception during flush: %s\n", exception.what());
    } catch (...) {
        Poison();
        LogPrintf("SQLiteDatabase: Unknown exception during flush.\n");
    }
}
} // namespace

int SQLiteStatementExecutor::Execute(
    sqlite3* database,
    const char* statement)
{
    return sqlite3_exec(database, statement, nullptr, nullptr, nullptr);
}

std::unique_ptr<WalletDatabase> MakeSQLiteDatabase(
    const std::string& filename,
    const DatabaseOptions& options,
    DatabaseStatus& status,
    std::string& error)
{
    status = DatabaseStatus::FAILED_LOAD;
    error.clear();

    if ((options.require_existing && options.require_create)) {
        status = DatabaseStatus::FAILED_INVALID_OPTIONS;
        error = "Invalid SQLite wallet database options.";
        return nullptr;
    }
    if (options.require_format &&
        *options.require_format != DatabaseFormat::SQLITE) {
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        error = "SQLite backend factory requires SQLite format.";
        return nullptr;
    }
    if (options.salvage) {
        status = DatabaseStatus::FAILED_UNSUPPORTED;
        error = "SQLite wallet salvage is not supported.";
        return nullptr;
    }
#ifdef WIN32
    status = DatabaseStatus::FAILED_UNSUPPORTED;
    error =
        "SQLite wallet storage is disabled on Windows until candidate files "
        "can be created with an owner-only DACL and opened without following "
        "reparse points.";
    return nullptr;
#endif

    fs::path path;
    if (!GetWalletDatabasePath(filename, path, error)) {
        status = DatabaseStatus::FAILED_BAD_PATH;
        return nullptr;
    }

    fs::file_status path_status;
    if (!GetPathStatus(path, path_status, error)) {
        status = DatabaseStatus::FAILED_BAD_PATH;
        return nullptr;
    }
    bool exists = path_status.type() != fs::file_not_found;
    if (exists && path_status.type() != fs::regular_file) {
        status = DatabaseStatus::FAILED_BAD_PATH;
        error = strprintf(
            "Refusing SQLite wallet '%s': the path must be a regular file and must not be a symlink.",
            path.string());
        return nullptr;
    }
    if (exists && options.require_create) {
        status = DatabaseStatus::FAILED_ALREADY_EXISTS;
        error = strprintf(
            "Failed to create SQLite wallet '%s': the path already exists.",
            path.string());
        return nullptr;
    }
    if (!exists && options.require_existing) {
        status = DatabaseStatus::FAILED_NOT_FOUND;
        error = strprintf(
            "Failed to open SQLite wallet '%s': the path does not exist.",
            path.string());
        return nullptr;
    }
    if (!CheckAuxiliaryFiles(path, exists, error)) {
        status = DatabaseStatus::FAILED_BAD_PATH;
        return nullptr;
    }

    OwnedCandidate candidate;
    if (!exists) {
        if (CreateOwnedCandidate(path, candidate, error) !=
            CandidateResult::SUCCESS) {
            status = DatabaseStatus::FAILED_LOAD;
            return nullptr;
        }
    }

    std::unique_ptr<SQLiteDatabase> database;
    PublishResult publish_result = PublishResult::ERROR;
    auto cleanup_failed_creation = [&] {
        if (publish_result == PublishResult::SUCCESS ||
            publish_result == PublishResult::PUBLISHED_ERROR) {
            std::string cleanup_error;
            if (!RemovePublishedCandidate(
                    candidate,
                    path,
                    cleanup_error)) {
                error += strprintf(
                    "%sFailed to remove the published SQLite wallet safely: %s",
                    error.empty() ? "" : " ",
                    cleanup_error);
            }
        }
        RemoveOwnedCandidate(candidate);
    };
    try {
        database = std::make_unique<SQLiteDatabase>(filename, path);
        const bool initialized =
            exists ?
                database->InitializeExisting(error) :
                database->InitializeCreated(candidate, publish_result, error);
        if (!initialized) {
            database.reset();
            if (!exists) {
                cleanup_failed_creation();
                if (publish_result == PublishResult::EXISTS) {
                    status = DatabaseStatus::FAILED_ALREADY_EXISTS;
                    error = strprintf(
                        "Failed to create SQLite wallet '%s': the path appeared concurrently.",
                        path.string());
                } else {
                    status = DatabaseStatus::FAILED_LOAD;
                }
            } else {
                status = DatabaseStatus::FAILED_VERIFY;
            }
            return nullptr;
        }
    } catch (const std::exception& exception) {
        error = exception.what();
        database.reset();
        if (!exists) {
            cleanup_failed_creation();
        }
        status = DatabaseStatus::FAILED_LOAD;
        return nullptr;
    }

    status = DatabaseStatus::SUCCESS;
    return database;
}

bool SetSQLiteStatementExecutorForTesting(
    DatabaseBatch& batch,
    std::unique_ptr<SQLiteStatementExecutor> executor)
{
    SQLiteBatch* const sqlite_batch = dynamic_cast<SQLiteBatch*>(&batch);
    return sqlite_batch && sqlite_batch->SetExecutor(std::move(executor));
}

bool GetSQLiteSynchronousModeForTesting(
    DatabaseBatch& batch,
    int64_t& mode)
{
    SQLiteBatch* const sqlite_batch = dynamic_cast<SQLiteBatch*>(&batch);
    return sqlite_batch && sqlite_batch->GetSynchronousMode(mode);
}

void InjectSQLitePostPublishFailureForTesting()
{
    g_fail_post_publish_once.store(true);
}

void InjectSQLiteAmbiguousPublishFailureForTesting()
{
    g_report_publish_error_after_rename_once.store(true);
}

void InjectSQLiteCloseFailureForTesting(
    int successful_closes_before_failure)
{
    g_fail_close_after_successes.store(
        successful_closes_before_failure);
}

bool ResetSQLiteLifecycleForTesting()
{
    sqlite3* abandoned_connection = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_sqlite_mutex);
        if (g_sqlite_owner_count != 0 ||
            g_sqlite_abandoned_connection_count != 1 ||
            !g_sqlite_first_abandoned_connection ||
            !g_sqlite_has_abandoned_connection.load()) {
            return false;
        }
        abandoned_connection =
            g_sqlite_first_abandoned_connection;
    }

    g_fail_close_after_successes.store(-1);
    g_fail_post_publish_once.store(false);
    g_report_publish_error_after_rename_once.store(false);
    if (sqlite3_close(abandoned_connection) != SQLITE_OK) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_sqlite_mutex);
    g_sqlite_first_abandoned_connection = nullptr;
    g_sqlite_abandoned_connection_count = 0;
    const int result = sqlite3_shutdown();
    if (result != SQLITE_OK) {
        return false;
    }
    g_sqlite_initialized = false;
    g_sqlite_has_abandoned_connection.store(false);
    return true;
}

#endif // USE_SQLITE
