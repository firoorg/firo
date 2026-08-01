// Copyright (c) 2020-present The Bitcoin Core developers
// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "config/bitcoin-config.h"

#ifdef USE_SQLITE

#include "wallet/sqlite.h"

#include "chainparams.h"
#include "crypto/common.h"
#include "init.h"
#include "support/cleanse.h"
#include "util.h"
#include "wallet/db.h"
#include "wallet/walletdb.h"

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <limits>
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
#include <linux/fs.h>
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
constexpr unsigned char LOGICAL_CREATION_MARKER[]{
    'f', 'i', 'r', 'o', '.', 's', 'q', 'l', 'i', 't', 'e', '.',
    'l', 'o', 'g', 'i', 'c', 'a', 'l', '-', 'c', 'r', 'e', 'a',
    't', 'i', 'o', 'n', '.', 'i', 'n', 'c', 'o', 'm', 'p', 'l',
    'e', 't', 'e', '.', 'v', '1'};

enum class SQLiteCreationMarkerState {
    ABSENT,
    PRESENT,
    INVALID,
    FAILED,
};

enum class SQLiteCreationState {
    NONE,
    PENDING,
    INDETERMINATE,
    PUBLISHED,
};

enum class SQLiteCreationMarkerPolicy {
    REQUIRE_ABSENT,
    REQUIRE_PRESENT,
    ALLOW_EITHER,
};

std::mutex g_sqlite_mutex;
size_t g_sqlite_owner_count{0};
bool g_sqlite_initialized{false};
std::atomic<bool> g_sqlite_has_abandoned_connection{false};
sqlite3* g_sqlite_first_abandoned_connection{nullptr};
size_t g_sqlite_abandoned_connection_count{0};
std::atomic<bool> g_fail_post_publish_once{false};
std::atomic<bool> g_report_publish_error_after_rename_once{false};
std::atomic<bool> g_report_backup_collision_once{false};
std::atomic<bool> g_fail_backup_collision_cleanup_once{false};
std::atomic<bool> g_report_migration_exchange_error_once{false};
std::atomic<bool> g_report_rewrite_commit_error_once{false};
std::atomic<int> g_fail_close_after_successes{-1};

bool ConsumePostPublishFailure()
{
    return g_fail_post_publish_once.exchange(false);
}

bool ConsumePublishErrorAfterRename()
{
    return g_report_publish_error_after_rename_once.exchange(false);
}

bool ConsumeBackupPublicationCollision()
{
    return g_report_backup_collision_once.exchange(false);
}

bool ConsumeBackupCollisionCleanupFailure()
{
    return g_fail_backup_collision_cleanup_once.exchange(false);
}

bool ConsumeMigrationExchangeError()
{
    return g_report_migration_exchange_error_once.exchange(false);
}

bool ConsumeRewriteCommitError()
{
    return g_report_rewrite_commit_error_once.exchange(false);
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

class SQLiteConnectionMutex final
{
private:
    sqlite3_mutex* const m_mutex;

public:
    explicit SQLiteConnectionMutex(sqlite3* database)
        : m_mutex(sqlite3_db_mutex(database))
    {
        if (m_mutex) {
            sqlite3_mutex_enter(m_mutex);
        }
    }

    ~SQLiteConnectionMutex()
    {
        if (m_mutex) {
            sqlite3_mutex_leave(m_mutex);
        }
    }

    SQLiteConnectionMutex(const SQLiteConnectionMutex&) = delete;
    SQLiteConnectionMutex& operator=(const SQLiteConnectionMutex&) = delete;
};

bool ReadBlobColumn(
    SQLiteColumnReader& reader,
    sqlite3* database,
    sqlite3_stmt* statement,
    int column,
    const void*& data,
    int& size,
    const char* context)
{
    SQLiteConnectionMutex sqlite_lock(database);

    data = reader.Blob(statement, column);
    if (!data) {
        const int result = reader.ErrorCode(database);
        if ((result & 0xff) == SQLITE_NOMEM) {
            LogSQLiteError(context, database, result);
            return false;
        }
    }

    size = reader.Bytes(statement, column);
    if (size == 0) {
        const int result = reader.ErrorCode(database);
        if ((result & 0xff) == SQLITE_NOMEM) {
            LogSQLiteError(context, database, result);
            return false;
        }
    }
    if (size < 0 || (size > 0 && !data)) {
        LogPrintf("%s: SQLite returned an invalid BLOB.\n", context);
        return false;
    }
    return true;
}

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

SQLiteCreationMarkerState ReadLogicalCreationMarker(
    sqlite3* database,
    std::string& error)
{
    SQLiteStatement statement;
    if (!PrepareStatement(
            database,
            "SELECT value FROM main WHERE key = ?",
            statement,
            "Failed to inspect SQLite logical-creation marker",
            &error) ||
        !BindBlob(
            statement.Get(),
            1,
            nullptr,
            0,
            "logical-creation marker key")) {
        if (error.empty()) {
            error = "Failed to bind SQLite logical-creation marker key.";
        }
        return SQLiteCreationMarkerState::FAILED;
    }

    const int result = sqlite3_step(statement.Get());
    if (result == SQLITE_DONE) {
        return SQLiteCreationMarkerState::ABSENT;
    }
    if (result != SQLITE_ROW) {
        error = strprintf(
            "Failed to inspect SQLite logical-creation marker: %s",
            sqlite3_errmsg(database));
        return SQLiteCreationMarkerState::FAILED;
    }
    if (sqlite3_column_type(statement.Get(), 0) != SQLITE_BLOB) {
        error = "SQLite wallet contains invalid reserved creation metadata.";
        return SQLiteCreationMarkerState::INVALID;
    }

    SQLiteColumnReader reader;
    const void* data = nullptr;
    int size = 0;
    if (!ReadBlobColumn(
            reader,
            database,
            statement.Get(),
            0,
            data,
            size,
            "Failed to read SQLite logical-creation marker")) {
        error = "Failed to read SQLite logical-creation marker.";
        return SQLiteCreationMarkerState::FAILED;
    }
    if (size != static_cast<int>(sizeof(LOGICAL_CREATION_MARKER)) ||
        std::memcmp(
            data,
            LOGICAL_CREATION_MARKER,
            sizeof(LOGICAL_CREATION_MARKER)) != 0) {
        error = "SQLite wallet contains invalid reserved creation metadata.";
        return SQLiteCreationMarkerState::INVALID;
    }
    return SQLiteCreationMarkerState::PRESENT;
}

bool ValidateLogicalCreationMarker(
    sqlite3* database,
    const fs::path& path,
    SQLiteCreationMarkerPolicy policy,
    std::string& error)
{
    const SQLiteCreationMarkerState state =
        ReadLogicalCreationMarker(database, error);
    if (state == SQLiteCreationMarkerState::FAILED ||
        state == SQLiteCreationMarkerState::INVALID) {
        error = strprintf(
            "Failed to validate reserved metadata in SQLite wallet '%s'%s%s",
            path.string(),
            error.empty() ? "." : ": ",
            error);
        return false;
    }
    if (state == SQLiteCreationMarkerState::PRESENT &&
        policy == SQLiteCreationMarkerPolicy::REQUIRE_ABSENT) {
        error = strprintf(
            "SQLite wallet '%s' is incomplete because its logical creation did not finish.",
            path.string());
        return false;
    }
    if (state == SQLiteCreationMarkerState::ABSENT &&
        policy == SQLiteCreationMarkerPolicy::REQUIRE_PRESENT) {
        error = strprintf(
            "SQLite wallet '%s' lost its logical-creation marker before initialization completed.",
            path.string());
        return false;
    }
    return true;
}

bool InsertLogicalCreationMarker(
    sqlite3* database,
    std::string& error)
{
    SQLiteStatement statement;
    if (!PrepareStatement(
            database,
            "INSERT INTO main(key, value) VALUES(?, ?)",
            statement,
            "Failed to prepare SQLite logical-creation marker",
            &error) ||
        !BindBlob(
            statement.Get(),
            1,
            nullptr,
            0,
            "logical-creation marker key") ||
        !BindBlob(
            statement.Get(),
            2,
            LOGICAL_CREATION_MARKER,
            sizeof(LOGICAL_CREATION_MARKER),
            "logical-creation marker value")) {
        if (error.empty()) {
            error = "Failed to bind SQLite logical-creation marker.";
        }
        return false;
    }
    const int result = sqlite3_step(statement.Get());
    if (result != SQLITE_DONE) {
        error = strprintf(
            "Failed to insert SQLite logical-creation marker: %s",
            sqlite3_errmsg(database));
        return false;
    }
    return true;
}

bool DeleteLogicalCreationMarker(
    sqlite3* database,
    std::string& error)
{
    SQLiteStatement statement;
    if (!PrepareStatement(
            database,
            "DELETE FROM main WHERE key = ? AND value = ?",
            statement,
            "Failed to prepare SQLite logical-creation completion",
            &error) ||
        !BindBlob(
            statement.Get(),
            1,
            nullptr,
            0,
            "logical-creation marker key") ||
        !BindBlob(
            statement.Get(),
            2,
            LOGICAL_CREATION_MARKER,
            sizeof(LOGICAL_CREATION_MARKER),
            "logical-creation marker value")) {
        if (error.empty()) {
            error = "Failed to bind SQLite logical-creation completion marker.";
        }
        return false;
    }
    const int result = sqlite3_step(statement.Get());
    if (result != SQLITE_DONE || sqlite3_changes(database) != 1) {
        error = result == SQLITE_DONE ?
                    "SQLite logical-creation marker was not removed exactly once." :
                    strprintf(
                        "Failed to remove SQLite logical-creation marker: %s",
                        sqlite3_errmsg(database));
        return false;
    }
    return true;
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

bool SameSQLiteFileIdentity(
    const SQLiteFileIdentity& first,
    const SQLiteFileIdentity& second) noexcept
{
#ifdef WIN32
    (void)first;
    (void)second;
    return false;
#else
    return first.valid &&
           second.valid &&
           first.device == second.device &&
           first.inode == second.inode;
#endif
}

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

bool DescriptorIdentityIsUnlinked(
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
           metadata.st_ino == identity.inode &&
           metadata.st_nlink == 0;
#endif
}

bool PrivateSQLiteIdentityMatches(
    int descriptor,
    const fs::path& path,
    const SQLiteFileIdentity& identity) noexcept
{
#ifdef WIN32
    (void)descriptor;
    (void)path;
    (void)identity;
    return false;
#else
    struct stat descriptor_status{};
    struct stat path_status{};
    return descriptor >= 0 &&
           fstat(descriptor, &descriptor_status) == 0 &&
           lstat(path.string().c_str(), &path_status) == 0 &&
           S_ISREG(descriptor_status.st_mode) &&
           S_ISREG(path_status.st_mode) &&
           descriptor_status.st_dev == identity.device &&
           descriptor_status.st_ino == identity.inode &&
           path_status.st_dev == identity.device &&
           path_status.st_ino == identity.inode &&
           descriptor_status.st_uid == geteuid() &&
           path_status.st_uid == geteuid() &&
           descriptor_status.st_nlink == 1 &&
           path_status.st_nlink == 1 &&
           (descriptor_status.st_mode & (S_IRWXG | S_IRWXO)) == 0 &&
           (path_status.st_mode & (S_IRWXG | S_IRWXO)) == 0;
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

bool VerifyIntegrity(
    sqlite3* database,
    std::string& error,
    bool* corruption = nullptr)
{
    if (corruption) {
        *corruption = false;
    }
    SQLiteStatement statement;
    if (!PrepareStatement(
            database,
            "PRAGMA integrity_check",
            statement,
            "Failed to prepare SQLite integrity check",
            &error)) {
        if (corruption) {
            const int result = sqlite3_extended_errcode(database) & 0xff;
            *corruption =
                result == SQLITE_CORRUPT ||
                result == SQLITE_NOTADB;
        }
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
            if (corruption) {
                const int primary_result = result & 0xff;
                *corruption =
                    primary_result == SQLITE_CORRUPT ||
                    primary_result == SQLITE_NOTADB;
            }
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
        if (corruption) {
            *corruption = true;
        }
        error = "SQLite wallet failed its full integrity check.";
        return false;
    }
    return true;
}

bool VerifyDatabaseIdentity(sqlite3* database, std::string& error)
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

    return true;
}

bool VerifyDatabase(sqlite3* database, std::string& error)
{
    return VerifyDatabaseIdentity(database, error) &&
           VerifySchema(database, error) &&
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

bool CreateSchema(
    sqlite3* database,
    bool logical_wallet_create,
    std::string& error)
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
        ExecuteSQL(database, version_statement.c_str(), &error) &&
        (!logical_wallet_create ||
            InsertLogicalCreationMarker(database, error));
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

int DurableSyncFileDescriptor(int descriptor) noexcept
{
    int result;
    do {
#ifdef WIN32
        result = _commit(descriptor);
#elif defined(__APPLE__) && defined(F_FULLFSYNC)
        result = fcntl(descriptor, F_FULLFSYNC, 0);
#else
        result = fsync(descriptor);
#endif
    } while (result != 0 && errno == EINTR);
    return result == 0 ?
               0 :
               (errno != 0 ? errno : EIO);
}

bool SyncDirectory(
    const fs::path& directory,
    std::string& error,
    bool require_supported = false)
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
    const int synchronization_error =
        DurableSyncFileDescriptor(descriptor);
    if (synchronization_error != 0 &&
        (require_supported ||
            (synchronization_error != EINVAL &&
                synchronization_error != ENOTSUP))) {
        error = strprintf(
            "Failed to synchronize SQLite publication directory '%s': %s",
            directory.string(),
            std::strerror(synchronization_error));
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

bool OwnerControlledMigrationDirectory(
    const fs::path& directory,
    std::string& error)
{
#ifdef WIN32
    error =
        "Secure SQLite migration directories are unavailable on Windows.";
    return false;
#elif !defined(O_CLOEXEC) || !defined(O_NOFOLLOW)
    error = strprintf(
        "Cannot secure SQLite migration directory '%s': O_CLOEXEC and O_NOFOLLOW are required.",
        directory.string());
    return false;
#else
    if (!ValidateWalletMigrationDirectory(
            directory,
            error)) {
        return false;
    }
    int flags =
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
    const int descriptor =
        open(directory.string().c_str(), flags);
    if (descriptor < 0) {
        error = strprintf(
            "Failed to open SQLite migration directory '%s': %s",
            directory.string(),
            std::strerror(errno));
        return false;
    }

    struct stat descriptor_status{};
    struct stat path_status{};
    const bool controlled =
        fstat(descriptor, &descriptor_status) == 0 &&
        lstat(
            directory.string().c_str(),
            &path_status) == 0 &&
        S_ISDIR(descriptor_status.st_mode) &&
        S_ISDIR(path_status.st_mode) &&
        descriptor_status.st_dev ==
            path_status.st_dev &&
        descriptor_status.st_ino ==
            path_status.st_ino &&
        descriptor_status.st_uid == geteuid() &&
        path_status.st_uid == geteuid() &&
        (descriptor_status.st_mode &
            (S_IWGRP | S_IWOTH)) == 0 &&
        (path_status.st_mode &
            (S_IWGRP | S_IWOTH)) == 0;
    const int close_result = close(descriptor);
    if (!controlled || close_result != 0) {
        error = strprintf(
            "Refusing SQLite migration directory '%s': it must be an effective-user-owned, non-symlink directory without group or other write access.",
            directory.string());
        return false;
    }
    return true;
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

bool RemoveOwnedCandidate(
    const OwnedCandidate& candidate,
    std::string& error) noexcept
{
    error.clear();
#ifndef WIN32
    struct stat metadata{};
    if (lstat(candidate.path.string().c_str(), &metadata) != 0) {
        if (errno == ENOENT) {
            return true;
        }
        error = strprintf(
            "Failed to inspect owned SQLite candidate '%s': %s",
            candidate.path.string(),
            std::strerror(errno));
        return false;
    }
    if (!candidate.cleanup_allowed ||
        g_sqlite_has_abandoned_connection.load()) {
        error = strprintf(
            "Refusing to remove owned SQLite candidate '%s' because a "
            "connection lifecycle failure made cleanup unsafe.",
            candidate.path.string());
        return false;
    }
    if (!candidate.valid ||
        !PathIdentityMatches(candidate.path, candidate.identity)) {
        error = strprintf(
            "Refusing to remove owned SQLite candidate '%s' because its "
            "ownership identity changed.",
            candidate.path.string());
        return false;
    }

    std::string detail;
    if (!CheckAuxiliaryFiles(candidate.path, false, detail)) {
        error = strprintf(
            "Refusing to remove owned SQLite candidate '%s' because "
            "auxiliary state exists and its provenance cannot be proven: %s",
            candidate.path.string(),
            detail);
        return false;
    }
    if (!RemoveOwnedPath(candidate.path, candidate.identity, detail)) {
        error = strprintf(
            "Failed to remove owned SQLite candidate '%s': %s",
            candidate.path.string(),
            detail);
        return false;
    }

    const fs::path parent =
        candidate.path.parent_path().empty() ?
            fs::path(".") :
            candidate.path.parent_path();
    if (!SyncDirectory(parent, detail)) {
        error = strprintf(
            "Removed owned SQLite candidate '%s', but failed to synchronize "
            "its parent directory '%s': %s",
            candidate.path.string(),
            parent.string(),
            detail);
        return false;
    }
    return true;
#else
    (void)candidate;
    error =
        "Secure removal of an owned SQLite candidate is unavailable on Windows.";
    return false;
#endif
}

void RemoveOwnedCandidate(const OwnedCandidate& candidate) noexcept
{
    std::string error;
    if (!RemoveOwnedCandidate(candidate, error)) {
        LogPrintf(
            "SQLiteDatabase: Candidate cleanup could not be proven: %s\n",
            error);
    }
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
    } else {
        candidate_error =
            DurableSyncFileDescriptor(
                candidate.descriptor);
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

bool CopyDescriptorContents(
    int source,
    int destination,
    std::string& error)
{
#ifdef WIN32
    (void)source;
    (void)destination;
    error = "Secure SQLite recovery backup copying is unavailable on Windows.";
    return false;
#else
    struct stat source_status{};
    if (source < 0 ||
        destination < 0 ||
        fstat(source, &source_status) != 0 ||
        !S_ISREG(source_status.st_mode) ||
        source_status.st_size < 0) {
        error = "Failed to inspect SQLite recovery backup source.";
        return false;
    }
    if (ftruncate(destination, 0) != 0) {
        error = strprintf(
            "Failed to initialize SQLite recovery backup: %s",
            std::strerror(errno));
        return false;
    }

    std::vector<unsigned char> buffer(64 * 1024);
    ByteVectorCleanser buffer_cleanser(buffer);
    off_t offset = 0;
    while (offset < source_status.st_size) {
        const size_t remaining = static_cast<size_t>(
            std::min<off_t>(
                source_status.st_size - offset,
                static_cast<off_t>(buffer.size())));
        ssize_t read_count;
        do {
            read_count = pread(
                source,
                buffer.data(),
                remaining,
                offset);
        } while (read_count < 0 && errno == EINTR);
        if (read_count <= 0) {
            error = strprintf(
                "Failed to read SQLite recovery backup source: %s",
                read_count == 0 ?
                    "unexpected end of file" :
                    std::strerror(errno));
            return false;
        }

        ssize_t written = 0;
        while (written < read_count) {
            ssize_t write_count;
            do {
                write_count = pwrite(
                    destination,
                    buffer.data() + written,
                    static_cast<size_t>(read_count - written),
                    offset + written);
            } while (write_count < 0 && errno == EINTR);
            if (write_count <= 0) {
                error = strprintf(
                    "Failed to write SQLite recovery backup: %s",
                    write_count == 0 ?
                        "no progress" :
                        std::strerror(errno));
                return false;
            }
            written += write_count;
        }
        offset += read_count;
    }
    int synchronization_error = 0;
    if (ftruncate(
            destination,
            source_status.st_size) != 0) {
        synchronization_error = errno;
    } else {
        synchronization_error =
            DurableSyncFileDescriptor(destination);
    }
    if (synchronization_error != 0) {
        error = strprintf(
            "Failed to synchronize SQLite recovery backup: %s",
            std::strerror(synchronization_error));
        return false;
    }
    return true;
#endif
}

bool DescriptorContentsEqual(
    int first,
    int second,
    std::string& error)
{
#ifdef WIN32
    (void)first;
    (void)second;
    error = "Secure SQLite recovery backup comparison is unavailable on Windows.";
    return false;
#else
    struct stat first_status{};
    struct stat second_status{};
    if (first < 0 ||
        second < 0 ||
        fstat(first, &first_status) != 0 ||
        fstat(second, &second_status) != 0 ||
        !S_ISREG(first_status.st_mode) ||
        !S_ISREG(second_status.st_mode) ||
        first_status.st_size < 0 ||
        first_status.st_size != second_status.st_size) {
        error = "SQLite recovery backup size or file identity does not match its source.";
        return false;
    }

    std::vector<unsigned char> first_buffer(64 * 1024);
    std::vector<unsigned char> second_buffer(64 * 1024);
    ByteVectorCleanser first_cleanser(first_buffer);
    ByteVectorCleanser second_cleanser(second_buffer);
    off_t offset = 0;
    while (offset < first_status.st_size) {
        const size_t remaining = static_cast<size_t>(
            std::min<off_t>(
                first_status.st_size - offset,
                static_cast<off_t>(first_buffer.size())));
        ssize_t first_count;
        ssize_t second_count;
        do {
            first_count = pread(
                first,
                first_buffer.data(),
                remaining,
                offset);
        } while (first_count < 0 && errno == EINTR);
        do {
            second_count = pread(
                second,
                second_buffer.data(),
                remaining,
                offset);
        } while (second_count < 0 && errno == EINTR);
        if (first_count <= 0 ||
            second_count != first_count ||
            !std::equal(
                first_buffer.begin(),
                first_buffer.begin() + first_count,
                second_buffer.begin())) {
            error = "SQLite recovery backup is not an exact byte copy of its source.";
            return false;
        }
        offset += first_count;
    }
    return true;
#endif
}

enum class SQLiteRecoveryMode {
    FULL,
    KEY_ONLY,
};

template <typename Callback>
bool ForEachSQLiteRecoveryRow(
    sqlite3* source,
    SQLiteRecoveryMode mode,
    Callback&& callback,
    size_t& count,
    std::string& error)
{
    count = 0;
    SQLiteStatement rows;
    if (!PrepareStatement(
            source,
            "SELECT key, value FROM main NOT INDEXED ORDER BY rowid",
            rows,
            "Failed to prepare SQLite recovery row scan",
            &error)) {
        return false;
    }

    SQLiteColumnReader reader;
    WalletKeyOnlyRecordValidator validator;
    while (true) {
        const int result = sqlite3_step(rows.Get());
        if (result == SQLITE_DONE) {
            return true;
        }
        if (result != SQLITE_ROW) {
            error = strprintf(
                "SQLite recovery row scan did not complete: %s",
                sqlite3_errmsg(source));
            return false;
        }
        if (sqlite3_column_type(rows.Get(), 0) != SQLITE_BLOB ||
            sqlite3_column_type(rows.Get(), 1) != SQLITE_BLOB) {
            error =
                "SQLite recovery found a key or value outside the canonical BLOB domain.";
            return false;
        }

        const void* key_data = nullptr;
        const void* value_data = nullptr;
        int key_size = 0;
        int value_size = 0;
        if (!ReadBlobColumn(
                reader,
                source,
                rows.Get(),
                0,
                key_data,
                key_size,
                "Failed to extract SQLite recovery key") ||
            !ReadBlobColumn(
                reader,
                source,
                rows.Get(),
                1,
                value_data,
                value_size,
                "Failed to extract SQLite recovery value")) {
            error = "Failed to extract a SQLite recovery row.";
            return false;
        }
        if (key_size == 0) {
            error =
                "SQLite recovery found reserved empty-key creation metadata.";
            return false;
        }

        CDataStream key(SER_DISK, CLIENT_VERSION);
        CDataStream value(SER_DISK, CLIENT_VERSION);
        StreamCleanser key_cleanser(key);
        StreamCleanser value_cleanser(value);
        try {
            key.write(
                static_cast<const char*>(key_data),
                key_size);
            if (value_size > 0) {
                value.write(
                    static_cast<const char*>(value_data),
                    value_size);
            }
        } catch (const std::bad_alloc&) {
            error = "Failed to allocate a SQLite recovery row.";
            return false;
        } catch (const std::exception&) {
            error = "Failed to copy a SQLite recovery row.";
            return false;
        }

        if (mode == SQLiteRecoveryMode::KEY_ONLY &&
            !validator.IsValid(key, value)) {
            continue;
        }
        if (!callback(key, value)) {
            if (error.empty()) {
                error = "Failed to process a SQLite recovery row.";
            }
            return false;
        }
        ++count;
    }
}

bool RecoveryCandidateRowCount(
    sqlite3* candidate,
    size_t& count,
    std::string& error)
{
    SQLiteStatement statement;
    if (!PrepareStatement(
            candidate,
            "SELECT count(*) FROM main NOT INDEXED",
            statement,
            "Failed to count SQLite recovery candidate rows",
            &error)) {
        return false;
    }
    const int result = sqlite3_step(statement.Get());
    if (result != SQLITE_ROW ||
        sqlite3_column_type(statement.Get(), 0) != SQLITE_INTEGER) {
        error = strprintf(
            "Failed to count SQLite recovery candidate rows: %s",
            sqlite3_errmsg(candidate));
        return false;
    }
    const sqlite3_int64 row_count =
        sqlite3_column_int64(statement.Get(), 0);
    if (row_count < 0 ||
        static_cast<uint64_t>(row_count) >
            std::numeric_limits<size_t>::max()) {
        error = "SQLite recovery candidate row count is out of range.";
        return false;
    }
    count = static_cast<size_t>(row_count);
    return true;
}

bool CopySQLiteRecoveryRows(
    sqlite3* source,
    sqlite3* candidate,
    SQLiteRecoveryMode mode,
    size_t& copied,
    std::string& error)
{
    copied = 0;
    if (!ExecuteSQL(
            candidate,
            "BEGIN IMMEDIATE TRANSACTION",
            &error)) {
        return false;
    }

    SQLiteStatement insert;
    if (!PrepareStatement(
            candidate,
            "INSERT INTO main(key, value) VALUES(?, ?)",
            insert,
            "Failed to prepare SQLite recovery insertion",
            &error)) {
        ExecuteSQL(candidate, "ROLLBACK TRANSACTION");
        return false;
    }

    const bool scanned = ForEachSQLiteRecoveryRow(
        source,
        mode,
        [&](const CDataStream& key, const CDataStream& value) {
            if (!BindBlob(
                    insert.Get(),
                    1,
                    key,
                    "recovery key") ||
                !BindBlob(
                    insert.Get(),
                    2,
                    value,
                    "recovery value")) {
                error =
                    "Failed to bind a SQLite recovery row.";
                return false;
            }
            const int result = sqlite3_step(insert.Get());
            const int reset_result =
                sqlite3_reset(insert.Get());
            const int clear_result =
                sqlite3_clear_bindings(insert.Get());
            if (result != SQLITE_DONE ||
                reset_result != SQLITE_OK ||
                clear_result != SQLITE_OK) {
                error = strprintf(
                    "Failed to insert a SQLite recovery row: %s",
                    sqlite3_errmsg(candidate));
                return false;
            }
            return true;
        },
        copied,
        error);
    if (!scanned || copied == 0) {
        ExecuteSQL(candidate, "ROLLBACK TRANSACTION");
        if (scanned && error.empty()) {
            error =
                "SQLite recovery found no records eligible for recovery.";
        }
        return false;
    }
    if (!ExecuteSQL(
            candidate,
            "COMMIT TRANSACTION",
            &error)) {
        if (sqlite3_get_autocommit(candidate) == 0) {
            ExecuteSQL(candidate, "ROLLBACK TRANSACTION");
        }
        return false;
    }
    if (sqlite3_get_autocommit(candidate) == 0) {
        ExecuteSQL(candidate, "ROLLBACK TRANSACTION");
        error =
            "SQLite recovery candidate remained in a transaction after commit.";
        return false;
    }
    return true;
}

bool VerifySQLiteRecoveryRows(
    sqlite3* source,
    sqlite3* candidate,
    SQLiteRecoveryMode mode,
    size_t expected_count,
    std::string& error)
{
    SQLiteStatement point;
    if (!PrepareStatement(
            candidate,
            "SELECT value FROM main WHERE key = ?",
            point,
            "Failed to prepare SQLite recovery comparison",
            &error)) {
        return false;
    }

    SQLiteColumnReader reader;
    size_t compared = 0;
    const bool scanned = ForEachSQLiteRecoveryRow(
        source,
        mode,
        [&](const CDataStream& key, const CDataStream& value) {
            if (!BindBlob(
                    point.Get(),
                    1,
                    key,
                    "recovery comparison key")) {
                error =
                    "Failed to bind a SQLite recovery comparison key.";
                return false;
            }
            const int result = sqlite3_step(point.Get());
            const void* candidate_value = nullptr;
            int candidate_size = 0;
            bool equal =
                result == SQLITE_ROW &&
                sqlite3_column_type(
                    point.Get(),
                    0) == SQLITE_BLOB &&
                ReadBlobColumn(
                    reader,
                    candidate,
                    point.Get(),
                    0,
                    candidate_value,
                    candidate_size,
                    "Failed to extract SQLite recovery comparison value") &&
                candidate_size ==
                    static_cast<int>(value.size()) &&
                (candidate_size == 0 ||
                    std::memcmp(
                        candidate_value,
                        value.data(),
                        value.size()) == 0);
            const int reset_result =
                sqlite3_reset(point.Get());
            const int clear_result =
                sqlite3_clear_bindings(point.Get());
            if (!equal ||
                reset_result != SQLITE_OK ||
                clear_result != SQLITE_OK) {
                error =
                    "SQLite recovery candidate does not exactly match its source rows.";
                return false;
            }
            return true;
        },
        compared,
        error);
    if (!scanned ||
        compared != expected_count) {
        if (scanned && error.empty()) {
            error =
                "SQLite recovery comparison row count changed.";
        }
        return false;
    }

    size_t candidate_count = 0;
    if (!RecoveryCandidateRowCount(
            candidate,
            candidate_count,
            error) ||
        candidate_count != expected_count) {
        if (error.empty()) {
            error =
                "SQLite recovery candidate contains an unexpected row count.";
        }
        return false;
    }
    return true;
}

bool VerifySQLiteMigrationPath(
    const fs::path& path,
    int retained_descriptor,
    const SQLiteFileIdentity& identity,
    std::string& error)
{
    error.clear();
    SQLiteFileIdentity verified_identity;
    if (!DescriptorIdentityMatches(retained_descriptor, identity) ||
        !VerifySQLiteHeaderDescriptor(
            retained_descriptor,
            path,
            verified_identity,
            error) ||
        !SameSQLiteFileIdentity(verified_identity, identity) ||
        !PathIdentityMatches(path, identity)) {
        if (error.empty()) {
            error = strprintf(
                "SQLite migration path '%s' does not match its retained candidate identity.",
                path.string());
        }
        return false;
    }
    if (!CheckAuxiliaryFiles(path, false, error)) {
        return false;
    }

    sqlite3* database = nullptr;
    if (!OpenSQLiteConnection(
            path,
            database,
            error,
            &identity)) {
        return false;
    }

    bool verified =
        VerifyDatabase(database, error) &&
        ValidateLogicalCreationMarker(
            database,
            path,
            SQLiteCreationMarkerPolicy::REQUIRE_ABSENT,
            error) &&
        SetConnectionPragmas(database, error) &&
        ConnectionIdentityMatches(
            database,
            path,
            identity,
            error) &&
        VerifyDatabase(database, error) &&
        ValidateLogicalCreationMarker(
            database,
            path,
            SQLiteCreationMarkerPolicy::REQUIRE_ABSENT,
            error);
    if (verified) {
        const int flush_result = sqlite3_db_cacheflush(database);
        if (flush_result != SQLITE_OK) {
            error = strprintf(
                "Failed to flush verified SQLite migration path '%s': %s",
                path.string(),
                sqlite3_errmsg(database));
            verified = false;
        }
    }

    if (!CloseSQLiteConnection(database)) {
        if (error.empty()) {
            error = strprintf(
                "Failed to close verified SQLite migration path '%s'.",
                path.string());
        } else {
            error += strprintf(
                " The verification connection for '%s' could not be closed.",
                path.string());
        }
        AbandonSQLiteConnection(database);
        return false;
    }
    if (!verified) {
        return false;
    }
#ifdef WIN32
    const int sync_result = _commit(retained_descriptor);
#else
    const int sync_result = fsync(retained_descriptor);
#endif
    if (sync_result != 0) {
        error = strprintf(
            "Failed to synchronize verified SQLite migration path '%s': %s",
            path.string(),
            std::strerror(errno));
        return false;
    }
    if (!CheckAuxiliaryFiles(path, false, error) ||
        !DescriptorIdentityMatches(retained_descriptor, identity) ||
        !PathIdentityMatches(path, identity)) {
        if (error.empty()) {
            error = strprintf(
                "Verified SQLite migration path '%s' lost its retained identity.",
                path.string());
        }
        return false;
    }
    return true;
}

class SQLiteDatabase;

class SQLiteCursor final : public DatabaseCursor
{
private:
    std::shared_lock<std::shared_mutex> m_connection_lock;
    sqlite3_stmt* m_statement{nullptr};
    std::shared_ptr<SQLiteColumnReader> m_column_reader;
    std::vector<unsigned char> m_start_key;

public:
    SQLiteCursor(
        std::shared_lock<std::shared_mutex> connection_lock,
        sqlite3_stmt* statement,
        std::shared_ptr<SQLiteColumnReader> column_reader,
        std::vector<unsigned char> start_key) noexcept
        : m_connection_lock(std::move(connection_lock)),
          m_statement(statement),
          m_column_reader(std::move(column_reader)),
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

        sqlite3* const database = sqlite3_db_handle(m_statement);
        if (!database || !m_column_reader) {
            return Status::FAIL;
        }

        key.SetType(SER_DISK);
        key.clear();
        const void* key_data = nullptr;
        int key_size = 0;
        if (!ReadBlobColumn(
                *m_column_reader,
                database,
                m_statement,
                0,
                key_data,
                key_size,
                "SQLiteCursor: Failed to extract record key") ||
            key_size == 0) {
            return Status::FAIL;
        }
        try {
            key.write(
                static_cast<const char*>(key_data),
                key_size);
        } catch (...) {
            CleanseStream(key);
            key.clear();
            return Status::FAIL;
        }

        value.SetType(SER_DISK);
        value.clear();
        const void* value_data = nullptr;
        int value_size = 0;
        if (!ReadBlobColumn(
                *m_column_reader,
                database,
                m_statement,
                1,
                value_data,
                value_size,
                "SQLiteCursor: Failed to extract record value")) {
            CleanseStream(key);
            key.clear();
            return Status::FAIL;
        }
        if (value_size > 0) {
            try {
                value.write(
                    static_cast<const char*>(value_data),
                    value_size);
            } catch (...) {
                CleanseStream(key);
                CleanseStream(value);
                key.clear();
                value.clear();
                return Status::FAIL;
            }
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
    fs::path m_recovery_backup_path;
    sqlite3* m_database{nullptr};
    int m_identity_descriptor{-1};
    SQLiteFileIdentity m_identity;
    bool m_sqlite_acquired{false};
    bool* m_failed_creation_cleanup_allowed{nullptr};
    SQLiteCreationState m_creation_state{
        SQLiteCreationState::NONE};
    bool m_creation_cleanup_allowed{false};
    bool m_completed_logical_creation{false};
    const bool m_migration_candidate{false};
    std::unique_ptr<SQLiteStatementExecutor> m_creation_executor{
        std::make_unique<SQLiteStatementExecutor>()};
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
        bool* cleanup_allowed = nullptr,
        std::optional<SQLiteCreationMarkerPolicy> marker_policy = std::nullopt)
    {
        if (m_poisoned.load() || m_database) {
            error = strprintf(
                "SQLite wallet '%s' is quarantined after an unrecoverable connection error.",
                m_filename);
            Poison();
            return false;
        }
        const SQLiteCreationMarkerPolicy required_marker =
            marker_policy.value_or(
                m_creation_state == SQLiteCreationState::PENDING ?
                    SQLiteCreationMarkerPolicy::REQUIRE_PRESENT :
                    SQLiteCreationMarkerPolicy::REQUIRE_ABSENT);
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
        if (!VerifyDatabase(m_database, error) ||
            !ValidateLogicalCreationMarker(
                m_database,
                m_path,
                required_marker,
                error)) {
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
            !VerifyDatabase(m_database, error) ||
            !ValidateLogicalCreationMarker(
                m_database,
                m_path,
                required_marker,
                error)) {
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
        bool logical_wallet_create,
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
            !CreateSchema(
                m_database,
                logical_wallet_create,
                error) ||
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
                &candidate.cleanup_allowed,
                logical_wallet_create ?
                    SQLiteCreationMarkerPolicy::REQUIRE_PRESENT :
                    SQLiteCreationMarkerPolicy::REQUIRE_ABSENT)) {
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
        if (logical_wallet_create) {
            m_creation_state = SQLiteCreationState::PENDING;
            m_creation_cleanup_allowed =
                candidate.cleanup_allowed;
        }
        m_usable.store(true);
        return true;
    }

    bool PreparePendingCleanupLocked(std::string& error)
    {
        if (m_creation_state != SQLiteCreationState::PENDING ||
            !m_creation_cleanup_allowed) {
            return false;
        }
        {
            std::lock_guard<std::mutex> state_lock(m_state_mutex);
            if (m_batch_count != 0) {
                error =
                    "active wallet database batches still exist";
                return false;
            }
        }
        if (!m_database ||
            m_poisoned.load() ||
            !m_usable.load()) {
            error =
                "the SQLite connection is not healthy";
            return false;
        }
        std::string marker_error;
        if (ReadLogicalCreationMarker(
                m_database,
                marker_error) !=
            SQLiteCreationMarkerState::PRESENT) {
            error = marker_error.empty() ?
                        "the exact incomplete-creation marker is not present" :
                        marker_error;
            return false;
        }
        return true;
    }

    bool RemoveMigrationCandidateLocked(std::string& error)
    {
        if (m_database && !CloseSQLiteConnection(m_database)) {
            error = strprintf(
                "Failed to close SQLite migration candidate '%s' before cleanup.",
                m_path.string());
            AbandonSQLiteConnection(m_database);
            return false;
        }
        {
            std::lock_guard<std::mutex> state_lock(m_state_mutex);
            m_open = false;
        }
        Poison();

        const fs::path parent =
            m_path.parent_path().empty() ?
                fs::path(".") :
                m_path.parent_path();
        if (!OwnerControlledMigrationDirectory(
                parent,
                error)) {
            return false;
        }
        if (m_identity_descriptor < 0 ||
            !PrivateSQLiteIdentityMatches(
                m_identity_descriptor,
                m_path,
                m_identity)) {
            if (error.empty()) {
                error = strprintf(
                    "SQLite migration candidate '%s' lost its retained identity.",
                    m_path.string());
            }
            return false;
        }
        if (!CheckAuxiliaryFiles(m_path, false, error) ||
            !RemoveOwnedPath(m_path, m_identity, error)) {
            return false;
        }
        if (!DescriptorIdentityIsUnlinked(
                m_identity_descriptor,
                m_identity)) {
            error = strprintf(
                "SQLite migration candidate pathname '%s' was removed, but the retained candidate inode was not proven unlinked.",
                m_path.string());
            return false;
        }
        if (!SyncDirectory(
                parent,
                error,
                true)) {
            return false;
        }
        m_creation_state = SQLiteCreationState::NONE;
        m_creation_cleanup_allowed = false;
        m_completed_logical_creation = false;
        return true;
    }

    void RemovePendingCreationLocked()
    {
        if (m_creation_state != SQLiteCreationState::PENDING ||
            !m_creation_cleanup_allowed ||
            m_database) {
            return;
        }

        std::string error;
        SQLiteFileIdentity verified_identity;
        if (!DescriptorIdentityMatches(
                m_identity_descriptor,
                m_identity) ||
            !VerifySQLiteHeaderDescriptor(
                m_identity_descriptor,
                m_path,
                verified_identity,
                error) ||
            !SameSQLiteFileIdentity(
                verified_identity,
                m_identity) ||
            !PathIdentityMatches(m_path, m_identity)) {
            LogPrintf(
                "SQLiteDatabase: Leaving incomplete wallet '%s' because its retained identity could not be verified: %s\n",
                m_filename,
                error.empty() ? "identity mismatch" : error);
            m_creation_cleanup_allowed = false;
            return;
        }
        if (!CheckAuxiliaryFiles(m_path, false, error)) {
            LogPrintf(
                "SQLiteDatabase: Leaving incomplete wallet '%s' because auxiliary state exists: %s\n",
                m_filename,
                error);
            m_creation_cleanup_allowed = false;
            return;
        }
        if (!RemoveOwnedPath(m_path, m_identity, error)) {
            LogPrintf(
                "SQLiteDatabase: Failed to remove incomplete wallet '%s': %s\n",
                m_filename,
                error);
            m_creation_cleanup_allowed = false;
            return;
        }

        const fs::path parent =
            m_path.parent_path().empty() ?
                fs::path(".") :
                m_path.parent_path();
        if (!SyncDirectory(parent, error)) {
            LogPrintf(
                "SQLiteDatabase: Failed to synchronize incomplete wallet cleanup for '%s': %s\n",
                m_filename,
                error);
        }
        m_creation_cleanup_allowed = false;
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

    DatabaseCreationResult MarkCreationIndeterminate(
        std::string& error,
        const std::string& reason)
    {
        m_creation_state =
            SQLiteCreationState::INDETERMINATE;
        m_creation_cleanup_allowed = false;
        {
            std::lock_guard<std::mutex> state_lock(m_state_mutex);
            m_open = false;
        }
        Poison();
        StartShutdown();
        try {
            error = strprintf(
                "SQLite wallet '%s' creation outcome is indeterminate: %s",
                m_filename,
                reason);
        } catch (...) {
        }
        LogPrintf(
            "SQLiteDatabase: Logical creation outcome for '%s' is indeterminate; retaining the wallet and shutting down.\n",
            m_filename);
        return DatabaseCreationResult::INDETERMINATE;
    }

    bool ValidateOwnedConnectionLocked(std::string& error)
    {
        SQLiteFileIdentity verified_identity;
        if (m_identity_descriptor < 0 ||
            !DescriptorIdentityMatches(
                m_identity_descriptor,
                m_identity) ||
            !VerifySQLiteHeaderDescriptor(
                m_identity_descriptor,
                m_path,
                verified_identity,
                error) ||
            !SameSQLiteFileIdentity(
                verified_identity,
                m_identity) ||
            !PathIdentityMatches(m_path, m_identity) ||
            !m_database ||
            !ConnectionIdentityMatches(
                m_database,
                m_path,
                m_identity,
                error)) {
            if (error.empty()) {
                error =
                    "retained SQLite wallet identity changed";
            }
            return false;
        }
        return true;
    }

    bool SynchronizeReconciledCreationStateLocked(
        SQLiteCreationMarkerState& marker,
        std::string& error)
    {
        marker = ReadLogicalCreationMarker(
            m_database,
            error);
        if (marker != SQLiteCreationMarkerState::ABSENT &&
            marker != SQLiteCreationMarkerState::PRESENT) {
            return false;
        }
        const int flush_result =
            sqlite3_db_cacheflush(m_database);
        if (flush_result != SQLITE_OK) {
            error = strprintf(
                "failed to flush reconciled SQLite state: %s",
                sqlite3_errmsg(m_database));
            return false;
        }
        if (!ValidateOwnedConnectionLocked(error)) {
            return false;
        }
#ifdef WIN32
        if (_commit(m_identity_descriptor) != 0) {
#else
        if (fsync(m_identity_descriptor) != 0) {
#endif
            error = strprintf(
                "failed to synchronize retained SQLite wallet identity: %s",
                std::strerror(errno));
            return false;
        }
        if (!CheckAuxiliaryFiles(m_path, false, error)) {
            return false;
        }
        const fs::path parent =
            m_path.parent_path().empty() ?
                fs::path(".") :
                m_path.parent_path();
        if (!SyncDirectory(parent, error)) {
            return false;
        }

        std::string second_error;
        const SQLiteCreationMarkerState second =
            ReadLogicalCreationMarker(
                m_database,
                second_error);
        if (second != marker) {
            error = second_error.empty() ?
                        "SQLite logical-creation marker changed during reconciliation" :
                        second_error;
            return false;
        }
        return ValidateOwnedConnectionLocked(error);
    }

    DatabaseCreationResult ReconcileCreationCompletionLocked(
        std::string& error)
    {
        {
            std::lock_guard<std::mutex> state_lock(m_state_mutex);
            m_open = false;
        }
        m_usable.store(false);
        if (!CloseOrAbandonSQLiteConnection(
                m_database,
                &m_creation_cleanup_allowed)) {
            return MarkCreationIndeterminate(
                error,
                "the post-commit connection could not be closed");
        }

        SQLiteFileIdentity verified_identity;
        std::string identity_error;
        if (!DescriptorIdentityMatches(
                m_identity_descriptor,
                m_identity) ||
            !VerifySQLiteHeaderDescriptor(
                m_identity_descriptor,
                m_path,
                verified_identity,
                identity_error) ||
            !SameSQLiteFileIdentity(
                verified_identity,
                m_identity) ||
            !PathIdentityMatches(m_path, m_identity)) {
            return MarkCreationIndeterminate(
                error,
                identity_error.empty() ?
                    "the retained wallet identity changed" :
                    identity_error);
        }

        std::string reopen_error;
        if (!OpenExistingLocked(
                reopen_error,
                &m_creation_cleanup_allowed,
                SQLiteCreationMarkerPolicy::ALLOW_EITHER)) {
            return MarkCreationIndeterminate(
                error,
                reopen_error.empty() ?
                    "the wallet could not be reopened for reconciliation" :
                    reopen_error);
        }
        {
            std::lock_guard<std::mutex> state_lock(m_state_mutex);
            m_open = true;
        }

        SQLiteCreationMarkerState marker{
            SQLiteCreationMarkerState::FAILED};
        std::string sync_error;
        if (!SynchronizeReconciledCreationStateLocked(
                marker,
                sync_error)) {
            return MarkCreationIndeterminate(
                error,
                sync_error.empty() ?
                    "the durable marker postcondition could not be verified" :
                    sync_error);
        }
        if (marker == SQLiteCreationMarkerState::ABSENT) {
            m_creation_state = SQLiteCreationState::NONE;
            m_creation_cleanup_allowed = false;
            m_completed_logical_creation = true;
            m_usable.store(true);
            error.clear();
            return DatabaseCreationResult::COMPLETE;
        }
        if (marker == SQLiteCreationMarkerState::PRESENT) {
            m_creation_state =
                SQLiteCreationState::PENDING;
            m_usable.store(true);
            error = strprintf(
                "SQLite wallet '%s' logical creation did not complete; the incomplete marker remains.",
                m_filename);
            return DatabaseCreationResult::FAILED;
        }
        return MarkCreationIndeterminate(
            error,
            "the durable marker has an invalid state");
    }

    DatabaseCreationResult RollBackCreationCompletionLocked(
        std::string& error)
    {
        int result;
        try {
            result = m_creation_executor->Execute(
                m_database,
                "ROLLBACK TRANSACTION");
        } catch (...) {
            result = SQLITE_ABORT;
        }
        if (result == SQLITE_OK &&
            sqlite3_get_autocommit(m_database) != 0) {
            std::string marker_error;
            if (ReadLogicalCreationMarker(
                    m_database,
                    marker_error) ==
                SQLiteCreationMarkerState::PRESENT) {
                error = strprintf(
                    "SQLite wallet '%s' logical creation did not complete; its transaction was rolled back.",
                    m_filename);
                return DatabaseCreationResult::FAILED;
            }
        }
        return ReconcileCreationCompletionLocked(error);
    }

public:
    SQLiteDatabase(
        std::string filename,
        fs::path path,
        bool migration_candidate)
        : m_filename(std::move(filename)),
          m_path(std::move(path)),
          m_migration_candidate(migration_candidate)
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
            bool pending_cleanup_ready = false;
            if (m_creation_state == SQLiteCreationState::PENDING) {
                std::string cleanup_error;
                pending_cleanup_ready =
                    PreparePendingCleanupLocked(cleanup_error);
                if (!pending_cleanup_ready) {
                    m_creation_cleanup_allowed = false;
                    LogPrintf(
                        "SQLiteDatabase: Leaving incomplete wallet '%s' because safe cleanup could not be certified: %s\n",
                        m_filename,
                        cleanup_error.empty() ?
                            "unknown lifecycle state" :
                            cleanup_error);
                }
            }
            bool* const cleanup_allowed =
                m_failed_creation_cleanup_allowed ?
                    m_failed_creation_cleanup_allowed :
                m_creation_state ==
                        SQLiteCreationState::PENDING ?
                    &m_creation_cleanup_allowed :
                    nullptr;
            const bool closed = CloseOrAbandonSQLiteConnection(
                m_database,
                cleanup_allowed);
            if (pending_cleanup_ready && closed) {
                RemovePendingCreationLocked();
            }
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
            m_creation_cleanup_allowed = false;
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
            m_creation_cleanup_allowed = false;
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
        bool logical_wallet_create,
        PublishResult& publish_result,
        std::string& error)
    {
        m_failed_creation_cleanup_allowed =
            &candidate.cleanup_allowed;
        std::unique_lock<std::shared_mutex> lock(m_connection_mutex);
        const bool initialized =
            CreateLocked(
                candidate,
                logical_wallet_create,
                publish_result,
                error);
        if (initialized) {
            m_failed_creation_cleanup_allowed = nullptr;
        }
        std::lock_guard<std::mutex> state_lock(m_state_mutex);
        m_open = initialized;
        return initialized;
    }

    const std::string& Filename() const override { return m_filename; }
    DatabaseFormat Format() const override { return DatabaseFormat::SQLITE; }
    std::string RecoveryBackupPath() const override
    {
        return m_recovery_backup_path.string();
    }
    void SetRecoveryBackupPath(fs::path path)
    {
        m_recovery_backup_path = std::move(path);
    }
    std::unique_ptr<DatabaseBatch> MakeBatch(const DatabaseBatchOptions& options) override;
    DatabaseCreationResult CompleteCreation(std::string& error) override;
    bool Rewrite(const char* skip) override;
    bool Backup(const std::string& destination) override;
    bool Backup(
        const std::string& destination,
        std::string& error) override;
    bool PeriodicFlush() override;
    void Flush(bool shutdown) override;

    bool SetCreationExecutor(
        std::unique_ptr<SQLiteStatementExecutor> executor)
    {
        if (!executor ||
            m_creation_state !=
                SQLiteCreationState::PENDING) {
            return false;
        }
        m_creation_executor = std::move(executor);
        return true;
    }

    SQLiteMigrationPublishResult PublishMigration(
        BerkeleyDatabase& source,
        std::string& error);
};

enum class SQLiteTransactionState {
    NONE,
    ACTIVE,
    AUTO_ROLLED_BACK,
    COMMIT_INDETERMINATE,
};

class SQLiteBatch final : public DatabaseBatch
{
private:
    SQLiteDatabase& m_database;
    const bool m_read_only;
    const bool m_flush_on_close;
    std::unique_ptr<SQLiteStatementExecutor> m_executor{
        std::make_unique<SQLiteStatementExecutor>()};
    std::shared_ptr<SQLiteColumnReader> m_column_reader{
        std::make_shared<SQLiteColumnReader>()};
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
        const SQLiteTransactionState state = m_transaction.load();
        return state == SQLiteTransactionState::AUTO_ROLLED_BACK ||
               state == SQLiteTransactionState::COMMIT_INDETERMINATE;
    }

    bool IsCommitIndeterminate() const
    {
        return m_transaction.load() ==
               SQLiteTransactionState::COMMIT_INDETERMINATE;
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

    void MarkCommitIndeterminate(const char* operation) noexcept
    {
        m_transaction.store(
            SQLiteTransactionState::COMMIT_INDETERMINATE);
        m_database.Poison();
        StartShutdown();
        LogPrintf(
            "SQLiteBatch: %s outcome is indeterminate; quarantining the database and shutting down.\n",
            operation);
    }

    bool HandleCommitExecutorException() noexcept
    {
        if (m_database.m_database &&
            sqlite3_get_autocommit(m_database.m_database) == 0) {
            LogPrintf(
                "SQLiteBatch: Statement executor threw while committing; the transaction remains active.\n");
            return false;
        }
        MarkCommitIndeterminate("wallet transaction commit");
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

    bool RecoverFailedWriteTransaction() noexcept
    {
        try {
            return HasActiveTxn() &&
                   TxnAbort() &&
                   !HasActiveTxn();
        } catch (...) {
            return false;
        }
    }

    [[noreturn]] void ThrowIndeterminateWrite(
        const char* operation)
    {
        m_database.Poison();
        StartShutdown();
        LogPrintf(
            "SQLiteBatch: %s outcome is indeterminate; quarantining the database and shutting down.\n",
            operation);
        throw std::runtime_error(strprintf(
            "SQLite %s outcome is indeterminate.",
            operation));
    }

    template <typename Operation>
    bool ExecuteCheckedWrite(
        const char* operation,
        Operation&& execute)
    {
        if (IsActive()) {
            return execute();
        }

        if (!TxnBegin()) {
            if (HasActiveTxn() &&
                !RecoverFailedWriteTransaction()) {
                ThrowIndeterminateWrite(operation);
            }
            return false;
        }

        bool wrote;
        try {
            wrote = execute();
        } catch (...) {
            if (!RecoverFailedWriteTransaction()) {
                m_database.Poison();
                StartShutdown();
            }
            throw;
        }
        if (!wrote) {
            if (!RecoverFailedWriteTransaction()) {
                ThrowIndeterminateWrite(operation);
            }
            return false;
        }

        if (TxnCommit()) {
            return true;
        }
        if (HasActiveTxn() &&
            RecoverFailedWriteTransaction()) {
            return false;
        }
        ThrowIndeterminateWrite(operation);
    }

    DatabaseReadStatus ReadRaw(CDataStream&& key, CDataStream& value) override
    {
        StreamCleanser key_cleanser(key);
        if (m_closed.load() || IsQuarantined()) {
            return DatabaseReadStatus::FAILED;
        }

        std::shared_lock<std::shared_mutex> connection_lock;
        if (!IsActive()) {
            connection_lock =
                std::shared_lock<std::shared_mutex>(m_database.m_connection_mutex);
        }
        TransactionGateReleaser gate_releaser(*this);
        if (!CanUseConnection()) {
            return DatabaseReadStatus::FAILED;
        }

        SQLiteStatement statement;
        if (!PrepareStatement(
                m_database.m_database,
                "SELECT value FROM main WHERE key = ?",
                statement,
                "SQLiteBatch: Failed to prepare read") ||
            !BindBlob(statement.Get(), 1, key, "key")) {
            ReconcileAfterError();
            return DatabaseReadStatus::FAILED;
        }

        const int result = sqlite3_step(statement.Get());
        if (result == SQLITE_DONE) {
            return DatabaseReadStatus::NOT_FOUND;
        }
        if (result != SQLITE_ROW) {
            ReconcileAfterError();
            LogSQLiteError(
                "SQLiteBatch: Failed to read record",
                m_database.m_database,
                result);
            return DatabaseReadStatus::FAILED;
        }
        if (sqlite3_column_type(statement.Get(), 0) != SQLITE_BLOB) {
            LogPrintf("SQLiteBatch: Wallet record has a non-BLOB value.\n");
            return DatabaseReadStatus::CORRUPT;
        }

        const void* data = nullptr;
        int size = 0;
        if (!ReadBlobColumn(
                *m_column_reader,
                m_database.m_database,
                statement.Get(),
                0,
                data,
                size,
                "SQLiteBatch: Failed to extract record value")) {
            ReconcileAfterError();
            return DatabaseReadStatus::FAILED;
        }

        value.SetType(SER_DISK);
        value.clear();
        if (size > 0) {
            try {
                value.write(
                    static_cast<const char*>(data),
                    size);
            } catch (...) {
                value.clear();
                return DatabaseReadStatus::FAILED;
            }
        }
        return DatabaseReadStatus::SUCCESS;
    }

    bool WriteRaw(CDataStream&& key, CDataStream&& value, bool overwrite) override
    {
        StreamCleanser key_cleanser(key);
        StreamCleanser value_cleanser(value);
        if (m_read_only || m_closed.load() || IsQuarantined()) {
            return false;
        }

        return ExecuteCheckedWrite(
            "wallet record write",
            [&] {
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
            });
    }

    bool EraseRaw(CDataStream&& key) override
    {
        StreamCleanser key_cleanser(key);
        if (m_read_only || m_closed.load() || IsQuarantined()) {
            return false;
        }

        return ExecuteCheckedWrite(
            "wallet record erase",
            [&] {
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
            });
    }

    DatabaseReadStatus HasRaw(CDataStream&& key) override
    {
        StreamCleanser key_cleanser(key);
        if (m_closed.load() || IsQuarantined()) {
            return DatabaseReadStatus::FAILED;
        }

        std::shared_lock<std::shared_mutex> connection_lock;
        if (!IsActive()) {
            connection_lock =
                std::shared_lock<std::shared_mutex>(m_database.m_connection_mutex);
        }
        TransactionGateReleaser gate_releaser(*this);
        if (!CanUseConnection()) {
            return DatabaseReadStatus::FAILED;
        }

        SQLiteStatement statement;
        if (!PrepareStatement(
                m_database.m_database,
                "SELECT 1 FROM main WHERE key = ?",
                statement,
                "SQLiteBatch: Failed to prepare existence query") ||
            !BindBlob(statement.Get(), 1, key, "key")) {
            ReconcileAfterError();
            return DatabaseReadStatus::FAILED;
        }
        const int result = sqlite3_step(statement.Get());
        if (result == SQLITE_ROW) {
            return DatabaseReadStatus::SUCCESS;
        }
        if (result == SQLITE_DONE) {
            return DatabaseReadStatus::NOT_FOUND;
        }
        ReconcileAfterError();
        LogSQLiteError(
            "SQLiteBatch: Failed to query record existence",
            m_database.m_database,
            result);
        return DatabaseReadStatus::FAILED;
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

        return ExecuteCheckedWrite(
            "wallet version initialization",
            [&] {
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
                    ReconcileAfterError();
                    return false;
                }
                const int result = sqlite3_step(statement.Get());
                if (result != SQLITE_DONE) {
                    ReconcileAfterError();
                    LogSQLiteError(
                        "SQLiteBatch: Failed to initialize wallet version",
                        m_database.m_database,
                        result);
                    return false;
                }
                return true;
            });
    }

    bool SetExecutor(std::unique_ptr<SQLiteStatementExecutor> executor)
    {
        if (!executor || m_closed.load()) {
            return false;
        }
        m_executor = std::move(executor);
        return true;
    }

    bool SetColumnReader(std::unique_ptr<SQLiteColumnReader> reader)
    {
        if (!reader || m_closed.load()) {
            return false;
        }
        m_column_reader =
            std::shared_ptr<SQLiteColumnReader>(
                std::move(reader));
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
            "SELECT key, value FROM main "
            "WHERE length(key) != 0 ORDER BY key",
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
                m_column_reader,
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
            "SELECT key, value FROM main "
            "WHERE length(key) != 0 AND key >= ? ORDER BY key",
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
                m_column_reader,
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
            return HandleCommitExecutorException();
        }
        if (result != SQLITE_OK) {
            if (m_database.m_database &&
                sqlite3_get_autocommit(m_database.m_database) != 0) {
                MarkCommitIndeterminate("wallet transaction commit");
            }
            LogSQLiteError(
                "SQLiteBatch: Failed to commit transaction",
                m_database.m_database,
                result);
            ReleaseTransactionGates();
            return false;
        }

        if (sqlite3_get_autocommit(m_database.m_database) == 0) {
            LogPrintf(
                "SQLiteBatch: Commit reported success while retaining an active transaction.\n");
            return false;
        }
        m_transaction.store(SQLiteTransactionState::NONE);
        ReleaseTransactionGates();
        return true;
    }

    bool TxnAbort() override
    {
        if (IsCommitIndeterminate()) {
            ReleaseTransactionGates();
            return false;
        }
        if (IsQuarantined()) {
            ReleaseTransactionGates();
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
        const SQLiteTransactionState state = m_transaction.load();
        return state == SQLiteTransactionState::ACTIVE ||
               state == SQLiteTransactionState::AUTO_ROLLED_BACK;
    }
};

DatabaseCreationResult SQLiteDatabase::CompleteCreation(
    std::string& error)
{
    error.clear();
    std::unique_lock<std::mutex> writer_lock(
        m_writer_mutex);
    std::unique_lock<std::shared_mutex> connection_lock(
        m_connection_mutex);

    if (m_creation_state == SQLiteCreationState::NONE) {
        return DatabaseCreationResult::COMPLETE;
    }
    if (m_creation_state ==
        SQLiteCreationState::PUBLISHED) {
        error =
            "The SQLite migration candidate was already published and consumed.";
        return DatabaseCreationResult::FAILED;
    }
    if (m_creation_state ==
        SQLiteCreationState::INDETERMINATE) {
        return MarkCreationIndeterminate(
            error,
            "the owner was already indeterminate");
    }

    bool has_batches;
    {
        std::lock_guard<std::mutex> state_lock(
            m_state_mutex);
        has_batches = m_batch_count != 0;
    }
    if (has_batches) {
        return MarkCreationIndeterminate(
            error,
            "active database batches remain");
    }
    if (m_poisoned.load() ||
        !m_usable.load() ||
        !ValidateOwnedConnectionLocked(error)) {
        return MarkCreationIndeterminate(
            error,
            error.empty() ?
                "the owned database connection is not healthy" :
                error);
    }
    if (sqlite3_get_autocommit(m_database) == 0) {
        return MarkCreationIndeterminate(
            error,
            "an unrelated transaction is active");
    }

    std::string marker_error;
    if (ReadLogicalCreationMarker(
            m_database,
            marker_error) !=
        SQLiteCreationMarkerState::PRESENT) {
        return MarkCreationIndeterminate(
            error,
            marker_error.empty() ?
                "the exact incomplete-creation marker is missing" :
                marker_error);
    }

    int result;
    try {
        result = m_creation_executor->Execute(
            m_database,
            "BEGIN IMMEDIATE TRANSACTION");
    } catch (...) {
        result = SQLITE_ABORT;
    }
    if (result != SQLITE_OK) {
        if (m_database &&
            sqlite3_get_autocommit(m_database) == 0) {
            return RollBackCreationCompletionLocked(error);
        }
        return ReconcileCreationCompletionLocked(error);
    }
    if (sqlite3_get_autocommit(m_database) != 0) {
        return ReconcileCreationCompletionLocked(error);
    }

    if (!DeleteLogicalCreationMarker(
            m_database,
            error)) {
        if (sqlite3_get_autocommit(m_database) == 0) {
            return RollBackCreationCompletionLocked(error);
        }
        return ReconcileCreationCompletionLocked(error);
    }

    try {
        result = m_creation_executor->Execute(
            m_database,
            "COMMIT TRANSACTION");
    } catch (...) {
        result = SQLITE_ABORT;
    }
    if (result == SQLITE_OK &&
        sqlite3_get_autocommit(m_database) != 0) {
        std::string completed_error;
        if (ReadLogicalCreationMarker(
                m_database,
                completed_error) ==
            SQLiteCreationMarkerState::ABSENT) {
            m_creation_state = SQLiteCreationState::NONE;
            m_creation_cleanup_allowed = false;
            m_completed_logical_creation = true;
            error.clear();
            return DatabaseCreationResult::COMPLETE;
        }
        return ReconcileCreationCompletionLocked(error);
    }
    if (sqlite3_get_autocommit(m_database) == 0) {
        return RollBackCreationCompletionLocked(error);
    }
    return ReconcileCreationCompletionLocked(error);
}

SQLiteMigrationPublishResult SQLiteDatabase::PublishMigration(
    BerkeleyDatabase& source,
    std::string& error)
{
#if !((defined(__linux__) && defined(SYS_renameat2)) || defined(__APPLE__))
    error =
        "Atomic SQLite/BDB migration publication is unavailable on this platform.";
    return SQLiteMigrationPublishResult::FAILED;
#endif

    fs::path source_path;
    fs::path backup_path;
    bool exchange_attempted = false;
    bool candidate_cleanup_authorized = false;

    auto mark_indeterminate =
        [&](const std::string& reason) noexcept {
            m_creation_state =
                SQLiteCreationState::INDETERMINATE;
            m_creation_cleanup_allowed = false;
            m_completed_logical_creation = false;
            try {
                std::lock_guard<std::mutex> state_lock(
                    m_state_mutex);
                m_open = false;
            } catch (...) {
            }
            Poison();
            StartShutdown();
            try {
                error = strprintf(
                    "SQLite migration publication is indeterminate: %s "
                    "Migration working path: '%s'. Wallet path: '%s'. "
                    "Backup path: '%s'. Preserve these paths and restart Firo "
                    "only after recovery.",
                    reason,
                    m_path.string(),
                    source_path.string(),
                    backup_path.string());
            } catch (...) {
                try {
                    error =
                        "SQLite migration publication is indeterminate; "
                        "preserve the wallet, migration, and backup paths.";
                } catch (...) {
                }
            }
            return SQLiteMigrationPublishResult::INDETERMINATE;
        };

    auto fail_from_exception =
        [&](const char* detail) noexcept {
            if (exchange_attempted) {
                return mark_indeterminate(
                    "an exception occurred after atomic exchange was attempted");
            }
            if (!candidate_cleanup_authorized) {
                try {
                    error = strprintf(
                        "SQLite migration publication failed before atomic "
                        "exchange without consuming the candidate: %s",
                        detail);
                } catch (...) {
                }
                return SQLiteMigrationPublishResult::FAILED;
            }

            try {
                std::unique_lock<std::mutex> writer_lock(
                    m_writer_mutex);
                std::unique_lock<std::shared_mutex> connection_lock(
                    m_connection_mutex);
                std::string cleanup_error;
                if (RemoveMigrationCandidateLocked(
                        cleanup_error)) {
                    error = strprintf(
                        "SQLite migration publication failed before atomic "
                        "exchange: %s The exact owned candidate '%s' was removed.",
                        detail,
                        m_path.string());
                    return SQLiteMigrationPublishResult::FAILED;
                }
            } catch (...) {
            }
            return mark_indeterminate(
                "an exception occurred before atomic exchange and candidate "
                "cleanup could not be certified");
        };

    try {
        error.clear();
        std::unique_lock<std::mutex> writer_lock(
            m_writer_mutex);
        std::unique_lock<std::shared_mutex> connection_lock(
            m_connection_mutex);

        backup_path = source.MigrationBackupPath();
        if (!m_migration_candidate) {
            error =
                "Refusing SQLite migration publication because the database "
                "owner has no migration-candidate capability.";
            return SQLiteMigrationPublishResult::FAILED;
        }
        if (m_filename.empty() ||
            m_filename.front() != '.' ||
            m_path.filename().string() != m_filename) {
            error = strprintf(
                "Refusing SQLite migration publication because '%s' is not "
                "an owned hidden candidate path.",
                m_path.string());
            return SQLiteMigrationPublishResult::FAILED;
        }
        if (m_creation_state ==
            SQLiteCreationState::PUBLISHED) {
            error =
                "The SQLite migration candidate was already published and consumed.";
            return SQLiteMigrationPublishResult::FAILED;
        }
        if (m_creation_state ==
            SQLiteCreationState::INDETERMINATE) {
            return mark_indeterminate(
                "the SQLite candidate owner was already indeterminate");
        }
        if (m_creation_state == SQLiteCreationState::NONE &&
            !m_completed_logical_creation) {
            error = strprintf(
                "Refusing SQLite migration publication because '%s' is not "
                "the completed logical-creation candidate owned by this operation.",
                m_path.string());
            return SQLiteMigrationPublishResult::FAILED;
        }
        candidate_cleanup_authorized = true;

        size_t batch_count;
        bool open;
        {
            std::lock_guard<std::mutex> state_lock(
                m_state_mutex);
            batch_count = m_batch_count;
            open = m_open;
            if (batch_count == 0 && open) {
                m_open = false;
            }
        }
        if (batch_count != 0) {
            return mark_indeterminate(
                "active SQLite candidate batches remain");
        }

        auto fail_before_exchange =
            [&](const std::string& reason) {
                std::string cleanup_error;
                if (!RemoveMigrationCandidateLocked(
                        cleanup_error)) {
                    return mark_indeterminate(
                        strprintf(
                            "%s The pre-exchange candidate could not be "
                            "removed safely: %s",
                            reason,
                            cleanup_error.empty() ?
                                "unknown cleanup failure" :
                                cleanup_error));
                }
                error = strprintf(
                    "SQLite migration was not published: %s "
                    "Removed the exact owned candidate '%s'; the BDB source "
                    "'%s' and backup '%s' were not replaced.",
                    reason,
                    m_path.string(),
                    source_path.string(),
                    backup_path.string());
                return SQLiteMigrationPublishResult::FAILED;
            };

        std::string path_error;
        if (!GetWalletDatabasePath(
                source.Filename(),
                source_path,
                path_error)) {
            return fail_before_exchange(
                path_error);
        }
        if (source_path == m_path ||
            backup_path.empty() ||
            backup_path == m_path ||
            backup_path == source_path) {
            return fail_before_exchange(
                strprintf(
                    "candidate '%s', final '%s', and backup '%s' are not "
                    "distinct migration paths",
                    m_path.string(),
                    source_path.string(),
                    backup_path.string()));
        }
        const fs::path parent =
            source_path.parent_path().empty() ?
                fs::path(".") :
                source_path.parent_path();
        const fs::path candidate_parent =
            m_path.parent_path().empty() ?
                fs::path(".") :
                m_path.parent_path();
        const fs::path backup_parent =
            backup_path.parent_path().empty() ?
                fs::path(".") :
                backup_path.parent_path();
        if (candidate_parent != parent ||
            backup_parent != parent) {
            return fail_before_exchange(
                "the candidate, source, and backup are not in one migration directory");
        }
        if (!OwnerControlledMigrationDirectory(
                parent,
                path_error)) {
            return mark_indeterminate(
                path_error);
        }
        if (!CheckAuxiliaryFiles(
                source_path,
                false,
                path_error)) {
            return fail_before_exchange(
                path_error);
        }
        if (m_creation_state != SQLiteCreationState::NONE ||
            !m_completed_logical_creation) {
            return fail_before_exchange(
                "the SQLite candidate logical creation is incomplete");
        }
        if (!open ||
            !m_database ||
            m_poisoned.load() ||
            !m_usable.load()) {
            return fail_before_exchange(
                "the SQLite candidate connection is not healthy");
        }
        if (sqlite3_get_autocommit(m_database) == 0) {
            return fail_before_exchange(
                "the SQLite candidate has an active transaction despite having no batches");
        }

        SQLiteFileIdentity verified_identity;
        std::string verification_error;
        if (!ValidateOwnedConnectionLocked(
                verification_error) ||
            !VerifySQLiteHeaderDescriptor(
                m_identity_descriptor,
                m_path,
                verified_identity,
                verification_error) ||
            !SameSQLiteFileIdentity(
                verified_identity,
                m_identity) ||
            !VerifyDatabase(
                m_database,
                verification_error) ||
            !ValidateLogicalCreationMarker(
                m_database,
                m_path,
                SQLiteCreationMarkerPolicy::REQUIRE_ABSENT,
                verification_error)) {
            return fail_before_exchange(
                verification_error.empty() ?
                    "the SQLite candidate failed pre-publication verification" :
                    verification_error);
        }

        const int flush_result =
            sqlite3_db_cacheflush(m_database);
        if (flush_result != SQLITE_OK) {
            return fail_before_exchange(
                strprintf(
                    "failed to flush SQLite candidate '%s': %s",
                    m_path.string(),
                    sqlite3_errmsg(m_database)));
        }
        if (!ValidateOwnedConnectionLocked(
                verification_error) ||
#ifdef WIN32
            _commit(m_identity_descriptor) != 0) {
#else
            fsync(m_identity_descriptor) != 0) {
#endif
            if (verification_error.empty()) {
                verification_error = strprintf(
                    "failed to synchronize retained SQLite candidate '%s': %s",
                    m_path.string(),
                    std::strerror(errno));
            }
            return fail_before_exchange(
                verification_error);
        }
        if (!CheckAuxiliaryFiles(
                m_path,
                true,
                verification_error)) {
            return fail_before_exchange(
                verification_error);
        }

        if (!CloseSQLiteConnection(m_database)) {
            AbandonSQLiteConnection(m_database);
            return mark_indeterminate(
                "the SQLite candidate connection could not be closed cleanly before exchange");
        }
        {
            std::lock_guard<std::mutex> state_lock(
                m_state_mutex);
            m_open = false;
        }
        Poison();

        if (!DescriptorIdentityMatches(
                m_identity_descriptor,
                m_identity) ||
            !PathIdentityMatches(
                m_path,
                m_identity) ||
            !CheckAuxiliaryFiles(
                m_path,
                false,
                verification_error)) {
            if (verification_error.empty()) {
                verification_error =
                    "the closed SQLite candidate lost its retained identity";
            }
            return mark_indeterminate(
                verification_error);
        }

        std::string source_error;
        if (!source.MigrationSourceMatchesPath(
                source_path,
                source_error) ||
            !source.MigrationBackupMatchesPath(
                source_error)) {
            return fail_before_exchange(
                source_error.empty() ?
                    "the retained BDB source or backup identity is unavailable" :
                    source_error);
        }
        if (!source.PrepareForMigrationPublication(
                source_error)) {
            std::string retained_error;
            if (!source.MigrationSourceMatchesPath(
                    source_path,
                    retained_error) ||
                !source.MigrationBackupMatchesPath(
                    retained_error)) {
                return mark_indeterminate(
                    strprintf(
                        "BDB publication preparation failed and its retained "
                        "source or backup identity could not be revalidated: %s",
                        retained_error.empty() ?
                            source_error :
                            retained_error));
            }
            return fail_before_exchange(
                source_error.empty() ?
                    "BDB publication preparation failed" :
                    source_error);
        }
        if (!DescriptorIdentityMatches(
                m_identity_descriptor,
                m_identity) ||
            !PathIdentityMatches(
                m_path,
                m_identity) ||
            !CheckAuxiliaryFiles(
                m_path,
                false,
                verification_error) ||
            !source.MigrationSourceMatchesPath(
                source_path,
                source_error) ||
            !source.MigrationBackupMatchesPath(
                source_error)) {
            return fail_before_exchange(
                !verification_error.empty() ?
                    verification_error :
                source_error.empty() ?
                    "a retained migration identity changed immediately before exchange" :
                    source_error);
        }

        if (!CheckAuxiliaryFiles(
                source_path,
                false,
                verification_error)) {
            return fail_before_exchange(
                verification_error);
        }
        if (!OwnerControlledMigrationDirectory(
                parent,
                verification_error) ||
            !SyncDirectory(
                parent,
                verification_error,
                true)) {
            return mark_indeterminate(
                verification_error);
        }

        int exchange_result;
#if defined(__linux__) && defined(SYS_renameat2)
        exchange_result = static_cast<int>(syscall(
            SYS_renameat2,
            AT_FDCWD,
            m_path.string().c_str(),
            AT_FDCWD,
            source_path.string().c_str(),
            RENAME_EXCHANGE));
#elif defined(__APPLE__)
        exchange_result = renameatx_np(
            AT_FDCWD,
            m_path.string().c_str(),
            AT_FDCWD,
            source_path.string().c_str(),
            RENAME_SWAP);
#else
    exchange_result = -1;
    errno = ENOTSUP;
#endif
        exchange_attempted = true;
        if (exchange_result == 0 &&
            ConsumeMigrationExchangeError()) {
            errno = EIO;
            exchange_result = -1;
        }
        const int exchange_error =
            exchange_result == 0 ? 0 : errno;

        const bool candidate_at_final =
            PathIdentityMatches(
                source_path,
                m_identity);
        const bool candidate_at_hidden =
            PathIdentityMatches(
                m_path,
                m_identity);
        std::string ignored_error;
        const bool source_at_final =
            source.MigrationSourceMatchesPath(
                source_path,
                ignored_error);
        ignored_error.clear();
        const bool source_at_hidden =
            source.MigrationSourceMatchesPath(
                m_path,
                ignored_error);
        ignored_error.clear();
        const bool backup_matches =
            source.MigrationBackupMatchesPath(
                ignored_error);
        const bool exchanged =
            candidate_at_final &&
            source_at_hidden;
        const bool unchanged =
            candidate_at_hidden &&
            source_at_final;

        if (exchange_result != 0) {
            if (unchanged && backup_matches) {
                return fail_before_exchange(
                    strprintf(
                        "atomic SQLite/BDB path exchange failed without "
                        "changing either retained identity: %s",
                        std::strerror(exchange_error)));
            }
            return mark_indeterminate(
                strprintf(
                    "atomic SQLite/BDB path exchange reported '%s'; retained "
                    "identity reconciliation found candidate-at-final=%d, "
                    "source-at-hidden=%d, candidate-at-hidden=%d, "
                    "source-at-final=%d, backup-exact=%d",
                    std::strerror(exchange_error),
                    candidate_at_final,
                    source_at_hidden,
                    candidate_at_hidden,
                    source_at_final,
                    backup_matches));
        }
        if (!exchanged || !backup_matches) {
            return mark_indeterminate(
                strprintf(
                    "atomic SQLite/BDB path exchange returned success but "
                    "retained identity reconciliation found candidate-at-final=%d, "
                    "source-at-hidden=%d, backup-exact=%d",
                    candidate_at_final,
                    source_at_hidden,
                    backup_matches));
        }

        std::string published_error;
        if (!VerifySQLiteMigrationPath(
                source_path,
                m_identity_descriptor,
                m_identity,
                published_error) ||
            !source.MigrationSourceMatchesPath(
                m_path,
                source_error) ||
            !source.MigrationBackupMatchesPath(
                source_error)) {
            return mark_indeterminate(
                !published_error.empty() ?
                    published_error :
                source_error.empty() ?
                    "a retained migration identity changed after exchange" :
                    source_error);
        }

        if (!SyncDirectory(
                parent,
                published_error,
                true)) {
            return mark_indeterminate(
                published_error);
        }
        if (!PathIdentityMatches(
                source_path,
                m_identity) ||
            !source.MigrationSourceMatchesPath(
                m_path,
                source_error) ||
            !source.MigrationBackupMatchesPath(
                source_error)) {
            return mark_indeterminate(
                source_error.empty() ?
                    "a retained migration identity changed before removing the displaced BDB source" :
                    source_error);
        }
#ifdef WIN32
        const int unlink_result =
            _unlink(m_path.string().c_str());
#else
        const int unlink_result =
            unlink(m_path.string().c_str());
#endif
        if (unlink_result != 0) {
            return mark_indeterminate(
                strprintf(
                    "failed to remove the proven displaced BDB source '%s': %s",
                    m_path.string(),
                    std::strerror(errno)));
        }
        if (!source.ConfirmMigrationSourceRemoved(
                source_error)) {
            return mark_indeterminate(
                source_error.empty() ?
                    "the displaced BDB source inode was not proven removed" :
                    source_error);
        }
        if (!SyncDirectory(
                parent,
                published_error,
                true)) {
            return mark_indeterminate(
                published_error);
        }

        fs::file_status displaced_status;
        if (!GetPathStatus(
                m_path,
                displaced_status,
                published_error) ||
            displaced_status.type() !=
                fs::file_not_found) {
            if (published_error.empty()) {
                published_error = strprintf(
                    "the displaced BDB path '%s' reappeared after removal",
                    m_path.string());
            }
            return mark_indeterminate(
                published_error);
        }
        if (!VerifySQLiteMigrationPath(
                source_path,
                m_identity_descriptor,
                m_identity,
                published_error) ||
            !source.MigrationBackupMatchesPath(
                source_error)) {
            return mark_indeterminate(
                !published_error.empty() ?
                    published_error :
                source_error.empty() ?
                    "the final SQLite wallet or retained backup failed final verification" :
                    source_error);
        }

        m_creation_state =
            SQLiteCreationState::PUBLISHED;
        m_creation_cleanup_allowed = false;
        m_completed_logical_creation = false;
        error.clear();
        return SQLiteMigrationPublishResult::SUCCESS;
    } catch (const boost::thread_interrupted&) {
        fail_from_exception(
            "thread interruption");
        throw;
    } catch (const std::exception& exception) {
        return fail_from_exception(
            exception.what());
    } catch (...) {
        return fail_from_exception(
            "unknown exception");
    }
}

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
    bool committed = ExecuteSQL(
        m_database,
        "COMMIT TRANSACTION");
    if (committed &&
        ConsumeRewriteCommitError()) {
        committed = false;
    }
    if (!committed) {
        if (m_database &&
            sqlite3_get_autocommit(m_database) != 0) {
            Poison();
            StartShutdown();
            LogPrintf(
                "SQLiteDatabase: Rewrite commit outcome is indeterminate; quarantining the database and shutting down.\n");
            return false;
        }
        return fail_transaction();
    }
    if (sqlite3_get_autocommit(m_database) == 0) {
        return fail_transaction();
    }
    return true;
}

bool SQLiteDatabase::Backup(const std::string& destination)
{
    std::string error;
    return Backup(destination, error);
}

bool SQLiteDatabase::Backup(
    const std::string& destination,
    std::string& backup_error)
{
    backup_error.clear();
#ifdef WIN32
    backup_error = strprintf(
        "Failed to back up SQLite wallet '%s' to '%s': secure SQLite "
        "backup is unavailable on Windows until owner-only DACL and "
        "reparse-point handling is implemented. Keep the source wallet and "
        "use a supported Linux or macOS build to create the backup.",
        m_filename,
        destination);
    LogPrintf("SQLiteDatabase: %s\n", backup_error);
    return false;
#else
    fs::path destination_path(destination);
    auto fail = [&](const std::string& detail, const char* action) {
        backup_error = strprintf(
            "Failed to back up SQLite wallet '%s' to '%s': %s %s",
            m_filename,
            destination_path.string(),
            detail,
            action);
        LogPrintf("SQLiteDatabase: %s\n", backup_error);
        return false;
    };
    const char* const retry_action =
        "The source wallet was not replaced. Correct the reported condition, "
        "inspect any destination artifact, and retry with a new absent "
        "destination path.";
    const char* const collision_action =
        "Choose a new absent destination; SQLite wallet backups never "
        "overwrite an existing path.";
    if (destination_path.empty()) {
        return fail(
            "the destination path is empty.",
            "Choose a new nonempty destination path.");
    }

    fs::file_status destination_status;
    std::string detail;
    if (!GetPathStatus(destination_path, destination_status, detail)) {
        return fail(detail, retry_action);
    }
    if (destination_status.type() == fs::directory_file) {
        destination_path /= m_filename;
    } else if (destination_status.type() != fs::file_not_found) {
        return fail(
            "the destination path already exists.",
            collision_action);
    }

    std::unique_lock<std::mutex> writer_lock(m_writer_mutex);
    std::shared_lock<std::shared_mutex> connection_lock(m_connection_mutex);
    if (!m_database || !m_usable.load() || m_poisoned.load()) {
        return fail(
            "the live SQLite database is closed, unusable, or quarantined.",
            "Keep the source wallet in place, restart Firo, and retry with a "
            "new absent destination only after the wallet opens cleanly.");
    }

    fs::file_status target_status;
    if (!GetPathStatus(destination_path, target_status, detail)) {
        return fail(detail, retry_action);
    }
    if (target_status.type() != fs::file_not_found) {
        return fail(
            "the destination path already exists.",
            collision_action);
    }
    if (!CheckAuxiliaryFiles(destination_path, false, detail)) {
        return fail(
            detail,
            "Choose a new absent destination with no -journal, -wal, or "
            "-shm side files.");
    }
    OwnedCandidate candidate;
    if (CreateOwnedCandidate(destination_path, candidate, detail) !=
        CandidateResult::SUCCESS) {
        return fail(detail, retry_action);
    }
    bool restart_required = false;
    auto record_lifecycle_failure = [&]() {
        if (restart_required) {
            return;
        }
        restart_required = true;
        detail += strprintf(
            "%sSQLite could not prove cleanup of candidate '%s' or "
            "destination '%s' after a connection lifecycle failure.",
            detail.empty() ? "" : " ",
            candidate.path.string(),
            destination_path.string());
    };

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
                detail,
                &candidate.identity,
                &candidate.cleanup_allowed) &&
            SetConnectionPragmas(backup_database, detail) &&
            ConnectionIdentityMatches(
                backup_database,
                candidate.path,
                candidate.identity,
                detail)) {
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
                    VerifyDatabase(backup_database, detail);
                if (!success && detail.empty()) {
                    detail = strprintf(
                        "Failed to copy SQLite backup (step error %d, finish error %d).",
                        step_result,
                        finish_result);
                }
            } else {
                detail = strprintf(
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
            detail = "Failed to close the SQLite backup candidate connection.";
        }
        if (!candidate.cleanup_allowed) {
            success = false;
            Poison();
            record_lifecycle_failure();
        }
        if (success &&
            !CheckAuxiliaryFiles(candidate.path, false, detail)) {
            success = false;
        }

        if (success) {
            if (ConsumeBackupCollisionCleanupFailure()) {
                publish_result = PublishResult::EXISTS;
                candidate.cleanup_allowed = false;
            } else if (ConsumeBackupPublicationCollision()) {
                publish_result = PublishResult::EXISTS;
            } else {
                publish_result =
                    PublishCandidate(
                        candidate,
                        destination_path,
                        detail);
            }
            success =
                publish_result == PublishResult::SUCCESS;
            if (publish_result == PublishResult::EXISTS) {
                detail =
                    "the destination path appeared concurrently and was not overwritten.";
            }
        }
        if (success && ConsumePostPublishFailure()) {
            detail =
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
                    detail) &&
                DescriptorIdentityMatches(
                    candidate.descriptor,
                    candidate.identity) &&
                PathIdentityMatches(
                    destination_path,
                    candidate.identity) &&
                OpenSQLiteConnection(
                    destination_path,
                    published_database,
                    detail,
                    &candidate.identity,
                    &candidate.cleanup_allowed) &&
                VerifyDatabase(published_database, detail) &&
                SetConnectionPragmas(published_database, detail) &&
                ConnectionIdentityMatches(
                    published_database,
                    destination_path,
                    candidate.identity,
                    detail) &&
                VerifyDatabase(published_database, detail);
            const bool published_closed =
                CloseOrAbandonSQLiteConnection(
                    published_database,
                    &candidate.cleanup_allowed);
            if (!published_closed) {
                success = false;
                detail =
                    "Failed to close the published SQLite backup verification connection.";
            }
            if (!candidate.cleanup_allowed) {
                success = false;
                Poison();
                record_lifecycle_failure();
            }
        }
    } catch (const std::exception& exception) {
        close_after_exception();
        detail = strprintf(
            "SQLite backup failed with an exception: %s",
            exception.what());
        if (!candidate.cleanup_allowed) {
            record_lifecycle_failure();
        }
    } catch (...) {
        close_after_exception();
        detail = "SQLite backup failed with an unknown exception.";
        if (!candidate.cleanup_allowed) {
            record_lifecycle_failure();
        }
    }

    if (!success &&
        (publish_result == PublishResult::SUCCESS ||
            publish_result == PublishResult::PUBLISHED_ERROR)) {
        std::string cleanup_error;
        if (!RemovePublishedCandidate(
                candidate,
                destination_path,
                cleanup_error)) {
            detail += strprintf(
                "%sFailed to remove the published SQLite backup safely: %s",
                detail.empty() ? "" : " ",
                cleanup_error);
            restart_required = true;
        }
    }
    std::string candidate_cleanup_error;
    if (!RemoveOwnedCandidate(
            candidate,
            candidate_cleanup_error)) {
        detail += strprintf(
            "%sSQLite could not prove cleanup of owned backup candidate "
            "'%s': %s",
            detail.empty() ? "" : " ",
            candidate.path.string(),
            candidate_cleanup_error);
        restart_required = true;
    }
    if (!success) {
        if (detail.empty()) {
            detail = "the backend did not provide a more specific failure.";
        }
        return fail(
            detail,
            restart_required ?
                "Keep the source wallet and all reported artifacts, restart "
                "Firo, and retry with a new absent destination only after "
                "the wallet opens cleanly." :
            publish_result == PublishResult::EXISTS ?
                collision_action :
                retry_action);
    }
    backup_error.clear();
    return true;
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

enum class SQLiteLogicalRecoveryResult {
    SUCCESS,
    FAILED,
    INDETERMINATE,
};

SQLiteLogicalRecoveryResult RecoverSQLiteDatabase(
    const std::string& filename,
    const fs::path& source_path,
    SQLiteRecoveryMode mode,
    fs::path& backup_path,
    std::string& error)
{
#if !((defined(__linux__) && defined(SYS_renameat2)) || defined(__APPLE__))
    (void)filename;
    (void)source_path;
    (void)mode;
    (void)backup_path;
    error =
        "Atomic SQLite recovery publication is unavailable on this platform.";
    return SQLiteLogicalRecoveryResult::FAILED;
#else
    backup_path.clear();
    error.clear();
    std::string acquire_error;
    if (!AcquireSQLite(acquire_error)) {
        error = strprintf(
            "Failed to initialize SQLite recovery for '%s': %s",
            source_path.string(),
            acquire_error);
        return SQLiteLogicalRecoveryResult::FAILED;
    }
    struct SQLiteReleaseGuard {
        ~SQLiteReleaseGuard() { ReleaseSQLite(); }
    } sqlite_release_guard;

    struct DescriptorGuard {
        int descriptor{-1};
        ~DescriptorGuard()
        {
            if (descriptor >= 0) {
                close(descriptor);
            }
        }
    } source_descriptor;

    SQLiteFileIdentity source_identity;
    OwnedCandidate replacement;
    OwnedCandidate backup;
    sqlite3* source_database = nullptr;
    sqlite3* replacement_database = nullptr;
    sqlite3* verification_database = nullptr;
    bool backup_published = false;
    bool exchange_attempted = false;
    bool exchange_proven = false;

    auto close_connections = [&]() noexcept {
        const bool source_closed =
            CloseOrAbandonSQLiteConnection(
                source_database);
        const bool replacement_closed =
            CloseOrAbandonSQLiteConnection(
                replacement_database,
                &replacement.cleanup_allowed);
        const bool verification_closed =
            CloseOrAbandonSQLiteConnection(
                verification_database,
                &replacement.cleanup_allowed);
        if (!source_closed ||
            !replacement_closed ||
            !verification_closed) {
            StartShutdown();
        }
        return source_closed &&
               replacement_closed &&
               verification_closed;
    };

    auto remove_pre_exchange_candidates = [&]() noexcept {
        if (!exchange_proven) {
            RemoveOwnedCandidate(replacement);
        }
        if (!backup_published) {
            RemoveOwnedCandidate(backup);
        }
    };

    auto fail_before_exchange =
        [&](const std::string& reason) {
            const bool closed = close_connections();
            remove_pre_exchange_candidates();
            error = strprintf(
                "SQLite %s for wallet '%s' failed before publication: %s%s",
                mode == SQLiteRecoveryMode::KEY_ONLY ?
                    "key-only salvage" :
                    "logical recovery",
                source_path.string(),
                reason.empty() ?
                    "unknown recovery failure" :
                    reason,
                backup_published ?
                    strprintf(
                        " Exact source backup retained at '%s'.",
                        backup_path.string()) :
                    "");
            if (!closed) {
                error +=
                    " A SQLite connection could not be closed; restart Firo "
                    "before retrying.";
            }
            return SQLiteLogicalRecoveryResult::FAILED;
        };

    auto mark_indeterminate =
        [&](const std::string& reason) {
            close_connections();
            StartShutdown();
            error = strprintf(
                "SQLite %s publication for wallet '%s' is indeterminate: %s "
                "Wallet path: '%s'. Recovery working path: '%s'. "
                "Backup path: '%s'. Preserve all paths and restart Firo only "
                "after recovery.",
                mode == SQLiteRecoveryMode::KEY_ONLY ?
                    "key-only salvage" :
                    "logical recovery",
                filename,
                reason.empty() ?
                    "retained file identities could not be reconciled" :
                    reason,
                source_path.string(),
                replacement.path.string(),
                backup_path.string());
            return SQLiteLogicalRecoveryResult::INDETERMINATE;
        };

    auto verify_recovery_source =
        [&](std::string& verification_error) {
            SQLiteFileIdentity verified_identity;
            if (!VerifySQLiteHeaderDescriptor(
                    source_descriptor.descriptor,
                    source_path,
                    verified_identity,
                    verification_error) ||
                !SameSQLiteFileIdentity(
                    verified_identity,
                    source_identity) ||
                !ConnectionIdentityMatches(
                    source_database,
                    source_path,
                    source_identity,
                    verification_error) ||
                !VerifyDatabaseIdentity(
                    source_database,
                    verification_error) ||
                !VerifySchema(
                    source_database,
                    verification_error)) {
                return false;
            }
            if (mode == SQLiteRecoveryMode::KEY_ONLY) {
                return true;
            }
            if (!VerifyBlobRecords(
                    source_database,
                    verification_error)) {
                return false;
            }

            bool corruption = false;
            std::string integrity_error;
            if (VerifyIntegrity(
                    source_database,
                    integrity_error,
                    &corruption)) {
                verification_error =
                    "The SQLite wallet passes full integrity verification; "
                    "automatic logical recovery is not applicable.";
                return false;
            }
            if (!corruption) {
                verification_error = strprintf(
                    "SQLite verification failed for a reason that is not "
                    "classified as recoverable corruption: %s",
                    integrity_error);
                return false;
            }
            return true;
        };

    auto verify_owned_recovery_path =
        [&](const fs::path& path,
            int descriptor,
            const SQLiteFileIdentity& identity,
            std::string& verification_error) {
            SQLiteFileIdentity verified_identity;
            if (!DescriptorIdentityMatches(
                    descriptor,
                    identity) ||
                !VerifySQLiteHeaderDescriptor(
                    descriptor,
                    path,
                    verified_identity,
                    verification_error) ||
                !SameSQLiteFileIdentity(
                    verified_identity,
                    identity) ||
                !PathIdentityMatches(
                    path,
                    identity) ||
                !CheckAuxiliaryFiles(
                    path,
                    false,
                    verification_error) ||
                !OpenSQLiteConnection(
                    path,
                    verification_database,
                    verification_error,
                    &identity)) {
                return false;
            }

            bool verified =
                VerifyDatabase(
                    verification_database,
                    verification_error) &&
                ValidateLogicalCreationMarker(
                    verification_database,
                    path,
                    SQLiteCreationMarkerPolicy::REQUIRE_ABSENT,
                    verification_error) &&
                SetConnectionPragmas(
                    verification_database,
                    verification_error) &&
                ConnectionIdentityMatches(
                    verification_database,
                    path,
                    identity,
                    verification_error) &&
                VerifyDatabase(
                    verification_database,
                    verification_error) &&
                ValidateLogicalCreationMarker(
                    verification_database,
                    path,
                    SQLiteCreationMarkerPolicy::REQUIRE_ABSENT,
                    verification_error);
            if (verified) {
                const int flush_result =
                    sqlite3_db_cacheflush(
                        verification_database);
                if (flush_result != SQLITE_OK) {
                    verification_error = strprintf(
                        "Failed to flush verified SQLite recovery path '%s': %s",
                        path.string(),
                        sqlite3_errmsg(
                            verification_database));
                    verified = false;
                }
            }
            if (!CloseSQLiteConnection(
                    verification_database)) {
                AbandonSQLiteConnection(
                    verification_database);
                replacement.cleanup_allowed = false;
                StartShutdown();
                if (verification_error.empty()) {
                    verification_error = strprintf(
                        "Failed to close SQLite recovery verification path '%s'.",
                        path.string());
                }
                return false;
            }
            return verified &&
                   CheckAuxiliaryFiles(
                       path,
                       false,
                       verification_error);
        };

    try {
        if (!PreflightSQLiteHeader(
                source_path,
                source_identity,
                error,
                &source_descriptor.descriptor) ||
            !CheckAuxiliaryFiles(
                source_path,
                true,
                error) ||
            !OpenSQLiteConnection(
                source_path,
                source_database,
                error,
                &source_identity)) {
            return fail_before_exchange(error);
        }

        std::string verification_error;
        if (!verify_recovery_source(
                verification_error)) {
            return fail_before_exchange(
                verification_error);
        }
        if (!SetConnectionPragmas(
                source_database,
                verification_error) ||
            !verify_recovery_source(
                verification_error)) {
            return fail_before_exchange(
                verification_error);
        }

        if (CreateOwnedCandidate(
                source_path,
                replacement,
                error) !=
                CandidateResult::SUCCESS ||
            !OpenSQLiteConnection(
                replacement.path,
                replacement_database,
                error,
                &replacement.identity,
                &replacement.cleanup_allowed) ||
            !SetConnectionPragmas(
                replacement_database,
                error) ||
            !CreateSchema(
                replacement_database,
                false,
                error)) {
            return fail_before_exchange(error);
        }

        size_t copied_rows = 0;
        if (!CopySQLiteRecoveryRows(
                source_database,
                replacement_database,
                mode,
                copied_rows,
                error) ||
            !VerifyDatabase(
                replacement_database,
                error) ||
            !ValidateLogicalCreationMarker(
                replacement_database,
                replacement.path,
                SQLiteCreationMarkerPolicy::REQUIRE_ABSENT,
                error) ||
            !VerifySQLiteRecoveryRows(
                source_database,
                replacement_database,
                mode,
                copied_rows,
                error)) {
            return fail_before_exchange(error);
        }

        const int source_flush_result =
            sqlite3_db_cacheflush(
                source_database);
        const int replacement_flush_result =
            sqlite3_db_cacheflush(
                replacement_database);
        if (source_flush_result != SQLITE_OK ||
            replacement_flush_result != SQLITE_OK) {
            return fail_before_exchange(
                "Failed to flush SQLite recovery source or candidate.");
        }
        if (!CloseSQLiteConnection(
                replacement_database) ||
            !CloseSQLiteConnection(
                source_database)) {
            if (replacement_database) {
                replacement.cleanup_allowed = false;
                AbandonSQLiteConnection(
                    replacement_database);
            }
            if (source_database) {
                AbandonSQLiteConnection(
                    source_database);
            }
            StartShutdown();
            return fail_before_exchange(
                "A SQLite recovery connection could not be closed.");
        }

        if (!PrivateSQLiteIdentityMatches(
                source_descriptor.descriptor,
                source_path,
                source_identity) ||
            !PrivateSQLiteIdentityMatches(
                replacement.descriptor,
                replacement.path,
                replacement.identity) ||
            !CheckAuxiliaryFiles(
                source_path,
                false,
                error) ||
            !CheckAuxiliaryFiles(
                replacement.path,
                false,
                error) ||
            !verify_owned_recovery_path(
                replacement.path,
                replacement.descriptor,
                replacement.identity,
                error)) {
            if (error.empty()) {
                error =
                    "SQLite recovery source or candidate lost its retained identity.";
            }
            return fail_before_exchange(error);
        }

        const fs::path parent =
            source_path.parent_path().empty() ?
                fs::path(".") :
                source_path.parent_path();
        backup_path =
            parent /
            strprintf(
                "wallet.%d.bak",
                GetTime());
        if (backup_path == source_path ||
            backup_path == replacement.path ||
            !OwnerControlledMigrationDirectory(
                parent,
                error) ||
            CreateOwnedCandidate(
                backup_path,
                backup,
                error) !=
                CandidateResult::SUCCESS ||
            !CopyDescriptorContents(
                source_descriptor.descriptor,
                backup.descriptor,
                error) ||
            !DescriptorContentsEqual(
                source_descriptor.descriptor,
                backup.descriptor,
                error)) {
            return fail_before_exchange(error);
        }

        const PublishResult backup_publish_result =
            PublishCandidate(
                backup,
                backup_path,
                error);
        backup_published =
            PathIdentityMatches(
                backup_path,
                backup.identity);
        if (backup_publish_result !=
                PublishResult::SUCCESS ||
            !backup_published ||
            !DescriptorContentsEqual(
                source_descriptor.descriptor,
                backup.descriptor,
                error)) {
            if (backup_publish_result ==
                PublishResult::EXISTS) {
                error = strprintf(
                    "Refusing to overwrite existing SQLite recovery backup '%s'.",
                    backup_path.string());
            }
            return fail_before_exchange(error);
        }

        if (!PrivateSQLiteIdentityMatches(
                source_descriptor.descriptor,
                source_path,
                source_identity) ||
            !PrivateSQLiteIdentityMatches(
                replacement.descriptor,
                replacement.path,
                replacement.identity) ||
            !PrivateSQLiteIdentityMatches(
                backup.descriptor,
                backup_path,
                backup.identity) ||
            !DescriptorContentsEqual(
                source_descriptor.descriptor,
                backup.descriptor,
                error) ||
            !CheckAuxiliaryFiles(
                source_path,
                false,
                error) ||
            !CheckAuxiliaryFiles(
                replacement.path,
                false,
                error) ||
            !CheckAuxiliaryFiles(
                backup_path,
                false,
                error) ||
            !SyncDirectory(
                parent,
                error,
                true)) {
            if (error.empty()) {
                error =
                    "A retained SQLite recovery identity changed before publication.";
            }
            return fail_before_exchange(error);
        }

        int exchange_result;
#if defined(__linux__) && defined(SYS_renameat2)
        exchange_result = static_cast<int>(syscall(
            SYS_renameat2,
            AT_FDCWD,
            replacement.path.string().c_str(),
            AT_FDCWD,
            source_path.string().c_str(),
            RENAME_EXCHANGE));
#elif defined(__APPLE__)
        exchange_result = renameatx_np(
            AT_FDCWD,
            replacement.path.string().c_str(),
            AT_FDCWD,
            source_path.string().c_str(),
            RENAME_SWAP);
#else
        exchange_result = -1;
        errno = ENOTSUP;
#endif
        exchange_attempted = true;
        const int exchange_error =
            exchange_result == 0 ?
                0 :
                errno;
        const bool replacement_at_final =
            PathIdentityMatches(
                source_path,
                replacement.identity);
        const bool source_at_hidden =
            PathIdentityMatches(
                replacement.path,
                source_identity);
        const bool replacement_at_hidden =
            PathIdentityMatches(
                replacement.path,
                replacement.identity);
        const bool source_at_final =
            PathIdentityMatches(
                source_path,
                source_identity);
        const bool exchanged =
            replacement_at_final &&
            source_at_hidden;
        const bool unchanged =
            replacement_at_hidden &&
            source_at_final;
        exchange_proven = exchanged;

        if (exchange_result != 0) {
            if (unchanged) {
                exchange_attempted = false;
                return fail_before_exchange(
                    strprintf(
                        "Atomic SQLite recovery exchange failed without "
                        "changing either retained identity: %s",
                        std::strerror(
                            exchange_error)));
            }
            return mark_indeterminate(
                strprintf(
                    "Atomic exchange reported '%s'; identity reconciliation "
                    "found replacement-at-final=%d, source-at-hidden=%d, "
                    "replacement-at-hidden=%d, source-at-final=%d",
                    std::strerror(exchange_error),
                    replacement_at_final,
                    source_at_hidden,
                    replacement_at_hidden,
                    source_at_final));
        }
        if (!exchanged) {
            return mark_indeterminate(
                strprintf(
                    "Atomic exchange returned success but identity "
                    "reconciliation found replacement-at-final=%d and "
                    "source-at-hidden=%d",
                    replacement_at_final,
                    source_at_hidden));
        }

        if (!DescriptorContentsEqual(
                source_descriptor.descriptor,
                backup.descriptor,
                error) ||
            !PathIdentityMatches(
                replacement.path,
                source_identity) ||
            !PrivateSQLiteIdentityMatches(
                replacement.descriptor,
                source_path,
                replacement.identity) ||
            !verify_owned_recovery_path(
                source_path,
                replacement.descriptor,
                replacement.identity,
                error) ||
            !SyncDirectory(
                parent,
                error,
                true)) {
            return mark_indeterminate(error);
        }

        if (!CheckAuxiliaryFiles(
                replacement.path,
                false,
                error) ||
            !PrivateSQLiteIdentityMatches(
                backup.descriptor,
                backup_path,
                backup.identity) ||
            !DescriptorContentsEqual(
                source_descriptor.descriptor,
                backup.descriptor,
                error) ||
            !RemoveOwnedPath(
                replacement.path,
                source_identity,
                error) ||
            !DescriptorIdentityIsUnlinked(
                source_descriptor.descriptor,
                source_identity) ||
            !SyncDirectory(
                parent,
                error,
                true) ||
            !verify_owned_recovery_path(
                source_path,
                replacement.descriptor,
                replacement.identity,
                error) ||
            !PathIdentityMatches(
                backup_path,
                backup.identity) ||
            !DescriptorContentsEqual(
                source_descriptor.descriptor,
                backup.descriptor,
                error)) {
            if (error.empty()) {
                error =
                    "SQLite recovery final identity verification failed.";
            }
            return mark_indeterminate(error);
        }

        LogPrintf(
            "SQLiteDatabase: %s completed for '%s'; exact source backup "
            "retained at '%s'.\n",
            mode == SQLiteRecoveryMode::KEY_ONLY ?
                "Key-only salvage" :
                "Logical recovery",
            source_path.string(),
            backup_path.string());
        error.clear();
        return SQLiteLogicalRecoveryResult::SUCCESS;
    } catch (const std::exception& exception) {
        if (exchange_attempted &&
            !exchange_proven) {
            return mark_indeterminate(
                strprintf(
                    "An exception occurred after atomic exchange was attempted: %s",
                    exception.what()));
        }
        if (exchange_proven) {
            return mark_indeterminate(
                strprintf(
                    "An exception occurred after atomic exchange: %s",
                    exception.what()));
        }
        return fail_before_exchange(
            strprintf(
                "Recovery raised an exception: %s",
                exception.what()));
    } catch (...) {
        if (exchange_attempted ||
            exchange_proven) {
            return mark_indeterminate(
                "An unknown exception occurred after atomic exchange was attempted.");
        }
        return fail_before_exchange(
            "Recovery raised an unknown exception.");
    }
#endif
}
} // namespace

int SQLiteStatementExecutor::Execute(
    sqlite3* database,
    const char* statement)
{
    return sqlite3_exec(database, statement, nullptr, nullptr, nullptr);
}

const void* SQLiteColumnReader::Blob(
    sqlite3_stmt* statement,
    int column)
{
    return sqlite3_column_blob(statement, column);
}

int SQLiteColumnReader::Bytes(
    sqlite3_stmt* statement,
    int column)
{
    return sqlite3_column_bytes(statement, column);
}

int SQLiteColumnReader::ErrorCode(sqlite3* database)
{
    return sqlite3_errcode(database);
}

std::unique_ptr<WalletDatabase> MakeSQLiteDatabase(
    const std::string& filename,
    const DatabaseOptions& options,
    DatabaseStatus& status,
    std::string& error)
{
    status = DatabaseStatus::FAILED_LOAD;
    error.clear();

    if ((options.require_existing && options.require_create) ||
        (options.logical_wallet_create &&
            !options.require_create) ||
        (options.sqlite_migration_candidate &&
            (!options.logical_wallet_create ||
                !options.require_create))) {
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

    fs::path recovery_backup_path;
    bool recovered = false;
    bool salvaged = false;
    bool recovery_indeterminate = false;
    if (exists && options.salvage) {
        const SQLiteLogicalRecoveryResult recovery_result =
            RecoverSQLiteDatabase(
                filename,
                path,
                SQLiteRecoveryMode::KEY_ONLY,
                recovery_backup_path,
                error);
        if (recovery_result !=
            SQLiteLogicalRecoveryResult::SUCCESS) {
            status =
                recovery_result ==
                        SQLiteLogicalRecoveryResult::INDETERMINATE ?
                    DatabaseStatus::FAILED_LOAD :
                    DatabaseStatus::FAILED_VERIFY;
            return nullptr;
        }
        salvaged = true;
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
        auto initialize_database = [&]() {
            database = std::make_unique<SQLiteDatabase>(
                filename,
                path,
                options.sqlite_migration_candidate);
            return exists ?
                       database->InitializeExisting(error) :
                       database->InitializeCreated(
                           candidate,
                           options.logical_wallet_create,
                           publish_result,
                           error);
        };

        bool initialized =
            initialize_database();
        if (!initialized &&
            exists &&
            !options.salvage &&
            options.verify &&
            options.recover) {
            const std::string initial_error = error;
            database.reset();
            std::string recovery_error;
            const SQLiteLogicalRecoveryResult recovery_result =
                RecoverSQLiteDatabase(
                    filename,
                    path,
                    SQLiteRecoveryMode::FULL,
                    recovery_backup_path,
                    recovery_error);
            if (recovery_result ==
                SQLiteLogicalRecoveryResult::SUCCESS) {
                recovered = true;
                error.clear();
                initialized =
                    initialize_database();
                if (!initialized) {
                    error = strprintf(
                        "Recovered SQLite wallet '%s' could not be reopened: "
                        "%s Exact source backup retained at '%s'.",
                        path.string(),
                        error,
                        recovery_backup_path.string());
                }
            } else {
                error = strprintf(
                    "%s Logical SQLite recovery did not publish a replacement: %s",
                    initial_error,
                    recovery_error);
                if (recovery_result ==
                    SQLiteLogicalRecoveryResult::INDETERMINATE) {
                    recovery_indeterminate = true;
                }
            }
        }
        if (!initialized) {
            database.reset();
            if (salvaged) {
                error = strprintf(
                    "Salvaged SQLite wallet '%s' could not be reopened: %s "
                    "Exact source backup retained at '%s'.",
                    path.string(),
                    error,
                    recovery_backup_path.string());
            }
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
                status =
                    recovery_indeterminate ?
                        DatabaseStatus::FAILED_LOAD :
                        DatabaseStatus::FAILED_VERIFY;
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

    if (recovered || salvaged) {
        database->SetRecoveryBackupPath(
            recovery_backup_path);
    }
    status =
        salvaged ?
            DatabaseStatus::SUCCESS_SALVAGED :
        recovered ?
            DatabaseStatus::SUCCESS_RECOVERED :
            DatabaseStatus::SUCCESS;
    return database;
}

SQLiteMigrationPublishResult PublishSQLiteMigrationCandidate(
    WalletDatabase& candidate,
    BerkeleyDatabase& source,
    std::string& error)
{
    SQLiteDatabase* const sqlite_candidate =
        dynamic_cast<SQLiteDatabase*>(&candidate);
    if (!sqlite_candidate) {
        error =
            "Cannot publish SQLite migration candidate: the candidate "
            "database is not an owned SQLite backend.";
        return SQLiteMigrationPublishResult::FAILED;
    }
    return sqlite_candidate->PublishMigration(
        source,
        error);
}

bool SetSQLiteStatementExecutorForTesting(
    DatabaseBatch& batch,
    std::unique_ptr<SQLiteStatementExecutor> executor)
{
    SQLiteBatch* const sqlite_batch = dynamic_cast<SQLiteBatch*>(&batch);
    return sqlite_batch && sqlite_batch->SetExecutor(std::move(executor));
}

bool SetSQLiteColumnReaderForTesting(
    DatabaseBatch& batch,
    std::unique_ptr<SQLiteColumnReader> reader)
{
    SQLiteBatch* const sqlite_batch = dynamic_cast<SQLiteBatch*>(&batch);
    return sqlite_batch &&
           sqlite_batch->SetColumnReader(std::move(reader));
}

bool SetSQLiteCreationStatementExecutorForTesting(
    WalletDatabase& database,
    std::unique_ptr<SQLiteStatementExecutor> executor)
{
    SQLiteDatabase* const sqlite_database =
        dynamic_cast<SQLiteDatabase*>(&database);
    return sqlite_database &&
           sqlite_database->SetCreationExecutor(
               std::move(executor));
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

void InjectSQLiteBackupPublicationCollisionForTesting()
{
    g_report_backup_collision_once.store(true);
}

void InjectSQLiteBackupCollisionCleanupFailureForTesting()
{
    g_fail_backup_collision_cleanup_once.store(true);
}

void InjectSQLiteMigrationExchangeFailureForTesting()
{
    g_report_migration_exchange_error_once.store(true);
}

void InjectSQLiteRewriteCommitFailureForTesting()
{
    g_report_rewrite_commit_error_once.store(true);
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
    g_report_backup_collision_once.store(false);
    g_fail_backup_collision_cleanup_once.store(false);
    g_report_migration_exchange_error_once.store(false);
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
