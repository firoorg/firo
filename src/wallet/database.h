// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_WALLET_DATABASE_H
#define FIRO_WALLET_DATABASE_H

#include "clientversion.h"
#include "fs.h"
#include "streams.h"

#include <cstdint>
#include <exception>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <utility>

/**
 * RAII interface for iterating serialized wallet database records.
 *
 * A cursor may outlive the batch that created it, but not the database owner.
 * It can retain backend read ownership, so callers must destroy it before
 * invoking another operation on the same database from the same thread. A
 * cursor is thread-affine: call Next() and destroy it on the thread that
 * created it.
 */
class DatabaseCursor
{
public:
    enum class Status {
        FAIL,
        MORE,
        DONE,
    };

    DatabaseCursor() = default;
    virtual ~DatabaseCursor() = default;

    DatabaseCursor(const DatabaseCursor&) = delete;
    DatabaseCursor& operator=(const DatabaseCursor&) = delete;

    virtual Status Next(CDataStream& key, CDataStream& value) = 0;
};

enum class DatabaseReadStatus {
    SUCCESS,
    NOT_FOUND,
    CORRUPT,
    FAILED,
};

enum class DatabaseCreationResult {
    COMPLETE,
    FAILED,
    INDETERMINATE,
};

/**
 * Backend-neutral access to one batch of serialized wallet records.
 *
 * Operations autocommit unless this batch starts a transaction. Transactions
 * are batch-local and non-nested. Close and destruction abort an active
 * transaction, and the database owner must outlive the batch.
 */
class DatabaseBatch
{
private:
    virtual DatabaseReadStatus ReadRaw(CDataStream&& key, CDataStream& value) = 0;
    virtual bool WriteRaw(CDataStream&& key, CDataStream&& value, bool overwrite) = 0;
    virtual bool EraseRaw(CDataStream&& key) = 0;
    virtual DatabaseReadStatus HasRaw(CDataStream&& key) = 0;

public:
    DatabaseBatch() = default;
    virtual ~DatabaseBatch() = default;

    DatabaseBatch(const DatabaseBatch&) = delete;
    DatabaseBatch& operator=(const DatabaseBatch&) = delete;

    /** Write an already serialized key/value record without changing its bytes. */
    bool WriteRawRecord(
        CDataStream key,
        CDataStream value,
        bool overwrite = false)
    {
        return WriteRaw(
            std::move(key),
            std::move(value),
            overwrite);
    }

    template <typename K, typename T>
    DatabaseReadStatus ReadWithStatus(const K& key, T& value)
    {
        CDataStream key_stream(SER_DISK, CLIENT_VERSION);
        key_stream.reserve(1000);
        key_stream << key;

        CDataStream value_stream(SER_DISK, CLIENT_VERSION);
        const DatabaseReadStatus status = ReadRaw(std::move(key_stream), value_stream);
        if (status != DatabaseReadStatus::SUCCESS) {
            return status;
        }

        try {
            value_stream >> value;
            return DatabaseReadStatus::SUCCESS;
        } catch (const std::bad_alloc&) {
            return DatabaseReadStatus::FAILED;
        } catch (const std::exception&) {
            return DatabaseReadStatus::CORRUPT;
        }
    }

    template <typename K, typename T>
    bool Read(const K& key, T& value)
    {
        return ReadWithStatus(key, value) == DatabaseReadStatus::SUCCESS;
    }

    template <typename K, typename T>
    bool Write(const K& key, const T& value, bool overwrite = true)
    {
        CDataStream key_stream(SER_DISK, CLIENT_VERSION);
        key_stream.reserve(1000);
        key_stream << key;

        CDataStream value_stream(SER_DISK, CLIENT_VERSION);
        value_stream.reserve(10000);
        value_stream << value;

        return WriteRaw(std::move(key_stream), std::move(value_stream), overwrite);
    }

    template <typename K>
    bool Erase(const K& key)
    {
        CDataStream key_stream(SER_DISK, CLIENT_VERSION);
        key_stream.reserve(1000);
        key_stream << key;

        return EraseRaw(std::move(key_stream));
    }

    template <typename K>
    DatabaseReadStatus ExistsWithStatus(const K& key)
    {
        CDataStream key_stream(SER_DISK, CLIENT_VERSION);
        key_stream.reserve(1000);
        key_stream << key;

        return HasRaw(std::move(key_stream));
    }

    template <typename K>
    bool Exists(const K& key)
    {
        return ExistsWithStatus(key) == DatabaseReadStatus::SUCCESS;
    }

    virtual void Flush() = 0;
    /** Close the batch, aborting any transaction it still owns. */
    virtual void Close() = 0;

    /** Iterate every record in serialized-key order. */
    virtual std::unique_ptr<DatabaseCursor> GetCursor() = 0;

    /** Iterate records beginning with the first serialized key not less than start_key. */
    virtual std::unique_ptr<DatabaseCursor> GetCursor(const CDataStream& start_key) = 0;

    virtual bool TxnBegin() = 0;
    virtual bool TxnCommit() = 0;
    virtual bool TxnAbort() = 0;
    virtual bool HasActiveTxn() const = 0;

    bool ReadVersion(int& version)
    {
        version = 0;
        return Read(std::string("version"), version);
    }

    bool WriteVersion(int version)
    {
        return Write(std::string("version"), version);
    }
};

/** Access mode and close behavior for one wallet database batch. */
enum class DatabaseBatchMode {
    READ_ONLY,
    READ_WRITE,
    READ_WRITE_CREATE,
};

struct DatabaseBatchOptions {
    DatabaseBatchMode mode{DatabaseBatchMode::READ_WRITE};
    bool flush_on_close{true};
};

enum class DatabaseFormat {
    BERKELEY,
    SQLITE,
};

struct DatabaseFileIdentity {
    uint64_t device{0};
    uint64_t inode{0};
};

/** Stable user-facing name for a wallet database format. */
const char* DatabaseFormatName(DatabaseFormat format);

struct DatabaseOptions {
    bool require_existing{false};
    bool require_create{false};
    std::optional<DatabaseFormat> require_format;
    bool verify{true};
    bool recover{true};
    bool salvage{false};
    /** Mark a production wallet candidate incomplete until logical initialization finishes. */
    bool logical_wallet_create{false};
    /** Grant an owned logical SQLite candidate the one-shot migration publication capability. */
    bool sqlite_migration_candidate{false};
    /** Require the retained source identity needed for explicit BDB-to-SQLite migration. */
    bool bdb_migration_source{false};
};

enum class DatabaseStatus {
    SUCCESS,
    SUCCESS_RECOVERED,
    SUCCESS_SALVAGED,
    FAILED_INVALID_OPTIONS,
    FAILED_BAD_PATH,
    FAILED_BAD_FORMAT,
    FAILED_UNSUPPORTED,
    FAILED_ALREADY_EXISTS,
    FAILED_NOT_FOUND,
    FAILED_LOAD,
    FAILED_VERIFY,
};

/**
 * Persistent identity and lifecycle operations for one wallet database.
 *
 * The owner must outlive every batch and cursor made from it. Implementations
 * support nested and parallel batches and coordinate lifecycle operations
 * with concurrent writers.
 */
class WalletDatabase
{
public:
    WalletDatabase() = default;
    virtual ~WalletDatabase() = default;

    WalletDatabase(const WalletDatabase&) = delete;
    WalletDatabase& operator=(const WalletDatabase&) = delete;

    virtual const std::string& Filename() const = 0;
    virtual DatabaseFormat Format() const = 0;
    virtual std::unique_ptr<DatabaseBatch> MakeBatch(const DatabaseBatchOptions& options = {}) = 0;
    /** Complete a pending production wallet creation. */
    virtual DatabaseCreationResult CompleteCreation(std::string& error)
    {
        error.clear();
        return DatabaseCreationResult::COMPLETE;
    }
    /**
     * Compact the database, update its singleton version record, and omit raw
     * serialized keys beginning with skip when it is non-null.
     */
    virtual bool Rewrite(const char* skip = nullptr) = 0;
    /** Write a consistent live snapshot to destination. */
    virtual bool Backup(const std::string& destination) = 0;
    /** Write a consistent live snapshot and return an actionable failure. */
    virtual bool Backup(
        const std::string& destination,
        std::string& error)
    {
        error.clear();
        const bool success = Backup(destination);
        if (!success) {
            error =
                "Failed to back up " +
                std::string(DatabaseFormatName(Format())) +
                " wallet '" + Filename() + "' to '" + destination +
                "': the backend did not provide a specific failure. Keep "
                "the source wallet, inspect any destination artifact, and "
                "retry to a different path after correcting its type and "
                "permissions.";
        }
        return success;
    }
    /** Exact retained backup path after successful automatic recovery. */
    virtual std::string RecoveryBackupPath() const { return {}; }
    virtual bool PeriodicFlush() = 0;
    virtual void Flush(bool shutdown) = 0;
};

/** Resolve a safe flat wallet filename inside the network data directory. */
bool GetWalletDatabasePath(const std::string& filename, fs::path& path, std::string& error);

/**
 * Require a migration directory and every ancestor to be protected from
 * pathname replacement by an untrusted local user.
 */
bool ValidateWalletMigrationDirectory(
    const fs::path& directory,
    std::string& error);

/** Inspect an existing wallet's content-authoritative format without opening a backend. */
bool ReadWalletDatabaseFormat(
    const std::string& filename,
    std::optional<DatabaseFormat>& format,
    std::string& error);

/** Select, verify, and construct the wallet database owner for filename. */
std::unique_ptr<WalletDatabase> MakeWalletDatabase(
    const std::string& filename,
    const DatabaseOptions& options,
    DatabaseStatus& status,
    std::string& error);

#endif // FIRO_WALLET_DATABASE_H
