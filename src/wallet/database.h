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

#include <exception>
#include <memory>
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
    virtual bool ReadRaw(CDataStream&& key, CDataStream& value) = 0;
    virtual bool WriteRaw(CDataStream&& key, CDataStream&& value, bool overwrite) = 0;
    virtual bool EraseRaw(CDataStream&& key) = 0;
    virtual bool HasRaw(CDataStream&& key) = 0;

public:
    DatabaseBatch() = default;
    virtual ~DatabaseBatch() = default;

    DatabaseBatch(const DatabaseBatch&) = delete;
    DatabaseBatch& operator=(const DatabaseBatch&) = delete;

    template <typename K, typename T>
    bool Read(const K& key, T& value)
    {
        CDataStream key_stream(SER_DISK, CLIENT_VERSION);
        key_stream.reserve(1000);
        key_stream << key;

        CDataStream value_stream(SER_DISK, CLIENT_VERSION);
        if (!ReadRaw(std::move(key_stream), value_stream)) {
            return false;
        }

        try {
            value_stream >> value;
            return true;
        } catch (const std::exception&) {
            return false;
        }
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
    bool Exists(const K& key)
    {
        CDataStream key_stream(SER_DISK, CLIENT_VERSION);
        key_stream.reserve(1000);
        key_stream << key;

        return HasRaw(std::move(key_stream));
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

struct DatabaseOptions {
    bool require_existing{false};
    bool require_create{false};
    std::optional<DatabaseFormat> require_format;
    bool verify{true};
    bool salvage{false};
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
    /**
     * Compact the database, update its singleton version record, and omit raw
     * serialized keys beginning with skip when it is non-null.
     */
    virtual bool Rewrite(const char* skip = nullptr) = 0;
    /** Write a consistent live snapshot to destination. */
    virtual bool Backup(const std::string& destination) = 0;
    virtual bool PeriodicFlush() = 0;
    virtual void Flush(bool shutdown) = 0;
};

/** Resolve a safe flat wallet filename inside the network data directory. */
bool GetWalletDatabasePath(const std::string& filename, fs::path& path, std::string& error);

/** Check whether a wallet path entry exists without following symlinks. */
bool WalletDatabasePathExists(const fs::path& path, bool& exists, std::string& error);

/** Select, verify, and construct the wallet database owner for filename. */
std::unique_ptr<WalletDatabase> MakeWalletDatabase(
    const std::string& filename,
    const DatabaseOptions& options,
    DatabaseStatus& status,
    std::string& error);

#endif // FIRO_WALLET_DATABASE_H
