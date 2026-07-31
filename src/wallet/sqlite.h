// Copyright (c) 2020-present The Bitcoin Core developers
// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_WALLET_SQLITE_H
#define FIRO_WALLET_SQLITE_H

#include "wallet/database.h"

#include <cstdint>
#include <memory>
#include <string>

struct sqlite3;
struct sqlite3_stmt;
class BerkeleyDatabase;

enum class SQLiteMigrationPublishResult {
    SUCCESS,
    FAILED,
    INDETERMINATE,
};

/**
 * Narrow statement execution seam used to exercise transaction failure
 * recovery. Production batches use the default implementation.
 */
class SQLiteStatementExecutor
{
public:
    virtual ~SQLiteStatementExecutor() = default;
    virtual int Execute(sqlite3* database, const char* statement);
};

/** Narrow BLOB-access seam used to exercise point-read allocation failures. */
class SQLiteColumnReader
{
public:
    virtual ~SQLiteColumnReader() = default;
    virtual const void* Blob(sqlite3_stmt* statement, int column);
    virtual int Bytes(sqlite3_stmt* statement, int column);
    virtual int ErrorCode(sqlite3* database);
};

/** Construct and verify a SQLite wallet backend. */
std::unique_ptr<WalletDatabase> MakeSQLiteDatabase(
    const std::string& filename,
    const DatabaseOptions& options,
    DatabaseStatus& status,
    std::string& error);

/** Atomically exchange a completed SQLite migration candidate with its BDB source. */
SQLiteMigrationPublishResult PublishSQLiteMigrationCandidate(
    WalletDatabase& candidate,
    BerkeleyDatabase& source,
    std::string& error);

/** Replace transaction statement execution for one SQLite batch. */
bool SetSQLiteStatementExecutorForTesting(
    DatabaseBatch& batch,
    std::unique_ptr<SQLiteStatementExecutor> executor);

/** Replace BLOB column access for one SQLite batch. */
bool SetSQLiteColumnReaderForTesting(
    DatabaseBatch& batch,
    std::unique_ptr<SQLiteColumnReader> reader);

/** Read the effective synchronous mode from one SQLite batch. */
bool GetSQLiteSynchronousModeForTesting(
    DatabaseBatch& batch,
    int64_t& mode);

/** Fail the next SQLite creation or backup after publishing its candidate. */
void InjectSQLitePostPublishFailureForTesting();

/** Report an error after the next candidate rename has actually succeeded. */
void InjectSQLiteAmbiguousPublishFailureForTesting();

/** Report an error after the next migration exchange has actually succeeded. */
void InjectSQLiteMigrationExchangeFailureForTesting();

/** Report an error after the next rewrite commit has actually succeeded. */
void InjectSQLiteRewriteCommitFailureForTesting();

/** Replace statement execution for one SQLite logical-creation owner. */
bool SetSQLiteCreationStatementExecutorForTesting(
    WalletDatabase& database,
    std::unique_ptr<SQLiteStatementExecutor> executor);

/** Fail one close after the requested number of successful close attempts. */
void InjectSQLiteCloseFailureForTesting(
    int successful_closes_before_failure = 0);

/** Recover the single deliberately abandoned connection created by a test. */
bool ResetSQLiteLifecycleForTesting();

#endif // FIRO_WALLET_SQLITE_H
