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

/**
 * Construct and verify a SQLite wallet backend without enabling SQLite in the
 * generic wallet database factory.
 */
std::unique_ptr<WalletDatabase> MakeSQLiteDatabase(
    const std::string& filename,
    const DatabaseOptions& options,
    DatabaseStatus& status,
    std::string& error);

/** Replace transaction statement execution for one SQLite batch. */
bool SetSQLiteStatementExecutorForTesting(
    DatabaseBatch& batch,
    std::unique_ptr<SQLiteStatementExecutor> executor);

/** Read the effective synchronous mode from one SQLite batch. */
bool GetSQLiteSynchronousModeForTesting(
    DatabaseBatch& batch,
    int64_t& mode);

/** Fail the next SQLite creation or backup after publishing its candidate. */
void InjectSQLitePostPublishFailureForTesting();

/** Report an error after the next candidate rename has actually succeeded. */
void InjectSQLiteAmbiguousPublishFailureForTesting();

/** Fail one close after the requested number of successful close attempts. */
void InjectSQLiteCloseFailureForTesting(
    int successful_closes_before_failure = 0);

/** Recover the single deliberately abandoned connection created by a test. */
bool ResetSQLiteLifecycleForTesting();

#endif // FIRO_WALLET_SQLITE_H
