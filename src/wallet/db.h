// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_DB_H
#define BITCOIN_WALLET_DB_H

#include "wallet/database.h"

#include "serialize.h"
#include "sync.h"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <boost/filesystem/path.hpp>

#include <db_cxx.h>

static const unsigned int DEFAULT_WALLET_DBLOGSIZE = 100;
static const bool DEFAULT_WALLET_PRIVDB = true;

class CDBEnv
{
private:
    bool fDbEnvInit;
    bool fMockDb;
    // Don't change into boost::filesystem::path, as that can result in
    // shutdown problems/crashes caused by a static initialized internal pointer.
    std::string strPath;

    void EnvShutdown();

public:
    mutable CCriticalSection cs_db;
    DbEnv *dbenv;
    std::map<std::string, int> mapFileUseCount;
    std::map<std::string, Db*> mapDb;

    CDBEnv();
    ~CDBEnv();
    void Reset();

    void MakeMock();
    bool IsMock() { return fMockDb; }

    /**
     * Verify that database file strFile is OK. If it is not,
     * call the callback to try to recover.
     * This must be called BEFORE strFile is opened.
     * Returns true if strFile is OK.
     */
    enum VerifyResult { VERIFY_OK,
                        RECOVER_OK,
                        RECOVER_FAIL };
    VerifyResult Verify(const std::string& strFile, bool (*recoverFunc)(CDBEnv& dbenv, const std::string& strFile));
    /**
     * Salvage data from a file that Verify says is bad.
     * fAggressive sets the DB_AGGRESSIVE flag (see berkeley DB->verify() method documentation).
     * Appends binary key/value pairs to vResult, returns true if successful.
     * NOTE: reads the entire database into memory, so cannot be used
     * for huge databases.
     */
    typedef std::pair<std::vector<unsigned char>, std::vector<unsigned char> > KeyValPair;
    bool Salvage(const std::string& strFile, bool fAggressive, std::vector<KeyValPair>& vResult);

    bool Open(const boost::filesystem::path& path);
    void Close();
    void Flush(bool fShutdown);
    void CheckpointLSN(const std::string& strFile);

    void CloseDb(const std::string& strFile);
    bool RemoveDb(const std::string& strFile);

    DbTxn* TxnBegin(int flags = DB_TXN_WRITE_NOSYNC)
    {
        DbTxn* ptxn = NULL;
        int ret = dbenv->txn_begin(NULL, &ptxn, flags);
        if (!ptxn || ret != 0)
            return NULL;
        return ptxn;
    }
};

extern CDBEnv bitdb;

struct BerkeleyFileIdentity {
    uint64_t device{0};
    uint64_t inode{0};
};

/**
 * Persistent identity and lifecycle operations for one Berkeley DB wallet.
 *
 * Batches borrow this object, so it must outlive every CDB constructed from
 * it.
 */
class BerkeleyDatabase final : public WalletDatabase
{
    friend class CDB;

private:
    enum class FirstOpenRequirement {
        NONE,
        EXISTING,
        CREATE,
    };

    CDBEnv* const m_env;
    const std::string m_filename;
    FirstOpenRequirement m_first_open_requirement{
        FirstOpenRequirement::NONE};
    std::optional<BerkeleyFileIdentity> m_first_open_identity;

public:
    /** Construct an inert database identity for a memory-only wallet. */
    BerkeleyDatabase()
        : m_env(nullptr)
    {
    }

    BerkeleyDatabase(CDBEnv& env, std::string filename)
        : m_env(&env),
          m_filename(std::move(filename))
    {
    }

    BerkeleyDatabase(
        CDBEnv& env,
        std::string filename,
        const DatabaseOptions& options,
        std::optional<BerkeleyFileIdentity> first_open_identity)
        : m_env(&env),
          m_filename(std::move(filename)),
          m_first_open_requirement(
              options.require_create ?
                  FirstOpenRequirement::CREATE :
              options.require_existing ?
                  FirstOpenRequirement::EXISTING :
                  FirstOpenRequirement::NONE),
          m_first_open_identity(
              std::move(first_open_identity))
    {
    }

    BerkeleyDatabase(const BerkeleyDatabase&) = delete;
    BerkeleyDatabase& operator=(const BerkeleyDatabase&) = delete;
    ~BerkeleyDatabase() override = default;

    const std::string& Filename() const override { return m_filename; }
    DatabaseFormat Format() const override { return DatabaseFormat::BERKELEY; }

    std::unique_ptr<DatabaseBatch> MakeBatch(const DatabaseBatchOptions& options = {}) override;
    bool Rewrite(const char* skip = nullptr) override;
    bool Backup(const std::string& destination) override;
    bool PeriodicFlush() override;
    void Flush(bool shutdown) override;
};


/** Berkeley DB implementation of a wallet database batch. */
class CDB : public DatabaseBatch
{
    friend class BerkeleyDatabase;

protected:
    BerkeleyDatabase& m_database;
    Db* pdb;
    std::string strFile;
    DbTxn* activeTxn;
    bool fReadOnly;
    bool fFlushOnClose;

    explicit CDB(BerkeleyDatabase& database, const char* pszMode = "r+", bool fFlushOnCloseIn = true);
    ~CDB() override { Close(); }
    static bool RewriteInternal(BerkeleyDatabase& database, const char* pszSkip, bool failBeforeRename);

private:
    DatabaseReadStatus ReadRaw(CDataStream&& key, CDataStream& value) override;
    bool WriteRaw(CDataStream&& key, CDataStream&& value, bool overwrite) override;
    bool EraseRaw(CDataStream&& key) override;
    DatabaseReadStatus HasRaw(CDataStream&& key) override;

    CDB(const CDB&) = delete;
    CDB& operator=(const CDB&) = delete;

public:
    void Flush() override;
    void Close() override;

    std::unique_ptr<DatabaseCursor> GetCursor() override;
    std::unique_ptr<DatabaseCursor> GetCursor(const CDataStream& start_key) override;

    bool TxnBegin() override;
    bool TxnCommit() override;
    bool TxnAbort() override;
    bool HasActiveTxn() const override { return activeTxn != nullptr; }

    static bool Rewrite(BerkeleyDatabase& database, const char* pszSkip = NULL);
};

std::unique_ptr<WalletDatabase> MakeBerkeleyDatabase(
    CDBEnv& env,
    std::string filename,
    const DatabaseOptions& options = {},
    std::optional<BerkeleyFileIdentity> first_open_identity =
        std::nullopt);
std::unique_ptr<WalletDatabase> MakeDummyWalletDatabase();
/** Return whether path has BDB B-tree magic; throw if it cannot be inspected. */
bool IsBerkeleyDatabase(const fs::path& path);

#endif // BITCOIN_WALLET_DB_H
