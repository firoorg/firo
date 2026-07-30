// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "db.h"

#include "addrman.h"
#include "hash.h"
#include "protocol.h"
#include "util.h"
#include "utilstrencodings.h"

#include <cstdlib>
#include <cstring>
#include <stdint.h>

#ifndef WIN32
#include <sys/stat.h>
#endif

#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <boost/version.hpp>


//
// CDB
//

CDBEnv bitdb;

namespace
{
void CleanseStream(CDataStream& stream)
{
    if (!stream.empty()) {
        memory_cleanse(stream.data(), stream.size());
    }
}

class BerkeleyMallocDbt final
{
private:
    Dbt m_data;
    const void* m_borrowed;

public:
    BerkeleyMallocDbt()
        : BerkeleyMallocDbt(nullptr)
    {
    }

    explicit BerkeleyMallocDbt(CDataStream* input)
        : m_borrowed(input ? input->data() : nullptr)
    {
        if (input) {
            m_data.set_data(input->data());
            m_data.set_size(input->size());
        }
        m_data.set_flags(DB_DBT_MALLOC);
    }

    ~BerkeleyMallocDbt()
    {
        void* const raw = m_data.get_data();
        if (raw && raw != m_borrowed) {
            memory_cleanse(raw, m_data.get_size());
            free(raw);
        }
    }

    BerkeleyMallocDbt(const BerkeleyMallocDbt&) = delete;
    BerkeleyMallocDbt& operator=(const BerkeleyMallocDbt&) = delete;

    Dbt* Get() { return &m_data; }
    void* Data() const { return m_data.get_data(); }
    size_t Size() const { return m_data.get_size(); }
};

struct BerkeleyCursorCloser {
    void operator()(Dbc* cursor) const noexcept
    {
        if (cursor) {
            cursor->close();
        }
    }
};

using BerkeleyCursorHandle = std::unique_ptr<Dbc, BerkeleyCursorCloser>;

class BerkeleyCursor final : public DatabaseCursor
{
private:
    BerkeleyCursorHandle m_cursor;
    CDataStream m_start_key;
    bool m_seek;

public:
    explicit BerkeleyCursor(BerkeleyCursorHandle cursor)
        : m_cursor(std::move(cursor)),
          m_start_key(SER_DISK, CLIENT_VERSION),
          m_seek(false)
    {
    }

    BerkeleyCursor(BerkeleyCursorHandle cursor, const CDataStream& start_key)
        : m_cursor(std::move(cursor)),
          m_start_key(start_key),
          m_seek(true)
    {
    }

    ~BerkeleyCursor() override
    {
        CleanseStream(m_start_key);
    }

    Status Next(CDataStream& key, CDataStream& value) override
    {
        BerkeleyMallocDbt db_key(m_seek ? &m_start_key : nullptr);
        unsigned int flags = DB_NEXT;
        if (m_seek) {
            flags = DB_SET_RANGE;
        }

        BerkeleyMallocDbt db_value;
        const int result = m_cursor->get(db_key.Get(), db_value.Get(), flags);
        m_seek = false;

        if (result != 0) {
            CleanseStream(m_start_key);
            m_start_key.clear();
            return result == DB_NOTFOUND ? Status::DONE : Status::FAIL;
        }

        if ((db_key.Size() != 0 && db_key.Data() == nullptr) ||
            (db_value.Size() != 0 && db_value.Data() == nullptr)) {
            CleanseStream(m_start_key);
            m_start_key.clear();
            return Status::FAIL;
        }

        key.SetType(SER_DISK);
        key.clear();
        if (db_key.Size() != 0) {
            key.write(static_cast<const char*>(db_key.Data()), db_key.Size());
        }

        value.SetType(SER_DISK);
        value.clear();
        if (db_value.Size() != 0) {
            value.write(static_cast<const char*>(db_value.Data()), db_value.Size());
        }

        CleanseStream(m_start_key);
        m_start_key.clear();
        return Status::MORE;
    }
};
} // namespace

void CDBEnv::EnvShutdown()
{
    if (!fDbEnvInit)
        return;

    fDbEnvInit = false;
    int ret = dbenv->close(0);
    if (ret != 0)
        LogPrintf("CDBEnv::EnvShutdown: Error %d shutting down database environment: %s\n", ret, DbEnv::strerror(ret));
    if (!fMockDb)
        DbEnv((u_int32_t)0).remove(strPath.c_str(), 0);
}

void CDBEnv::Reset()
{
    delete dbenv;
    dbenv = new DbEnv(DB_CXX_NO_EXCEPTIONS);
    fDbEnvInit = false;
    fMockDb = false;
}

CDBEnv::CDBEnv() : dbenv(NULL)
{
    Reset();
}

CDBEnv::~CDBEnv()
{
    EnvShutdown();
    delete dbenv;
    dbenv = NULL;
}

void CDBEnv::Close()
{
    EnvShutdown();
}

bool CDBEnv::Open(const boost::filesystem::path& pathIn)
{
    if (fDbEnvInit)
        return true;

    boost::this_thread::interruption_point();

    strPath = pathIn.string();
    boost::filesystem::path pathLogDir = pathIn / "database";
    TryCreateDirectory(pathLogDir);
    boost::filesystem::path pathErrorFile = pathIn / "db.log";
    LogPrintf("CDBEnv::Open: LogDir=%s ErrorFile=%s\n", pathLogDir.string(), pathErrorFile.string());

    unsigned int nEnvFlags = 0;
    if (GetBoolArg("-privdb", DEFAULT_WALLET_PRIVDB))
        nEnvFlags |= DB_PRIVATE;

    dbenv->set_lg_dir(pathLogDir.string().c_str());
    dbenv->set_cachesize(0, 0x100000, 1); // 1 MiB should be enough for just the wallet
    dbenv->set_lg_bsize(0x10000);
    dbenv->set_lg_max(1048576);
    dbenv->set_lk_max_locks(40000);
    dbenv->set_lk_max_objects(40000);
    dbenv->set_errfile(fopen(pathErrorFile.string().c_str(), "a")); /// debug
    dbenv->set_flags(DB_AUTO_COMMIT, 1);
    dbenv->set_flags(DB_TXN_WRITE_NOSYNC, 1);
    dbenv->log_set_config(DB_LOG_AUTO_REMOVE, 1);
    int ret = dbenv->open(strPath.c_str(),
                         DB_CREATE |
                             DB_INIT_LOCK |
                             DB_INIT_LOG |
                             DB_INIT_MPOOL |
                             DB_INIT_TXN |
                             DB_THREAD |
                             DB_RECOVER |
                             nEnvFlags,
                         S_IRUSR | S_IWUSR);
    if (ret != 0)
        return error("CDBEnv::Open: Error %d opening database environment: %s\n", ret, DbEnv::strerror(ret));

    fDbEnvInit = true;
    fMockDb = false;
    return true;
}

void CDBEnv::MakeMock()
{
    if (fDbEnvInit)
        throw std::runtime_error("CDBEnv::MakeMock: Already initialized");

    boost::this_thread::interruption_point();

    LogPrint("db", "CDBEnv::MakeMock\n");

    dbenv->set_cachesize(1, 0, 1);
    dbenv->set_lg_bsize(10485760 * 4);
    dbenv->set_lg_max(10485760);
    dbenv->set_lk_max_locks(10000);
    dbenv->set_lk_max_objects(10000);
    dbenv->set_flags(DB_AUTO_COMMIT, 1);
    dbenv->log_set_config(DB_LOG_IN_MEMORY, 1);
    int ret = dbenv->open(NULL,
                         DB_CREATE |
                             DB_INIT_LOCK |
                             DB_INIT_LOG |
                             DB_INIT_MPOOL |
                             DB_INIT_TXN |
                             DB_THREAD |
                             DB_PRIVATE,
                         S_IRUSR | S_IWUSR);
    if (ret > 0)
        throw std::runtime_error(strprintf("CDBEnv::MakeMock: Error %d opening database environment.", ret));

    fDbEnvInit = true;
    fMockDb = true;
}

CDBEnv::VerifyResult CDBEnv::Verify(const std::string& strFile, bool (*recoverFunc)(CDBEnv& dbenv, const std::string& strFile))
{
    LOCK(cs_db);
    assert(mapFileUseCount.count(strFile) == 0);

    Db db(dbenv, 0);
    int result = db.verify(strFile.c_str(), NULL, NULL, 0);
    if (result == 0)
        return VERIFY_OK;
    else if (recoverFunc == NULL)
        return RECOVER_FAIL;

    // Try to recover:
    bool fRecovered = (*recoverFunc)(*this, strFile);
    return (fRecovered ? RECOVER_OK : RECOVER_FAIL);
}

/* End of headers, beginning of key/value data */
static const char *HEADER_END = "HEADER=END";
/* End of key/value data */
static const char *DATA_END = "DATA=END";

bool CDBEnv::Salvage(const std::string& strFile, bool fAggressive, std::vector<CDBEnv::KeyValPair>& vResult)
{
    LOCK(cs_db);
    assert(mapFileUseCount.count(strFile) == 0);

    u_int32_t flags = DB_SALVAGE;
    if (fAggressive)
        flags |= DB_AGGRESSIVE;

    std::stringstream strDump;

    Db db(dbenv, 0);
    int result = db.verify(strFile.c_str(), NULL, &strDump, flags);
    if (result == DB_VERIFY_BAD) {
        LogPrintf("CDBEnv::Salvage: Database salvage found errors, all data may not be recoverable.\n");
        if (!fAggressive) {
            LogPrintf("CDBEnv::Salvage: Rerun with aggressive mode to ignore errors and continue.\n");
            return false;
        }
    }
    if (result != 0 && result != DB_VERIFY_BAD) {
        LogPrintf("CDBEnv::Salvage: Database salvage failed with result %d.\n", result);
        return false;
    }

    // Format of bdb dump is ascii lines:
    // header lines...
    // HEADER=END
    //  hexadecimal key
    //  hexadecimal value
    //  ... repeated
    // DATA=END

    std::string strLine;
    while (!strDump.eof() && strLine != HEADER_END)
        getline(strDump, strLine); // Skip past header

    std::string keyHex, valueHex;
    while (!strDump.eof() && keyHex != DATA_END) {
        getline(strDump, keyHex);
        if (keyHex != DATA_END) {
            if (strDump.eof())
                break;
            getline(strDump, valueHex);
            if (valueHex == DATA_END) {
                LogPrintf("CDBEnv::Salvage: WARNING: Number of keys in data does not match number of values.\n");
                break;
            }
            vResult.push_back(make_pair(ParseHex(keyHex), ParseHex(valueHex)));
        }
    }

    if (keyHex != DATA_END) {
        LogPrintf("CDBEnv::Salvage: WARNING: Unexpected end of file while reading salvage output.\n");
        return false;
    }

    return (result == 0);
}


void CDBEnv::CheckpointLSN(const std::string& strFile)
{
    dbenv->txn_checkpoint(0, 0, 0);
    if (fMockDb)
        return;
    dbenv->lsn_reset(strFile.c_str(), 0);
}


CDB::CDB(BerkeleyDatabase& database, const char* pszMode, bool fFlushOnCloseIn)
    : m_database(database),
      pdb(NULL),
      activeTxn(NULL)
{
    const std::string& strFilename = database.m_filename;
    int ret;
    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));
    fFlushOnClose = fFlushOnCloseIn;
    if (!database.m_env || strFilename.empty())
        return;

    bool fCreate = strchr(pszMode, 'c') != NULL;
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;

    CDBEnv& env = *m_database.m_env;
    {
        LOCK(env.cs_db);
        if (!env.Open(GetDataDir()))
            throw std::runtime_error("CDB: Failed to open database environment.");

        strFile = strFilename;
        ++env.mapFileUseCount[strFile];
        pdb = env.mapDb[strFile];
        if (pdb == NULL) {
            pdb = new Db(env.dbenv, 0);

            bool fMockDb = env.IsMock();
            if (fMockDb) {
                DbMpoolFile* mpf = pdb->get_mpf();
                ret = mpf->set_flags(DB_MPOOL_NOFILE, 1);
                if (ret != 0)
                    throw std::runtime_error(strprintf("CDB: Failed to configure for no temp file backing for database %s", strFile));
            }

            ret = pdb->open(NULL,                               // Txn pointer
                            fMockDb ? NULL : strFile.c_str(),   // Filename
                            fMockDb ? strFile.c_str() : "main", // Logical db name
                            DB_BTREE,                           // Database type
                            nFlags,                             // Flags
                            0);

            if (ret != 0) {
                delete pdb;
                pdb = NULL;
                --env.mapFileUseCount[strFile];
                strFile = "";
                throw std::runtime_error(strprintf("CDB: Error %d, can't open database %s", ret, strFilename));
            }

            if (fCreate && !Exists(std::string("version"))) {
                bool fTmp = fReadOnly;
                fReadOnly = false;
                WriteVersion(CLIENT_VERSION);
                fReadOnly = fTmp;
            }

            env.mapDb[strFile] = pdb;
        }
    }
}

bool CDB::ReadRaw(CDataStream&& key, CDataStream& value)
{
    if (!pdb) {
        return false;
    }

    Dbt db_key(key.data(), key.size());
    BerkeleyMallocDbt db_value;
    const int result = pdb->get(activeTxn, &db_key, db_value.Get(), 0);
    CleanseStream(key);

    if (result != 0 ||
        (db_value.Size() != 0 && db_value.Data() == nullptr)) {
        return false;
    }

    value.SetType(SER_DISK);
    value.clear();
    if (db_value.Size() != 0) {
        value.write(static_cast<const char*>(db_value.Data()), db_value.Size());
    }
    return true;
}

bool CDB::WriteRaw(CDataStream&& key, CDataStream&& value, bool overwrite)
{
    if (!pdb) {
        return false;
    }
    if (fReadOnly) {
        assert(!"Write called on database in read-only mode");
    }

    Dbt db_key(key.data(), key.size());
    Dbt db_value(value.data(), value.size());
    const int result = pdb->put(activeTxn, &db_key, &db_value, overwrite ? 0 : DB_NOOVERWRITE);

    CleanseStream(key);
    CleanseStream(value);
    return result == 0;
}

bool CDB::EraseRaw(CDataStream&& key)
{
    if (!pdb) {
        return false;
    }
    if (fReadOnly) {
        assert(!"Erase called on database in read-only mode");
    }

    Dbt db_key(key.data(), key.size());
    const int result = pdb->del(activeTxn, &db_key, 0);
    CleanseStream(key);
    return result == 0 || result == DB_NOTFOUND;
}

bool CDB::HasRaw(CDataStream&& key)
{
    if (!pdb) {
        return false;
    }

    Dbt db_key(key.data(), key.size());
    const int result = pdb->exists(activeTxn, &db_key, 0);
    CleanseStream(key);
    return result == 0;
}

void CDB::Flush()
{
    if (!m_database.m_env || m_database.m_filename.empty() || activeTxn)
        return;

    // Flush database activity from memory pool to disk log
    unsigned int nMinutes = 0;
    if (fReadOnly)
        nMinutes = 1;

    m_database.m_env->dbenv->txn_checkpoint(nMinutes ? GetArg("-dblogsize", DEFAULT_WALLET_DBLOGSIZE) * 1024 : 0, nMinutes, 0);
}

void CDB::Close()
{
    if (!pdb)
        return;
    if (activeTxn)
        activeTxn->abort();
    activeTxn = NULL;
    pdb = NULL;

    if (fFlushOnClose)
        Flush();

    {
        LOCK(m_database.m_env->cs_db);
        --m_database.m_env->mapFileUseCount[strFile];
    }
}

std::unique_ptr<DatabaseCursor> CDB::GetCursor()
{
    if (!pdb) {
        return nullptr;
    }

    Dbc* cursor = nullptr;
    if (pdb->cursor(nullptr, &cursor, 0) != 0) {
        return nullptr;
    }
    return std::make_unique<BerkeleyCursor>(BerkeleyCursorHandle(cursor));
}

std::unique_ptr<DatabaseCursor> CDB::GetCursor(const CDataStream& start_key)
{
    if (!pdb) {
        return nullptr;
    }

    Dbc* cursor = nullptr;
    if (pdb->cursor(nullptr, &cursor, 0) != 0) {
        return nullptr;
    }
    return std::make_unique<BerkeleyCursor>(BerkeleyCursorHandle(cursor), start_key);
}

bool CDB::TxnBegin()
{
    if (!pdb || activeTxn) {
        return false;
    }

    DbTxn* transaction = m_database.m_env->TxnBegin();
    if (!transaction) {
        return false;
    }
    activeTxn = transaction;
    return true;
}

bool CDB::TxnCommit()
{
    if (!pdb || !activeTxn) {
        return false;
    }

    const int result = activeTxn->commit(0);
    activeTxn = nullptr;
    return result == 0;
}

bool CDB::TxnAbort()
{
    if (!pdb || !activeTxn) {
        return false;
    }

    const int result = activeTxn->abort();
    activeTxn = nullptr;
    return result == 0;
}

void CDBEnv::CloseDb(const std::string& strFile)
{
    {
        LOCK(cs_db);
        if (mapDb[strFile] != NULL) {
            // Close the database handle
            Db* pdb = mapDb[strFile];
            pdb->close(0);
            delete pdb;
            mapDb[strFile] = NULL;
        }
    }
}

bool CDBEnv::RemoveDb(const std::string& strFile)
{
    this->CloseDb(strFile);

    LOCK(cs_db);
    int rc = dbenv->dbremove(NULL, strFile.c_str(), NULL, DB_AUTO_COMMIT);
    return (rc == 0);
}

bool CDB::Rewrite(BerkeleyDatabase& database, const char* pszSkip)
{
    return RewriteInternal(database, pszSkip, false);
}

bool CDB::RewriteInternal(BerkeleyDatabase& database, const char* pszSkip, bool failBeforeRename)
{
    if (!database.m_env || database.m_filename.empty()) {
        return true;
    }
    CDBEnv& env = *database.m_env;
    const std::string& strFile = database.m_filename;
    while (true) {
        {
            LOCK(env.cs_db);
            if (!env.mapFileUseCount.count(strFile) || env.mapFileUseCount[strFile] == 0) {
                // Flush log data to the dat file
                env.CloseDb(strFile);
                env.CheckpointLSN(strFile);
                env.mapFileUseCount.erase(strFile);

                bool fSuccess = true;
                LogPrintf("CDB::Rewrite: Rewriting %s...\n", strFile);
                std::string strFileRes = strFile + ".rewrite";
                { // surround usage of db with extra {}
                    CDB db(database, "r");
                    auto pdbCopy = std::make_unique<Db>(env.dbenv, 0);

                    int ret = pdbCopy->open(NULL, // Txn pointer
                        strFileRes.c_str(),       // Filename
                        "main",                   // Logical db name
                        DB_BTREE,                 // Database type
                        DB_CREATE | DB_EXCL,      // Flags
                        0);
                    const bool copyOpen = ret == 0;
                    if (!copyOpen) {
                        LogPrintf("CDB::Rewrite: Can't create database file %s\n", strFileRes);
                        fSuccess = false;
                    }

                    auto cursor = db.GetCursor();
                    if (!cursor) {
                        fSuccess = false;
                    }
                    while (fSuccess) {
                        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
                        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
                        const DatabaseCursor::Status status = cursor->Next(ssKey, ssValue);
                        if (status == DatabaseCursor::Status::DONE) {
                            break;
                        }
                        if (status == DatabaseCursor::Status::FAIL) {
                            fSuccess = false;
                            break;
                        }

                        const size_t skipSize = pszSkip ? strlen(pszSkip) : 0;
                        if (skipSize != 0 && ssKey.size() >= skipSize &&
                            memcmp(ssKey.data(), pszSkip, skipSize) == 0) {
                            continue;
                        }

                        static const char serializedVersion[] = "\x07version";
                        if (ssKey.size() == sizeof(serializedVersion) - 1 &&
                            memcmp(ssKey.data(), serializedVersion, sizeof(serializedVersion) - 1) == 0) {
                            ssValue.clear();
                            ssValue << CLIENT_VERSION;
                        }

                        Dbt datKey(ssKey.data(), ssKey.size());
                        Dbt datValue(ssValue.data(), ssValue.size());
                        if (pdbCopy->put(NULL, &datKey, &datValue, DB_NOOVERWRITE) != 0) {
                            fSuccess = false;
                        }
                    }

                    cursor.reset();
                    db.Close();
                    env.CloseDb(strFile);
                    if (copyOpen && pdbCopy->close(0) != 0) {
                        fSuccess = false;
                    }
                }
                if (fSuccess) {
                    DbTxn* publishTxn = env.TxnBegin(0);
                    if (!publishTxn) {
                        fSuccess = false;
                    } else if (env.dbenv->dbremove(publishTxn, strFile.c_str(), nullptr, 0) != 0 ||
                               failBeforeRename ||
                               env.dbenv->dbrename(publishTxn, strFileRes.c_str(), nullptr, strFile.c_str(), 0) != 0) {
                        publishTxn->abort();
                        fSuccess = false;
                    } else {
                        fSuccess = publishTxn->commit(DB_TXN_SYNC) == 0;
                    }
                }
                if (!fSuccess)
                    LogPrintf("CDB::Rewrite: Failed to rewrite database file %s\n", strFileRes);
                return fSuccess;
            }
        }
        MilliSleep(100);
    }
    return false;
}

bool BerkeleyDatabase::Rewrite(const char* skip)
{
    return CDB::Rewrite(*this, skip);
}

bool BerkeleyDatabase::Backup(const std::string& destination)
{
    if (!m_env || m_filename.empty()) {
        return false;
    }
    while (true) {
        {
            LOCK(m_env->cs_db);
            if (!m_env->mapFileUseCount.count(m_filename) || m_env->mapFileUseCount[m_filename] == 0) {
                m_env->CloseDb(m_filename);
                m_env->CheckpointLSN(m_filename);
                m_env->mapFileUseCount.erase(m_filename);

                boost::filesystem::path source = GetDataDir() / m_filename;
                boost::filesystem::path target(destination);
                if (boost::filesystem::is_directory(target)) {
                    target /= m_filename;
                }

                try {
#if BOOST_VERSION >= 104000
                    const auto copyOptions = boost::filesystem::copy_options::overwrite_existing;
                    boost::filesystem::copy(source, target, copyOptions);
#else
                    boost::filesystem::copy_file(source, target);
#endif
                    LogPrintf("copied %s to %s\n", m_filename, target.string());
                    return true;
                } catch (const boost::filesystem::filesystem_error& error) {
                    LogPrintf("error copying %s to %s - %s\n", m_filename, target.string(), error.what());
                    return false;
                }
            }
        }
        MilliSleep(100);
    }
}

bool BerkeleyDatabase::PeriodicFlush()
{
    if (!m_env || m_filename.empty()) {
        return false;
    }
    TRY_LOCK(m_env->cs_db, lockDb);
    if (!lockDb) {
        return false;
    }

    int refCount = 0;
    for (const auto& entry : m_env->mapFileUseCount) {
        refCount += entry.second;
    }
    if (refCount != 0) {
        return false;
    }

    boost::this_thread::interruption_point();
    auto file = m_env->mapFileUseCount.find(m_filename);
    if (file == m_env->mapFileUseCount.end()) {
        return false;
    }

    LogPrint("db", "Flushing %s\n", m_filename);
    const int64_t start = GetTimeMillis();
    m_env->CloseDb(m_filename);
    m_env->CheckpointLSN(m_filename);
    m_env->mapFileUseCount.erase(file);
    LogPrint("db", "Flushed %s %dms\n", m_filename, GetTimeMillis() - start);
    return true;
}

void BerkeleyDatabase::Flush(bool shutdown)
{
    if (m_env && !m_filename.empty()) {
        m_env->Flush(shutdown);
    }
}

void CDBEnv::Flush(bool fShutdown)
{
    int64_t nStart = GetTimeMillis();
    // Flush log data to the actual data file on all files that are not in use
    LogPrint("db", "CDBEnv::Flush: Flush(%s)%s\n", fShutdown ? "true" : "false", fDbEnvInit ? "" : " database not started");
    if (!fDbEnvInit)
        return;
    {
        LOCK(cs_db);
        std::map<std::string, int>::iterator mi = mapFileUseCount.begin();
        while (mi != mapFileUseCount.end()) {
            std::string strFile = (*mi).first;
            int nRefCount = (*mi).second;
            LogPrint("db", "CDBEnv::Flush: Flushing %s (refcount = %d)...\n", strFile, nRefCount);
            if (nRefCount == 0) {
                // Move log data to the dat file
                CloseDb(strFile);
                LogPrint("db", "CDBEnv::Flush: %s checkpoint\n", strFile);
                dbenv->txn_checkpoint(0, 0, 0);
                LogPrint("db", "CDBEnv::Flush: %s detach\n", strFile);
                if (!fMockDb)
                    dbenv->lsn_reset(strFile.c_str(), 0);
                LogPrint("db", "CDBEnv::Flush: %s closed\n", strFile);
                mapFileUseCount.erase(mi++);
            } else
                mi++;
        }
        LogPrint("db", "CDBEnv::Flush: Flush(%s)%s took %15dms\n", fShutdown ? "true" : "false", fDbEnvInit ? "" : " database not started", GetTimeMillis() - nStart);
        if (fShutdown) {
            char** listp;
            if (mapFileUseCount.empty()) {
                dbenv->log_archive(&listp, DB_ARCH_REMOVE);
                Close();
                if (!fMockDb)
                    boost::filesystem::remove_all(boost::filesystem::path(strPath) / "database");
            }
        }
    }
}
