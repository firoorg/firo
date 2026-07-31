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

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <stdint.h>

#ifndef WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
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

bool BerkeleyIdentityMatches(
    Db& database,
    const fs::path& path,
    const std::optional<DatabaseFileIdentity>& expected)
{
    if (!expected) {
        return true;
    }
#ifdef WIN32
    return false;
#else
    int descriptor = -1;
    struct stat descriptor_status{};
    struct stat path_status{};
    return database.fd(&descriptor) == 0 &&
           descriptor >= 0 &&
           fstat(descriptor, &descriptor_status) == 0 &&
           S_ISREG(descriptor_status.st_mode) &&
           lstat(path.string().c_str(), &path_status) == 0 &&
           S_ISREG(path_status.st_mode) &&
           static_cast<uint64_t>(descriptor_status.st_dev) ==
               expected->device &&
           static_cast<uint64_t>(descriptor_status.st_ino) ==
               expected->inode &&
           static_cast<uint64_t>(path_status.st_dev) ==
               expected->device &&
           static_cast<uint64_t>(path_status.st_ino) ==
               expected->inode;
#endif
}

#ifndef WIN32
class ScopedMigrationDescriptor final
{
private:
    int m_descriptor{-1};

public:
    ScopedMigrationDescriptor() = default;
    explicit ScopedMigrationDescriptor(int descriptor)
        : m_descriptor(descriptor)
    {
    }

    ~ScopedMigrationDescriptor()
    {
        if (m_descriptor >= 0) {
            close(m_descriptor);
        }
    }

    ScopedMigrationDescriptor(
        const ScopedMigrationDescriptor&) = delete;
    ScopedMigrationDescriptor& operator=(
        const ScopedMigrationDescriptor&) = delete;

    int Get() const { return m_descriptor; }

    void Reset(int descriptor)
    {
        if (m_descriptor >= 0) {
            close(m_descriptor);
        }
        m_descriptor = descriptor;
    }

    int Release()
    {
        const int descriptor = m_descriptor;
        m_descriptor = -1;
        return descriptor;
    }

    bool Close(int& close_error)
    {
        close_error = 0;
        if (m_descriptor < 0) {
            return true;
        }
        const int descriptor = Release();
        if (close(descriptor) == 0) {
            return true;
        }
        close_error = errno;
        return false;
    }
};

struct CleansedMigrationBuffer {
    std::array<unsigned char, 64 * 1024> bytes{};

    ~CleansedMigrationBuffer()
    {
        memory_cleanse(bytes.data(), bytes.size());
    }
};

bool StatMatchesMigrationIdentity(
    const struct stat& metadata,
    const DatabaseFileIdentity& identity,
    bool require_single_link)
{
    return S_ISREG(metadata.st_mode) &&
           (!require_single_link || metadata.st_nlink == 1) &&
           static_cast<uint64_t>(metadata.st_dev) ==
               identity.device &&
           static_cast<uint64_t>(metadata.st_ino) ==
               identity.inode;
}

bool DescriptorMatchesMigrationIdentity(
    int descriptor,
    const DatabaseFileIdentity& identity,
    bool require_single_link)
{
    struct stat metadata{};
    return descriptor >= 0 &&
           fstat(descriptor, &metadata) == 0 &&
           StatMatchesMigrationIdentity(
               metadata,
               identity,
               require_single_link);
}

bool PathMatchesMigrationIdentity(
    const fs::path& path,
    const DatabaseFileIdentity& identity,
    bool require_single_link)
{
    struct stat metadata{};
    return lstat(path.string().c_str(), &metadata) == 0 &&
           StatMatchesMigrationIdentity(
               metadata,
               identity,
               require_single_link);
}

bool MigrationIdentityMatches(
    int descriptor,
    const fs::path& path,
    const DatabaseFileIdentity& identity)
{
    return DescriptorMatchesMigrationIdentity(
               descriptor,
               identity,
               true) &&
           PathMatchesMigrationIdentity(
               path,
               identity,
               true);
}

bool PrivateMigrationSourceMatches(
    int descriptor,
    const fs::path& path,
    const DatabaseFileIdentity& identity)
{
    struct stat descriptor_status{};
    struct stat path_status{};
    return descriptor >= 0 &&
           fstat(descriptor, &descriptor_status) == 0 &&
           lstat(path.string().c_str(), &path_status) == 0 &&
           StatMatchesMigrationIdentity(
               descriptor_status,
               identity,
               true) &&
           StatMatchesMigrationIdentity(
               path_status,
               identity,
               true) &&
           descriptor_status.st_uid == geteuid() &&
           path_status.st_uid == geteuid() &&
           (descriptor_status.st_mode &
               (S_IWGRP | S_IWOTH)) == 0 &&
           (path_status.st_mode &
               (S_IWGRP | S_IWOTH)) == 0;
}

bool OwnerControlledMigrationDirectory(
    const fs::path& directory,
    std::string& error)
{
#if !defined(O_CLOEXEC) || !defined(O_NOFOLLOW)
    error = strprintf(
        "Cannot secure migration directory '%s': O_CLOEXEC and O_NOFOLLOW are required.",
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
    ScopedMigrationDescriptor descriptor(
        open(directory.string().c_str(), flags));
    struct stat descriptor_status{};
    struct stat path_status{};
    if (descriptor.Get() < 0 ||
        fstat(
            descriptor.Get(),
            &descriptor_status) != 0 ||
        lstat(
            directory.string().c_str(),
            &path_status) != 0 ||
        !S_ISDIR(descriptor_status.st_mode) ||
        !S_ISDIR(path_status.st_mode) ||
        descriptor_status.st_dev !=
            path_status.st_dev ||
        descriptor_status.st_ino !=
            path_status.st_ino ||
        descriptor_status.st_uid != geteuid() ||
        path_status.st_uid != geteuid() ||
        (descriptor_status.st_mode &
            (S_IWGRP | S_IWOTH)) != 0 ||
        (path_status.st_mode &
            (S_IWGRP | S_IWOTH)) != 0) {
        error = strprintf(
            "Refusing migration directory '%s': it must be an effective-user-owned, non-symlink directory without group or other write access.",
            directory.string());
        return false;
    }
    return true;
#endif
}

bool PrivateMigrationBackupMatches(
    int descriptor,
    const fs::path& path,
    const DatabaseFileIdentity& identity)
{
    struct stat descriptor_status{};
    struct stat path_status{};
    const mode_t private_mode = S_IRUSR | S_IWUSR;
    const mode_t permission_mask =
        S_IRWXU | S_IRWXG | S_IRWXO;
    return descriptor >= 0 &&
           fstat(descriptor, &descriptor_status) == 0 &&
           lstat(path.string().c_str(), &path_status) == 0 &&
           StatMatchesMigrationIdentity(
               descriptor_status,
               identity,
               true) &&
           StatMatchesMigrationIdentity(
               path_status,
               identity,
               true) &&
           descriptor_status.st_uid == geteuid() &&
           path_status.st_uid == geteuid() &&
           (descriptor_status.st_mode & permission_mask) ==
               private_mode &&
           (path_status.st_mode & permission_mask) ==
               private_mode;
}

bool SynchronizeMigrationDirectory(
    const fs::path& directory,
    std::string& error)
{
    if (!OwnerControlledMigrationDirectory(
            directory,
            error)) {
        return false;
    }
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#else
    error = strprintf(
        "Cannot synchronize migration directory '%s': O_CLOEXEC is unavailable.",
        directory.string());
    return false;
#endif
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
    ScopedMigrationDescriptor descriptor(
        open(directory.string().c_str(), flags));
    if (descriptor.Get() < 0) {
        error = strprintf(
            "Failed to open migration directory '%s': %s",
            directory.string(),
            std::strerror(errno));
        return false;
    }
    if (fsync(descriptor.Get()) != 0) {
        error = strprintf(
            "Failed to synchronize migration directory '%s': %s",
            directory.string(),
            std::strerror(errno));
        return false;
    }
    int close_error = 0;
    if (!descriptor.Close(close_error)) {
        error = strprintf(
            "Failed to close migration directory '%s': %s",
            directory.string(),
            std::strerror(close_error));
        return false;
    }
    return true;
}

bool CopyMigrationFile(
    int source,
    int target,
    const fs::path& source_path,
    const fs::path& target_path,
    std::string& error)
{
    CleansedMigrationBuffer buffer;
    while (true) {
        ssize_t read_size;
        do {
            read_size = read(
                source,
                buffer.bytes.data(),
                buffer.bytes.size());
        } while (read_size < 0 && errno == EINTR);

        if (read_size < 0) {
            error = strprintf(
                "Failed to read BDB migration source '%s': %s",
                source_path.string(),
                std::strerror(errno));
            return false;
        }
        if (read_size == 0) {
            return true;
        }

        ssize_t written = 0;
        while (written < read_size) {
            ssize_t write_size;
            do {
                write_size = write(
                    target,
                    buffer.bytes.data() + written,
                    static_cast<size_t>(read_size - written));
            } while (write_size < 0 && errno == EINTR);
            if (write_size <= 0) {
                const int write_error =
                    write_size < 0 ? errno : EIO;
                error = strprintf(
                    "Failed to write BDB migration backup '%s': %s",
                    target_path.string(),
                    std::strerror(write_error));
                return false;
            }
            written += write_size;
        }
    }
}

bool CloseAndCheckpointMigrationDatabase(
    CDBEnv& environment,
    const std::string& filename,
    std::string& error)
{
    const auto users =
        environment.mapFileUseCount.find(filename);
    if (users != environment.mapFileUseCount.end() &&
        users->second != 0) {
        error = strprintf(
            "Cannot checkpoint BDB wallet '%s' for migration while database batches remain active.",
            filename);
        return false;
    }
    environment.migrationLogPins.insert(filename);

    int close_result = 0;
    const auto cached = environment.mapDb.find(filename);
    if (cached != environment.mapDb.end()) {
        Db* const database = cached->second;
        if (database) {
            close_result = database->close(0);
            delete database;
        }
        environment.mapDb.erase(cached);
    }
    environment.mapFileUseCount.erase(filename);
    if (close_result != 0) {
        error = strprintf(
            "Failed to close BDB wallet '%s' for migration: %s",
            filename,
            DbEnv::strerror(close_result));
        return false;
    }

    const int checkpoint_result =
        environment.dbenv->txn_checkpoint(0, 0, 0);
    if (checkpoint_result != 0) {
        error = strprintf(
            "Failed to checkpoint BDB wallet '%s' for migration: %s",
            filename,
            DbEnv::strerror(checkpoint_result));
        return false;
    }
    return true;
}

bool VerifyMigrationBackup(
    CDBEnv& environment,
    const std::string& filename,
    const fs::path& path,
    std::string& error)
{
    if (environment.Verify(filename, nullptr) !=
        CDBEnv::VERIFY_OK) {
        error = strprintf(
            "Failed to verify BDB migration backup '%s'.",
            path.string());
        return false;
    }

    Db reopened(environment.dbenv, 0);
    const int open_result = reopened.open(
        nullptr,
        filename.c_str(),
        "main",
        DB_BTREE,
        DB_RDONLY | DB_THREAD,
        0);
    if (open_result != 0) {
        error = strprintf(
            "Failed to reopen BDB migration backup '%s': %s",
            path.string(),
            DbEnv::strerror(open_result));
        return false;
    }
    const int close_result = reopened.close(0);
    if (close_result != 0) {
        error = strprintf(
            "Failed to close verified BDB migration backup '%s': %s",
            path.string(),
            DbEnv::strerror(close_result));
        return false;
    }
    return true;
}

bool RemoveExactMigrationTarget(
    const fs::path& path,
    const DatabaseFileIdentity& identity,
    int descriptor,
    bool& removed,
    std::string& error)
{
    removed = false;
    if (!MigrationIdentityMatches(
            descriptor,
            path,
            identity)) {
        error = strprintf(
            "Refusing to remove migration backup '%s': its exact created inode cannot be certified.",
            path.string());
        return false;
    }
    if (unlink(path.string().c_str()) != 0) {
        error = strprintf(
            "Failed to remove migration backup '%s': %s",
            path.string(),
            std::strerror(errno));
        return false;
    }
    struct stat retained_status{};
    if (fstat(
            descriptor,
            &retained_status) != 0 ||
        !StatMatchesMigrationIdentity(
            retained_status,
            identity,
            false) ||
        retained_status.st_nlink != 0) {
        error = strprintf(
            "Migration backup pathname '%s' was removed, but the retained created inode was not proven unlinked.",
            path.string());
        return false;
    }
    removed = true;
    const fs::path parent =
        path.parent_path().empty() ?
            fs::path(".") :
            path.parent_path();
    return SynchronizeMigrationDirectory(parent, error);
}
#endif // !WIN32

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
    migrationLogPins.clear();
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

    const bool fCreate = strchr(pszMode, 'c') != NULL;

    CDBEnv& env = *m_database.m_env;
    {
        LOCK(env.cs_db);
        if (!env.Open(GetDataDir()))
            throw std::runtime_error("CDB: Failed to open database environment.");

        const auto cached = env.mapDb.find(strFilename);
        Db* cached_database =
            cached == env.mapDb.end() ? nullptr : cached->second;
        if ((database.m_first_open_requirement !=
                    BerkeleyDatabase::FirstOpenRequirement::NONE ||
                database.m_first_open_identity) &&
            cached_database) {
            const auto use_count =
                env.mapFileUseCount.find(strFilename);
            if (use_count != env.mapFileUseCount.end() &&
                use_count->second != 0) {
                throw std::runtime_error(strprintf(
                    "CDB: Cannot apply the required first-open policy to an in-use database %s",
                    strFilename));
            }
            env.CloseDb(strFilename);
            env.mapDb.erase(strFilename);
            env.mapFileUseCount.erase(strFilename);
            cached_database = nullptr;
        }
        if (cached_database) {
            strFile = strFilename;
            pdb = cached_database;
            ++env.mapFileUseCount[strFile];
            return;
        }

        unsigned int nFlags = DB_THREAD;
        switch (database.m_first_open_requirement) {
        case BerkeleyDatabase::FirstOpenRequirement::CREATE:
            nFlags |= DB_CREATE | DB_EXCL;
            break;
        case BerkeleyDatabase::FirstOpenRequirement::EXISTING:
            break;
        case BerkeleyDatabase::FirstOpenRequirement::NONE:
            if (fCreate)
                nFlags |= DB_CREATE;
            break;
        }

        std::unique_ptr<Db> opened = std::make_unique<Db>(env.dbenv, 0);
        const bool fMockDb = env.IsMock();
        if (fMockDb) {
            DbMpoolFile* mpf = opened->get_mpf();
            ret = mpf->set_flags(DB_MPOOL_NOFILE, 1);
            if (ret != 0)
                throw std::runtime_error(strprintf("CDB: Failed to configure for no temp file backing for database %s", strFilename));
        }

        ret = opened->open(NULL,                    // Txn pointer
            fMockDb ? NULL : strFilename.c_str(),   // Filename
            fMockDb ? strFilename.c_str() : "main", // Logical db name
            DB_BTREE,                               // Database type
            nFlags,                                 // Flags
            0);
        if (ret != 0) {
            throw std::runtime_error(strprintf(
                "CDB: Error %d, can't open database %s",
                ret,
                strFilename));
        }

        if (!fMockDb &&
            !BerkeleyIdentityMatches(
                *opened,
                GetDataDir() / strFilename,
                database.m_first_open_identity)) {
            opened->close(0);
            throw std::runtime_error(strprintf(
                "CDB: Refusing database %s because its file identity changed before first open",
                strFilename));
        }

        pdb = opened.get();
        if ((fCreate ||
                database.m_first_open_requirement ==
                    BerkeleyDatabase::FirstOpenRequirement::CREATE) &&
            !Exists(std::string("version"))) {
            const bool fTmp = fReadOnly;
            fReadOnly = false;
            WriteVersion(CLIENT_VERSION);
            fReadOnly = fTmp;
        }

        strFile = strFilename;
        env.mapDb[strFile] = opened.release();
        ++env.mapFileUseCount[strFile];
        database.m_first_open_requirement =
            BerkeleyDatabase::FirstOpenRequirement::NONE;
        database.m_first_open_identity.reset();
    }
}

BerkeleyDatabase::~BerkeleyDatabase() noexcept
{
#ifndef WIN32
    if (m_migration_backup_descriptor >= 0) {
        close(m_migration_backup_descriptor);
        m_migration_backup_descriptor = -1;
    }
    if (m_migration_source_descriptor >= 0) {
        close(m_migration_source_descriptor);
        m_migration_source_descriptor = -1;
    }
#endif
}

std::unique_ptr<DatabaseBatch> BerkeleyDatabase::MakeBatch(const DatabaseBatchOptions& options)
{
    const char* mode = nullptr;
    switch (options.mode) {
    case DatabaseBatchMode::READ_ONLY:
        mode = "r";
        break;
    case DatabaseBatchMode::READ_WRITE:
        mode = "r+";
        break;
    case DatabaseBatchMode::READ_WRITE_CREATE:
        mode = "cr+";
        break;
    }

    if (!mode) {
        throw std::invalid_argument("Unknown wallet database batch mode");
    }
    return std::unique_ptr<DatabaseBatch>(new CDB(*this, mode, options.flush_on_close));
}

std::unique_ptr<WalletDatabase> MakeBerkeleyDatabase(
    CDBEnv& env,
    std::string filename,
    const DatabaseOptions& options,
    std::optional<DatabaseFileIdentity> first_open_identity)
{
    return std::make_unique<BerkeleyDatabase>(
        env,
        std::move(filename),
        options,
        std::move(first_open_identity));
}

std::unique_ptr<WalletDatabase> MakeDummyWalletDatabase()
{
    return std::make_unique<BerkeleyDatabase>();
}

bool IsBerkeleyDatabase(const fs::path& path)
{
    boost::system::error_code error;
    const uintmax_t size = fs::file_size(path, error);
    if (error) {
        throw std::runtime_error(strprintf("cannot determine file size: %s", error.message()));
    }
    if (size < 4096) {
        return false;
    }

    fs::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("cannot open file");
    }

    std::array<unsigned char, 16> header{};
    file.read(reinterpret_cast<char*>(header.data()), header.size());
    if (file.gcount() != static_cast<std::streamsize>(header.size())) {
        throw std::runtime_error("cannot read file header");
    }

    static constexpr std::array<unsigned char, 4> BIG_ENDIAN_MAGIC{{0x00, 0x05, 0x31, 0x62}};
    static constexpr std::array<unsigned char, 4> LITTLE_ENDIAN_MAGIC{{0x62, 0x31, 0x05, 0x00}};
    return std::equal(BIG_ENDIAN_MAGIC.begin(), BIG_ENDIAN_MAGIC.end(), header.begin() + 12) ||
           std::equal(LITTLE_ENDIAN_MAGIC.begin(), LITTLE_ENDIAN_MAGIC.end(), header.begin() + 12);
}

DatabaseReadStatus CDB::ReadRaw(CDataStream&& key, CDataStream& value)
{
    if (!pdb) {
        return DatabaseReadStatus::FAILED;
    }

    Dbt db_key(key.data(), key.size());
    BerkeleyMallocDbt db_value;
    const int result = pdb->get(activeTxn, &db_key, db_value.Get(), 0);
    CleanseStream(key);

    if (result == DB_NOTFOUND) {
        return DatabaseReadStatus::NOT_FOUND;
    }
    if (result != 0 ||
        (db_value.Size() != 0 && db_value.Data() == nullptr)) {
        return DatabaseReadStatus::FAILED;
    }

    value.SetType(SER_DISK);
    value.clear();
    if (db_value.Size() != 0) {
        value.write(static_cast<const char*>(db_value.Data()), db_value.Size());
    }
    return DatabaseReadStatus::SUCCESS;
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

DatabaseReadStatus CDB::HasRaw(CDataStream&& key)
{
    if (!pdb) {
        return DatabaseReadStatus::FAILED;
    }

    Dbt db_key(key.data(), key.size());
    const int result = pdb->exists(activeTxn, &db_key, 0);
    CleanseStream(key);
    if (result == 0) {
        return DatabaseReadStatus::SUCCESS;
    }
    if (result == DB_NOTFOUND) {
        return DatabaseReadStatus::NOT_FOUND;
    }
    return DatabaseReadStatus::FAILED;
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

MigrationBackupResult BerkeleyDatabase::CreateMigrationBackup(
    const std::string& backup_filename,
    std::string& error)
{
    error.clear();
#ifdef WIN32
    (void)backup_filename;
    error =
        "Secure BDB-to-SQLite migration backup is unavailable on Windows.";
    return MigrationBackupResult::FAILED;
#else
#if !defined(O_CLOEXEC) || !defined(O_NOFOLLOW)
    (void)backup_filename;
    error =
        "Secure BDB-to-SQLite migration backup requires O_CLOEXEC and O_NOFOLLOW.";
    return MigrationBackupResult::FAILED;
#else
    if (!m_env || m_filename.empty() || m_env->IsMock()) {
        error =
            "Cannot create a migration backup for an inert or memory-only BDB wallet.";
        return MigrationBackupResult::FAILED;
    }
    if (m_migration_source_descriptor >= 0 ||
        m_migration_backup_descriptor >= 0 ||
        m_migration_source_identity ||
        m_migration_backup_identity ||
        !m_migration_backup_path.empty()) {
        error =
            "A BDB migration backup identity is already retained by this wallet database.";
        return MigrationBackupResult::FAILED;
    }

    fs::path source_path;
    if (!GetWalletDatabasePath(
            m_filename,
            source_path,
            error)) {
        return MigrationBackupResult::FAILED;
    }
    fs::path target_path;
    if (!GetWalletDatabasePath(
            backup_filename,
            target_path,
            error)) {
        return MigrationBackupResult::FAILED;
    }
    if (backup_filename == m_filename ||
        target_path == source_path) {
        error = strprintf(
            "Refusing BDB migration backup '%s': the backup filename must differ from the source filename.",
            target_path.string());
        return MigrationBackupResult::FAILED;
    }
    const fs::path source_parent =
        source_path.parent_path().empty() ?
            fs::path(".") :
            source_path.parent_path();
    const fs::path target_parent =
        target_path.parent_path().empty() ?
            fs::path(".") :
            target_path.parent_path();
    if (source_parent != target_parent ||
        !OwnerControlledMigrationDirectory(
            source_parent,
            error)) {
        if (error.empty()) {
            error =
                "The BDB migration source and backup must use the same owner-controlled directory.";
        }
        return MigrationBackupResult::FAILED;
    }

    LOCK(m_env->cs_db);
    if (!m_env->Open(GetDataDir())) {
        error = strprintf(
            "Failed to open the production Berkeley environment for migration backup '%s'.",
            target_path.string());
        return MigrationBackupResult::FAILED;
    }

    const auto source_users =
        m_env->mapFileUseCount.find(m_filename);
    if (source_users !=
            m_env->mapFileUseCount.end() &&
        source_users->second != 0) {
        error = strprintf(
            "Cannot create BDB migration backup '%s': active source database batches still exist.",
            target_path.string());
        return MigrationBackupResult::FAILED;
    }
    const auto target_users =
        m_env->mapFileUseCount.find(backup_filename);
    if (target_users !=
            m_env->mapFileUseCount.end() &&
        target_users->second != 0) {
        error = strprintf(
            "Cannot create BDB migration backup '%s': that database name is active in the Berkeley environment.",
            target_path.string());
        return MigrationBackupResult::FAILED;
    }
    if (!m_first_open_identity) {
        error = strprintf(
            "Cannot create BDB migration backup '%s': the source first-open identity was not retained.",
            target_path.string());
        return MigrationBackupResult::FAILED;
    }
    const DatabaseFileIdentity source_identity =
        *m_first_open_identity;
    ScopedMigrationDescriptor source_descriptor(
        open(
            source_path.string().c_str(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (source_descriptor.Get() < 0) {
        error = strprintf(
            "Failed to open BDB migration source '%s' without following links: %s",
            source_path.string(),
            std::strerror(errno));
        return MigrationBackupResult::FAILED;
    }
    if (!PrivateMigrationSourceMatches(
            source_descriptor.Get(),
            source_path,
            source_identity)) {
        error = strprintf(
            "Refusing BDB migration source '%s': it is not the retained effective-user-owned, non-group/other-writable, single-link regular file.",
            source_path.string());
        return MigrationBackupResult::FAILED;
    }

    ScopedMigrationDescriptor target_descriptor(
        open(
            target_path.string().c_str(),
            O_CREAT | O_EXCL | O_RDWR |
                O_CLOEXEC | O_NOFOLLOW,
            S_IRUSR | S_IWUSR));
    if (target_descriptor.Get() < 0) {
        if (errno == EEXIST) {
            error = strprintf(
                "BDB migration backup '%s' already exists.",
                target_path.string());
            return MigrationBackupResult::EXISTS;
        }
        error = strprintf(
            "Failed to exclusively create BDB migration backup '%s': %s",
            target_path.string(),
            std::strerror(errno));
        return MigrationBackupResult::FAILED;
    }

    std::optional<DatabaseFileIdentity> target_identity;
    ScopedMigrationDescriptor target_read_descriptor;
    auto fail_created_target = [&]() {
        bool removed = false;
        std::string cleanup_error;
        const int identity_descriptor =
            target_read_descriptor.Get() >= 0 ?
                target_read_descriptor.Get() :
                target_descriptor.Get();
        bool cleanup_succeeded = false;
        if (target_identity) {
            cleanup_succeeded =
                RemoveExactMigrationTarget(
                    target_path,
                    *target_identity,
                    identity_descriptor,
                    removed,
                    cleanup_error);
        } else {
            cleanup_error =
                "the created target inode identity could not be read";
        }

        if (cleanup_succeeded) {
            return MigrationBackupResult::FAILED;
        }
        if (removed) {
            error = strprintf(
                "%s The failed backup at '%s' was removed, but its parent directory could not be synchronized: %s",
                error,
                target_path.string(),
                cleanup_error);
            return MigrationBackupResult::FAILED;
        }

        m_migration_source_descriptor =
            source_descriptor.Release();
        m_migration_source_identity =
            source_identity;
        m_migration_backup_descriptor =
            target_read_descriptor.Get() >= 0 ?
                target_read_descriptor.Release() :
                target_descriptor.Release();
        m_migration_backup_identity =
            target_identity;
        m_migration_backup_path =
            target_path;
        error = strprintf(
            "%s Safe removal could not be certified; the created backup inode is retained by descriptor and pathname '%s' is unverified: %s",
            error,
            target_path.string(),
            cleanup_error);
        return MigrationBackupResult::FAILED;
    };

    struct stat target_status{};
    if (fstat(
            target_descriptor.Get(),
            &target_status) != 0) {
        error = strprintf(
            "Failed to inspect created BDB migration backup '%s': %s",
            target_path.string(),
            std::strerror(errno));
        return fail_created_target();
    }
    target_identity = DatabaseFileIdentity{
        static_cast<uint64_t>(target_status.st_dev),
        static_cast<uint64_t>(target_status.st_ino)};
    if (!S_ISREG(target_status.st_mode) ||
        target_status.st_nlink != 1) {
        error = strprintf(
            "Refusing created BDB migration backup '%s': it is not a single-link regular file.",
            target_path.string());
        return fail_created_target();
    }
    if (fchmod(
            target_descriptor.Get(),
            S_IRUSR | S_IWUSR) != 0) {
        error = strprintf(
            "Failed to set private permissions on BDB migration backup '%s': %s",
            target_path.string(),
            std::strerror(errno));
        return fail_created_target();
    }
    if (!PrivateMigrationBackupMatches(
            target_descriptor.Get(),
            target_path,
            *target_identity)) {
        error = strprintf(
            "Refusing BDB migration backup '%s': its private file identity changed after creation.",
            target_path.string());
        return fail_created_target();
    }
    if (!CloseAndCheckpointMigrationDatabase(
            *m_env,
            m_filename,
            error)) {
        return fail_created_target();
    }
    if (!PrivateMigrationSourceMatches(
            source_descriptor.Get(),
            source_path,
            source_identity)) {
        error = strprintf(
            "BDB migration source '%s' changed while it was checkpointed.",
            source_path.string());
        return fail_created_target();
    }
    if (!PrivateMigrationBackupMatches(
            target_descriptor.Get(),
            target_path,
            *target_identity)) {
        error = strprintf(
            "BDB migration backup '%s' changed while the source was checkpointed.",
            target_path.string());
        return fail_created_target();
    }
    if (lseek(source_descriptor.Get(), 0, SEEK_SET) != 0) {
        error = strprintf(
            "Failed to rewind BDB migration source '%s': %s",
            source_path.string(),
            std::strerror(errno));
        return fail_created_target();
    }
    if (!CopyMigrationFile(
            source_descriptor.Get(),
            target_descriptor.Get(),
            source_path,
            target_path,
            error)) {
        return fail_created_target();
    }
    if (fsync(target_descriptor.Get()) != 0) {
        error = strprintf(
            "Failed to synchronize BDB migration backup '%s': %s",
            target_path.string(),
            std::strerror(errno));
        return fail_created_target();
    }

    target_read_descriptor.Reset(
        open(
            target_path.string().c_str(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (target_read_descriptor.Get() < 0) {
        error = strprintf(
            "Failed to retain a read descriptor for BDB migration backup '%s': %s",
            target_path.string(),
            std::strerror(errno));
        return fail_created_target();
    }
    if (!PrivateMigrationBackupMatches(
            target_read_descriptor.Get(),
            target_path,
            *target_identity)) {
        error = strprintf(
            "Refusing BDB migration backup '%s': its retained read descriptor does not match the created file.",
            target_path.string());
        return fail_created_target();
    }

    int close_error = 0;
    if (!target_descriptor.Close(close_error)) {
        error = strprintf(
            "Failed to close BDB migration backup '%s' after copying: %s",
            target_path.string(),
            std::strerror(close_error));
        return fail_created_target();
    }
    if (!SynchronizeMigrationDirectory(
            target_path.parent_path(),
            error)) {
        return fail_created_target();
    }

    const int file_id_result =
        m_env->dbenv->fileid_reset(
            backup_filename.c_str(),
            0);
    if (file_id_result != 0) {
        error = strprintf(
            "Failed to assign an independent Berkeley file identity to migration backup '%s': %s",
            target_path.string(),
            DbEnv::strerror(file_id_result));
        return fail_created_target();
    }
    if (fsync(target_read_descriptor.Get()) != 0) {
        error = strprintf(
            "Failed to synchronize the independent Berkeley identity for migration backup '%s': %s",
            target_path.string(),
            std::strerror(errno));
        return fail_created_target();
    }
    if (!PrivateMigrationBackupMatches(
            target_read_descriptor.Get(),
            target_path,
            *target_identity)) {
        error = strprintf(
            "BDB migration backup '%s' changed while assigning its independent Berkeley identity.",
            target_path.string());
        return fail_created_target();
    }
    const int lsn_result =
        m_env->dbenv->lsn_reset(
            backup_filename.c_str(),
            0);
    if (lsn_result != 0) {
        error = strprintf(
            "Failed to reset the Berkeley log sequence number in migration backup '%s': %s",
            target_path.string(),
            DbEnv::strerror(lsn_result));
        return fail_created_target();
    }
    if (fsync(target_read_descriptor.Get()) != 0) {
        error = strprintf(
            "Failed to synchronize the reset Berkeley log sequence number for migration backup '%s': %s",
            target_path.string(),
            std::strerror(errno));
        return fail_created_target();
    }
    if (!PrivateMigrationBackupMatches(
            target_read_descriptor.Get(),
            target_path,
            *target_identity)) {
        error = strprintf(
            "BDB migration backup '%s' changed while resetting its Berkeley log sequence number.",
            target_path.string());
        return fail_created_target();
    }

    int cached_target_close_result = 0;
    const auto cached_target =
        m_env->mapDb.find(backup_filename);
    if (cached_target != m_env->mapDb.end()) {
        Db* const cached_database =
            cached_target->second;
        if (cached_database) {
            cached_target_close_result =
                cached_database->close(0);
            delete cached_database;
        }
        m_env->mapDb.erase(cached_target);
    }
    m_env->mapFileUseCount.erase(backup_filename);
    if (cached_target_close_result != 0) {
        error = strprintf(
            "Failed to close a stale Berkeley handle before verifying migration backup '%s': %s",
            target_path.string(),
            DbEnv::strerror(
                cached_target_close_result));
        return fail_created_target();
    }
    if (!VerifyMigrationBackup(
            *m_env,
            backup_filename,
            target_path,
            error)) {
        return fail_created_target();
    }
    if (!PrivateMigrationSourceMatches(
            source_descriptor.Get(),
            source_path,
            source_identity)) {
        error = strprintf(
            "BDB migration source '%s' changed while its backup was created.",
            source_path.string());
        return fail_created_target();
    }
    if (!PrivateMigrationBackupMatches(
            target_read_descriptor.Get(),
            target_path,
            *target_identity)) {
        error = strprintf(
            "BDB migration backup '%s' changed while it was verified.",
            target_path.string());
        return fail_created_target();
    }

    m_migration_source_descriptor =
        source_descriptor.Release();
    m_migration_source_identity =
        source_identity;
    m_migration_backup_descriptor =
        target_read_descriptor.Release();
    m_migration_backup_identity =
        *target_identity;
    m_migration_backup_path =
        target_path;
    error.clear();
    return MigrationBackupResult::SUCCESS;
#endif
#endif
}

bool BerkeleyDatabase::PrepareForMigrationPublication(
    std::string& error)
{
    error.clear();
#ifdef WIN32
    error =
        "Secure BDB-to-SQLite migration publication is unavailable on Windows.";
    return false;
#else
    if (!m_env ||
        m_filename.empty() ||
        m_migration_source_descriptor < 0 ||
        !m_migration_source_identity ||
        m_migration_backup_descriptor < 0 ||
        !m_migration_backup_identity ||
        m_migration_backup_path.empty()) {
        error =
            "Cannot prepare BDB migration publication without a verified retained backup.";
        return false;
    }

    fs::path source_path;
    if (!GetWalletDatabasePath(
            m_filename,
            source_path,
            error)) {
        return false;
    }
    while (true) {
        {
            LOCK(m_env->cs_db);
            const auto users =
                m_env->mapFileUseCount.find(m_filename);
            if (users ==
                    m_env->mapFileUseCount.end() ||
                users->second == 0) {
                if (!CloseAndCheckpointMigrationDatabase(
                        *m_env,
                        m_filename,
                        error)) {
                    return false;
                }
                if (!PrivateMigrationSourceMatches(
                        m_migration_source_descriptor,
                        source_path,
                        *m_migration_source_identity)) {
                    error = strprintf(
                        "Refusing BDB migration publication: source '%s' no longer matches its retained identity.",
                        source_path.string());
                    return false;
                }
                if (!PrivateMigrationBackupMatches(
                        m_migration_backup_descriptor,
                        m_migration_backup_path,
                        *m_migration_backup_identity)) {
                    error = strprintf(
                        "Refusing BDB migration publication: backup '%s' no longer matches its retained private identity.",
                        m_migration_backup_path.string());
                    return false;
                }
                return true;
            }
        }
        MilliSleep(100);
    }
#endif
}

bool BerkeleyDatabase::MigrationSourceMatchesPath(
    const fs::path& path,
    std::string& error) const
{
    error.clear();
#ifdef WIN32
    (void)path;
    error =
        "Retained BDB migration source identities are unavailable on Windows.";
    return false;
#else
    if (m_migration_source_descriptor < 0 ||
        !m_migration_source_identity) {
        error =
            "No BDB migration source identity is retained.";
        return false;
    }
    if (!PrivateMigrationSourceMatches(
            m_migration_source_descriptor,
            path,
            *m_migration_source_identity)) {
        error = strprintf(
            "BDB migration source path '%s' does not match its retained effective-user-owned, non-group/other-writable, single-link regular-file identity.",
            path.string());
        return false;
    }
    return true;
#endif
}

bool BerkeleyDatabase::MigrationBackupMatchesPath(
    std::string& error) const
{
    error.clear();
#ifdef WIN32
    error =
        "Retained BDB migration backup identities are unavailable on Windows.";
    return false;
#else
    if (m_migration_backup_descriptor < 0 ||
        !m_migration_backup_identity ||
        m_migration_backup_path.empty()) {
        error =
            "No BDB migration backup identity is retained.";
        return false;
    }
    if (!PrivateMigrationBackupMatches(
            m_migration_backup_descriptor,
            m_migration_backup_path,
            *m_migration_backup_identity)) {
        error = strprintf(
            "BDB migration backup path '%s' does not match its retained owner-private single-link regular-file identity.",
            m_migration_backup_path.string());
        return false;
    }
    return true;
#endif
}

bool BerkeleyDatabase::ConfirmMigrationSourceRemoved(
    std::string& error)
{
    error.clear();
#ifdef WIN32
    error =
        "Retained BDB migration source identities are unavailable on Windows.";
    return false;
#else
    if (!m_env ||
        m_filename.empty() ||
        m_migration_source_descriptor < 0 ||
        !m_migration_source_identity) {
        error =
            "No BDB migration source identity is retained.";
        return false;
    }

    struct stat metadata{};
    if (fstat(
            m_migration_source_descriptor,
            &metadata) != 0 ||
        !StatMatchesMigrationIdentity(
            metadata,
            *m_migration_source_identity,
            false) ||
        metadata.st_nlink != 0) {
        error =
            "The retained BDB migration source inode was not proven unlinked.";
        return false;
    }

    LOCK(m_env->cs_db);
    const auto pin =
        m_env->migrationLogPins.find(m_filename);
    if (pin ==
        m_env->migrationLogPins.end()) {
        error =
            "The retained BDB migration source lost its Berkeley log pin.";
        return false;
    }
    m_env->migrationLogPins.erase(pin);
    return true;
#endif
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
            if (mapFileUseCount.empty() &&
                migrationLogPins.empty()) {
                dbenv->log_archive(&listp, DB_ARCH_REMOVE);
                Close();
                if (!fMockDb)
                    boost::filesystem::remove_all(boost::filesystem::path(strPath) / "database");
            }
        }
    }
}
