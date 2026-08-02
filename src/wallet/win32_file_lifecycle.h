// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_WALLET_WIN32_FILE_LIFECYCLE_H
#define FIRO_WALLET_WIN32_FILE_LIFECYCLE_H

#include "config/bitcoin-config.h"

#if defined(WIN32) && defined(USE_SQLITE)

#include "fs.h"
#include "wallet/database.h"

#include <cstddef>
#include <cstdint>
#include <string>

struct sqlite3;

namespace wallet
{
namespace win32
{
/** Access requested from an existing wallet-lifecycle file. */
enum class FileAccess {
    READ_ONLY,
    READ_WRITE,
};

/**
 * Security policy applied in addition to the common local-NTFS, regular-file,
 * single-link, non-reparse, and non-delete-pending checks.
 */
enum class SecurityPolicy {
    /** No owner or DACL restriction; suitable only for non-mutating discovery. */
    DISCOVERY,
    /** Current-user-owned, with no untrusted mutation or security-control ACE. */
    SOURCE_CONTROLLED,
    /** Current-user-owned, with no untrusted read, mutation, delete, or control ACE. */
    PRIVATE,
};

enum class OpenResult {
    OPENED,
    ABSENT,
    FAILED,
};

enum class CreateResult {
    CREATED,
    EXISTS,
    FAILED,
    /**
     * A file was created, but the failed creation could only be made
     * delete-pending (or its exact cleanup could not be certified). Windows
     * cannot prove that namespace cleanup durable across power loss.
     */
    INDETERMINATE,
};

/**
 * Result of comparing a retained identity with a handle or pathname.
 *
 * ABSENT is returned only for a pathname whose absence can be observed now.
 * It does not claim that the absence is durable across power loss.
 */
enum class IdentityState {
    MATCH,
    ABSENT,
    OTHER,
    FAILED,
};

struct FileState {
    DatabaseFileIdentity identity{};
    uint64_t size{0};
    uint32_t link_count{0};
    bool directory{false};
    bool reparse_point{false};
    bool delete_pending{false};
};

struct MoveResult;
struct DeleteResult;
class FileHandleAccess;

/** Movable ownership of one native HANDLE without exposing Windows headers. */
class File final
{
public:
    File() noexcept = default;
    ~File();

    File(File&& other) noexcept;
    File& operator=(File&& other) noexcept;

    File(const File&) = delete;
    File& operator=(const File&) = delete;

    explicit operator bool() const noexcept;
    bool Close(std::string& error);
    void Reset() noexcept;

private:
    File(void* handle, std::string path) noexcept;
    void* Get() const noexcept;

    void* m_handle{nullptr};
    std::string m_path;

    friend OpenResult OpenExistingFile(
        const fs::path&,
        FileAccess,
        SecurityPolicy,
        bool,
        File&,
        DatabaseFileIdentity&,
        std::string&);
    friend CreateResult CreatePrivateFile(
        const fs::path&,
        bool,
        File&,
        DatabaseFileIdentity&,
        std::string&);
    friend bool GetFileState(const File&, FileState&, std::string&);
    friend IdentityState InspectHandleIdentity(
        const File&,
        const DatabaseFileIdentity&,
        std::string&);
    friend bool FlushFile(const File&, std::string&);
    friend bool ReadExact(
        const File&,
        uint64_t,
        void*,
        size_t,
        std::string&);
    friend MoveResult MoveFileNoReplace(
        const fs::path&,
        const File&,
        const DatabaseFileIdentity&,
        const fs::path&,
        std::string&);
    friend MoveResult MoveFileReplace(
        const fs::path&,
        const File&,
        const DatabaseFileIdentity&,
        const fs::path&,
        const File&,
        const DatabaseFileIdentity&,
        SecurityPolicy,
        std::string&);
    friend DeleteResult MarkDeletePendingExact(
        const fs::path&,
        const DatabaseFileIdentity&,
        SecurityPolicy,
        const File*,
        std::string&);
    friend class FileHandleAccess;
};

/**
 * Open and validate an existing regular file without following its final
 * component. A non-claiming open omits delete sharing so the pathname cannot
 * be renamed during a following BDB or SQLite library open. A claiming open
 * requests read/write access, shares read/write/delete, and retains an
 * exclusive one-byte LockFileEx sentinel above SQLite's maximum database
 * offset.
 */
OpenResult OpenExistingFile(
    const fs::path& path,
    FileAccess access,
    SecurityPolicy policy,
    bool claim,
    File& file,
    DatabaseFileIdentity& identity,
    std::string& error);

/**
 * Exclusively create a regular file with a protected DACL containing exactly
 * one current-user full-control ACE, then validate its retained identity.
 */
CreateResult CreatePrivateFile(
    const fs::path& path,
    bool claim,
    File& file,
    DatabaseFileIdentity& identity,
    std::string& error);

/** Fail validation after the next private file is created and identified. */
void InjectPrivateFileValidationFailureForTesting();

/** Clear the private-file validation failure seam. */
void ResetFileLifecycleForTesting();

/**
 * Validate the absolute migration directory and each ancestor without
 * following reparse points. The migration directory must be private and
 * current-user-owned; ancestors must have trusted owners and must not grant
 * untrusted path-replacement or security-control rights.
 */
bool ValidateMigrationDirectory(
    const fs::path& directory,
    std::string& error);

/** Convert the native UTF-16 path to strict UTF-8 for sqlite3_open_v2. */
bool PathToUtf8(
    const fs::path& path,
    std::string& utf8,
    std::string& error);

bool GetFileState(
    const File& file,
    FileState& state,
    std::string& error);

IdentityState InspectHandleIdentity(
    const File& file,
    const DatabaseFileIdentity& expected,
    std::string& error);

IdentityState InspectPathIdentity(
    const fs::path& path,
    const DatabaseFileIdentity& expected,
    std::string& error);

/** Compare SQLite's native main-database HANDLE with a retained identity. */
bool SQLiteHandleIdentityMatches(
    sqlite3* database,
    const DatabaseFileIdentity& expected,
    std::string& error);

bool FlushFile(
    const File& file,
    std::string& error);

bool ReadExact(
    const File& file,
    uint64_t offset,
    void* output,
    size_t size,
    std::string& error);

/** Copy the exact source size and bytes; the caller chooses the flush boundary. */
bool CopyFileContents(
    const File& source,
    const File& destination,
    std::string& error);

/** Return false only for an inspection/read error; byte inequality is not an error. */
bool FileContentsEqual(
    const File& first,
    const File& second,
    bool& equal,
    std::string& error);

enum class MoveDisposition {
    MOVED,
    COLLISION,
    NOT_MOVED,
    INDETERMINATE,
};

/**
 * Reconciled result of a MoveFileExW operation. write_through_confirmed is
 * true only when MoveFileExW itself reported success and post-move identity,
 * security, and final-file flush checks also succeeded.
 */
struct MoveResult {
    MoveDisposition disposition{MoveDisposition::INDETERMINATE};
    IdentityState source_path{IdentityState::FAILED};
    IdentityState destination_path{IdentityState::FAILED};
    IdentityState destination_replaced{IdentityState::ABSENT};
    IdentityState moving_handle{IdentityState::FAILED};
    IdentityState replaced_handle{IdentityState::ABSENT};
    bool replaced_delete_pending{false};
    bool write_through_confirmed{false};
    uint32_t native_error{0};
};

MoveResult MoveFileNoReplace(
    const fs::path& source_path,
    const File& source,
    const DatabaseFileIdentity& source_identity,
    const fs::path& destination_path,
    std::string& error);

MoveResult MoveFileReplace(
    const fs::path& source_path,
    const File& source,
    const DatabaseFileIdentity& source_identity,
    const fs::path& destination_path,
    const File& replaced,
    const DatabaseFileIdentity& replaced_identity,
    SecurityPolicy replaced_policy,
    std::string& error);

enum class DeleteDisposition {
    DELETE_PENDING,
    ABSENT,
    NOT_OWNED,
    INDETERMINATE,
};

/**
 * Exact-identity cleanup result. Windows has no supported ordinary-user
 * directory flush, so namespace_durable is always false.
 */
struct DeleteResult {
    DeleteDisposition disposition{DeleteDisposition::INDETERMINATE};
    IdentityState path{IdentityState::FAILED};
    IdentityState retained_handle{IdentityState::FAILED};
    bool delete_pending{false};
    bool namespace_durable{false};
    uint32_t native_error{0};
};

DeleteResult MarkDeletePendingExact(
    const fs::path& path,
    const DatabaseFileIdentity& expected,
    SecurityPolicy policy,
    const File* retained,
    std::string& error);

} // namespace win32
} // namespace wallet

#endif // defined(WIN32) && defined(USE_SQLITE)

#endif // FIRO_WALLET_WIN32_FILE_LIFECYCLE_H
