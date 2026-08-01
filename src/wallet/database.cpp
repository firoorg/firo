// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "config/bitcoin-config.h"

#include "wallet/database.h"

#include "util.h"
#include "utilstrencodings.h"
#include "wallet/db.h"
#include "wallet/walletdb.h"

#ifdef USE_SQLITE
#include "wallet/sqlite.h"
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <optional>

#include <boost/filesystem/fstream.hpp>

#ifndef WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace
{
struct DatabaseFileInfo {
    bool entry_exists{false};
    bool exists{false};
    std::optional<DatabaseFormat> format;
    std::optional<DatabaseFileIdentity> identity;
};

bool GetWalletPathStatus(const fs::path& path, fs::file_status& status, std::string& error)
{
    try {
        status = fs::symlink_status(path);
        return true;
    } catch (const fs::filesystem_error& filesystem_error) {
        error = strprintf(
            "Failed to inspect wallet database '%s': %s",
            path.string(),
            filesystem_error.what());
        return false;
    }
}

bool GetLegacyWalletDatabasePath(
    const std::string& filename,
    fs::path& path,
    std::string& error)
{
    error.clear();
    if (filename.find_first_of("/\\") != std::string::npos ||
        SanitizeString(filename, SAFE_CHARS_FILENAME) != filename) {
        error = strprintf(
            "Invalid wallet filename. Specify one plain filename inside '%s'.",
            GetDataDir().string());
        return false;
    }

    path = GetDataDir() / filename;
    return true;
}

bool IsSQLiteDatabase(const fs::path& path)
{
    boost::system::error_code error;
    const uintmax_t size = fs::file_size(path, error);
    if (error) {
        throw std::runtime_error(strprintf("cannot determine file size: %s", error.message()));
    }
    if (size < 16) {
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

    static constexpr std::array<unsigned char, 16> SQLITE_MAGIC{{
        'S',
        'Q',
        'L',
        'i',
        't',
        'e',
        ' ',
        'f',
        'o',
        'r',
        'm',
        'a',
        't',
        ' ',
        '3',
        '\0',
    }};
    return std::equal(SQLITE_MAGIC.begin(), SQLITE_MAGIC.end(), header.begin());
}

bool InspectWalletDatabaseFile(
    const fs::path& path,
    DatabaseFileInfo& info,
    bool inspect_format,
    DatabaseStatus& status,
    std::string& error)
{
    fs::file_status path_status;
    if (!GetWalletPathStatus(path, path_status, error)) {
        status = DatabaseStatus::FAILED_BAD_PATH;
        return false;
    }

    info = {};
    info.entry_exists =
        path_status.type() != fs::file_not_found;
    if (!info.entry_exists) {
        return true;
    }

    fs::file_status target_status = path_status;
    boost::system::error_code target_error;
    if (path_status.type() == fs::symlink_file) {
        target_status = fs::status(path, target_error);
        if (target_status.type() == fs::file_not_found) {
            info.exists = false;
            return true;
        }
        if (target_error) {
            status = DatabaseStatus::FAILED_BAD_PATH;
            error = strprintf(
                "Failed to inspect wallet database symlink target '%s': %s",
                path.string(),
                target_error.message());
            return false;
        }
    }
    info.exists =
        target_status.type() != fs::file_not_found;

#ifndef WIN32
    if (path_status.type() == fs::regular_file) {
        struct stat metadata{};
        if (lstat(path.string().c_str(), &metadata) != 0) {
            status = DatabaseStatus::FAILED_BAD_PATH;
            error = strprintf(
                "Failed to retain wallet database identity for '%s': %s",
                path.string(),
                std::strerror(errno));
            return false;
        }
        if (!S_ISREG(metadata.st_mode)) {
            status = DatabaseStatus::FAILED_BAD_PATH;
            error = strprintf(
                "Refusing wallet database '%s': the path changed while its identity was inspected.",
                path.string());
            return false;
        }
        info.identity = DatabaseFileIdentity{
            static_cast<uint64_t>(metadata.st_dev),
            static_cast<uint64_t>(metadata.st_ino)};
    }
#endif

    if (!inspect_format ||
        target_status.type() != fs::regular_file) {
        return true;
    }

    bool is_berkeley = false;
    bool is_sqlite = false;
    try {
        is_berkeley = IsBerkeleyDatabase(path);
    } catch (const std::exception&) {
        // Preserve legacy BDB verification for unreadable or damaged files.
    }
    try {
        is_sqlite = IsSQLiteDatabase(path);
    } catch (const std::exception&) {
        // Preserve legacy BDB verification for unreadable or damaged files.
    }

    if (is_berkeley && is_sqlite) {
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        error = strprintf("Failed to load wallet database '%s': the format is ambiguous.", path.string());
        return false;
    }
    if (is_berkeley) {
        info.format = DatabaseFormat::BERKELEY;
    } else if (is_sqlite) {
        info.format = DatabaseFormat::SQLITE;
    }
    return true;
}

bool OpenBerkeleyEnvironment(std::string& error)
{
    if (bitdb.Open(GetDataDir())) {
        return true;
    }

    const fs::path database_path = GetDataDir() / "database";
    const fs::path backup_path = GetDataDir() / strprintf("database.%d.bak", GetTime());
    try {
        fs::rename(database_path, backup_path);
        LogPrintf("Moved old %s to %s. Retrying.\n", database_path.string(), backup_path.string());
    } catch (const fs::filesystem_error&) {
        // Preserve the existing retry behavior even when the old environment
        // cannot be moved.
    }

    if (bitdb.Open(GetDataDir())) {
        return true;
    }

    error = strprintf("Error initializing wallet database environment '%s'.", GetDataDir().string());
    return false;
}

#ifndef USE_SQLITE
void SetSQLiteUnavailableError(
    const fs::path& path,
    bool exists,
    DatabaseStatus& status,
    std::string& error)
{
    status = DatabaseStatus::FAILED_UNSUPPORTED;
    error = exists ? strprintf(
                         "SQLite wallet database '%s' is not supported by this build because SQLite wallet support is disabled.",
                         path.string()) :
                     strprintf(
                         "Cannot create SQLite wallet database '%s': this build has SQLite wallet support disabled.",
                         path.string());
}
#endif
} // namespace

const char* DatabaseFormatName(DatabaseFormat format)
{
    switch (format) {
    case DatabaseFormat::BERKELEY:
        return "bdb";
    case DatabaseFormat::SQLITE:
        return "sqlite";
    }
    return "unknown";
}

bool GetWalletDatabasePath(const std::string& filename, fs::path& path, std::string& error)
{
    error.clear();
    const fs::path filename_path(filename);
    if (filename.empty() ||
        filename == "." ||
        filename == ".." ||
        filename.find_first_of("/\\") != std::string::npos ||
        filename_path.is_absolute() ||
        !filename_path.parent_path().empty() ||
        filename_path.filename().string() != filename ||
        SanitizeString(filename, SAFE_CHARS_FILENAME) != filename) {
        error = strprintf(
            "Invalid wallet filename. Specify one plain filename inside '%s'.",
            GetDataDir().string());
        return false;
    }

    path = GetDataDir() / filename_path;
    return true;
}

bool ValidateWalletMigrationDirectory(
    const fs::path& directory,
    std::string& error)
{
    error.clear();
#ifdef WIN32
    (void)directory;
    error =
        "Secure wallet migration directory validation is unavailable on Windows.";
    return false;
#else
    if (!directory.is_absolute()) {
        error = strprintf(
            "Refusing migration directory '%s': an absolute path is required.",
            directory.string());
        return false;
    }

    const uid_t effective_user = geteuid();
    fs::path current = directory;
    bool migration_directory = true;
    while (true) {
        struct stat current_status{};
        if (lstat(
                current.string().c_str(),
                &current_status) != 0 ||
            !S_ISDIR(current_status.st_mode)) {
            error = strprintf(
                "Refusing migration directory '%s': '%s' is not a non-symlink directory.",
                directory.string(),
                current.string());
            return false;
        }
        if (migration_directory &&
            (current_status.st_uid != effective_user ||
                (current_status.st_mode &
                    (S_IWGRP | S_IWOTH)) != 0)) {
            error = strprintf(
                "Refusing migration directory '%s': it must be effective-user-owned without group or other write access.",
                directory.string());
            return false;
        }

        const fs::path parent = current.parent_path();
        if (parent.empty() || parent == current) {
            return true;
        }

        struct stat parent_status{};
        if (lstat(
                parent.string().c_str(),
                &parent_status) != 0 ||
            !S_ISDIR(parent_status.st_mode)) {
            error = strprintf(
                "Refusing migration directory '%s': ancestor '%s' is not a non-symlink directory.",
                directory.string(),
                parent.string());
            return false;
        }
        if (parent_status.st_uid != effective_user &&
            parent_status.st_uid != 0) {
            error = strprintf(
                "Refusing migration directory '%s': ancestor '%s' is controlled by an untrusted user.",
                directory.string(),
                parent.string());
            return false;
        }
        if ((parent_status.st_mode &
                (S_IWGRP | S_IWOTH)) != 0 &&
            ((parent_status.st_mode & S_ISVTX) == 0 ||
                (current_status.st_uid != effective_user &&
                    current_status.st_uid != 0))) {
            error = strprintf(
                "Refusing migration directory '%s': ancestor '%s' is writable by group or other without trusted sticky-directory protection.",
                directory.string(),
                parent.string());
            return false;
        }

        current = parent;
        migration_directory = false;
    }
#endif
}

bool ReadWalletDatabaseFormat(
    const std::string& filename,
    std::optional<DatabaseFormat>& format,
    std::string& error)
{
    format.reset();
    fs::path path;
    if (!GetWalletDatabasePath(filename, path, error)) {
        return false;
    }

    DatabaseFileInfo info;
    DatabaseStatus status;
    if (!InspectWalletDatabaseFile(
            path,
            info,
            true,
            status,
            error)) {
        return false;
    }
    format = info.format;
    return true;
}

std::unique_ptr<WalletDatabase> MakeWalletDatabase(
    const std::string& filename,
    const DatabaseOptions& options,
    DatabaseStatus& status,
    std::string& error)
{
    status = DatabaseStatus::FAILED_LOAD;
    error.clear();

    if ((options.require_existing && options.require_create) ||
        (options.logical_wallet_create && !options.require_create) ||
        (options.sqlite_migration_candidate &&
            (!options.logical_wallet_create ||
                !options.require_create ||
                options.require_format !=
                    DatabaseFormat::SQLITE)) ||
        (options.salvage &&
            (!options.verify || !options.recover))) {
        status = DatabaseStatus::FAILED_INVALID_OPTIONS;
        error = "Invalid wallet database options.";
        return nullptr;
    }

    fs::path path;
    if (!GetLegacyWalletDatabasePath(
            filename,
            path,
            error)) {
        status = DatabaseStatus::FAILED_BAD_PATH;
        return nullptr;
    }
    if (options.require_format ==
        DatabaseFormat::SQLITE) {
        fs::path sqlite_path;
        if (!GetWalletDatabasePath(
                filename,
                sqlite_path,
                error)) {
            status = DatabaseStatus::FAILED_BAD_PATH;
            return nullptr;
        }
    }

    DatabaseFileInfo file_info;
    if (!InspectWalletDatabaseFile(path, file_info, !options.require_create, status, error)) {
        return nullptr;
    }

    if (file_info.entry_exists &&
        options.require_create) {
        status = DatabaseStatus::FAILED_ALREADY_EXISTS;
        error = strprintf("Failed to create wallet database '%s': the path already exists.", path.string());
        return nullptr;
    }

    std::optional<DatabaseFormat> format = file_info.format;
    if (file_info.exists) {
        if (!format) {
            format = DatabaseFormat::BERKELEY;
        }
    } else if (options.require_existing) {
        status = DatabaseStatus::FAILED_NOT_FOUND;
        error = strprintf("Failed to load wallet database '%s': the path does not exist.", path.string());
        return nullptr;
    }

    if (format && options.require_format && *format != *options.require_format) {
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        error = strprintf(
            "Failed to load wallet database '%s': found %s, but a different format was required.",
            path.string(),
            DatabaseFormatName(*format));
        return nullptr;
    }

    if (!format) {
        if (options.require_format) {
            format = options.require_format;
        } else {
#if defined(USE_SQLITE) && !defined(WIN32)
            format = DatabaseFormat::SQLITE;
#else
            format = DatabaseFormat::BERKELEY;
#endif
        }
    }

    if (*format == DatabaseFormat::SQLITE) {
        if (!GetWalletDatabasePath(
                filename,
                path,
                error)) {
            status = DatabaseStatus::FAILED_BAD_PATH;
            return nullptr;
        }
#ifdef USE_SQLITE
        return MakeSQLiteDatabase(filename, options, status, error);
#else
        SetSQLiteUnavailableError(path, file_info.exists, status, error);
        return nullptr;
#endif
    }

    if (!OpenBerkeleyEnvironment(error)) {
        status = DatabaseStatus::FAILED_LOAD;
        return nullptr;
    }

    DatabaseFileInfo opened_file_info;
    if (!InspectWalletDatabaseFile(path, opened_file_info, !options.require_create, status, error)) {
        return nullptr;
    }
    if (!opened_file_info.exists && file_info.exists) {
        status = DatabaseStatus::FAILED_NOT_FOUND;
        error = strprintf(
            "Failed to load wallet database '%s': the path disappeared while opening the Berkeley DB environment.",
            path.string());
        return nullptr;
    }
    if (opened_file_info.entry_exists &&
        options.require_create) {
        status = DatabaseStatus::FAILED_ALREADY_EXISTS;
        error = strprintf(
            "Failed to create wallet database '%s': the path appeared while opening the Berkeley DB environment.",
            path.string());
        return nullptr;
    }
    if (opened_file_info.exists &&
        opened_file_info.format &&
        options.require_format &&
        *opened_file_info.format != *options.require_format) {
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        error = strprintf(
            "Failed to load wallet database '%s': found %s after opening the Berkeley DB environment, but a different format was required.",
            path.string(),
            DatabaseFormatName(*opened_file_info.format));
        return nullptr;
    }
    if (opened_file_info.format == DatabaseFormat::SQLITE) {
#ifndef USE_SQLITE
        SetSQLiteUnavailableError(path, true, status, error);
#else
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        error = strprintf(
            "Failed to load wallet database '%s': its format changed from Berkeley DB to SQLite while opening.",
            path.string());
#endif
        return nullptr;
    }
    DatabaseStatus success_status = DatabaseStatus::SUCCESS;

    if (options.salvage) {
        if (!CWalletDB::Recover(bitdb, filename, true)) {
            status = DatabaseStatus::FAILED_VERIFY;
            error = strprintf("Failed to salvage Berkeley DB wallet '%s'.", path.string());
            return nullptr;
        }
        success_status = DatabaseStatus::SUCCESS_SALVAGED;
    }

    if (options.verify && (opened_file_info.exists || options.salvage)) {
        using RecoveryFunction =
            bool (*)(CDBEnv&, const std::string&);
        const RecoveryFunction recoveryFunction =
            options.recover ?
                static_cast<RecoveryFunction>(
                    &CWalletDB::Recover) :
                nullptr;
        const CDBEnv::VerifyResult result =
            bitdb.Verify(
                filename,
                recoveryFunction);
        if (result == CDBEnv::RECOVER_FAIL) {
            status = DatabaseStatus::FAILED_VERIFY;
            error = strprintf("Berkeley DB wallet '%s' is corrupt and recovery failed.", path.string());
            return nullptr;
        }
        if (result == CDBEnv::RECOVER_OK) {
            success_status = DatabaseStatus::SUCCESS_RECOVERED;
        }
    }

    std::optional<DatabaseFileIdentity> first_open_identity;
    if (opened_file_info.exists || options.salvage) {
        DatabaseFileInfo final_file_info;
        if (!InspectWalletDatabaseFile(
                path,
                final_file_info,
                true,
                status,
                error)) {
            return nullptr;
        }
        if (!final_file_info.exists) {
            status = DatabaseStatus::FAILED_NOT_FOUND;
            error = strprintf(
                "Failed to load Berkeley DB wallet '%s': the path disappeared before first open.",
                path.string());
            return nullptr;
        }
        if (final_file_info.format ==
            DatabaseFormat::SQLITE) {
            status = DatabaseStatus::FAILED_BAD_FORMAT;
            error = strprintf(
                "Failed to load Berkeley DB wallet '%s': its format changed before first open.",
                path.string());
            return nullptr;
        }
        first_open_identity =
            final_file_info.identity;
    }

    std::unique_ptr<WalletDatabase> database =
        MakeBerkeleyDatabase(
            bitdb,
            filename,
            options,
            std::move(first_open_identity));
    status = success_status;
    return database;
}
