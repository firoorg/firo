// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "config/bitcoin-config.h"

#include "wallet/database.h"

#include "util.h"
#include "utilstrencodings.h"
#include "wallet/db.h"
#include "wallet/walletdb.h"

#include <algorithm>
#include <array>
#include <optional>

#include <boost/filesystem/fstream.hpp>

namespace
{
struct DatabaseFileInfo {
    bool exists{false};
    std::optional<DatabaseFormat> format;
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
    info.exists = path_status.type() != fs::file_not_found;
    if (!info.exists) {
        return true;
    }

    if (path_status.type() != fs::regular_file) {
        status = DatabaseStatus::FAILED_BAD_PATH;
        error = strprintf(
            "Refusing wallet database '%s': the path must be a regular file and must not be a symlink.",
            path.string());
        return false;
    }

    if (!inspect_format) {
        return true;
    }

    bool is_berkeley;
    bool is_sqlite;
    try {
        is_berkeley = IsBerkeleyDatabase(path);
        is_sqlite = IsSQLiteDatabase(path);
    } catch (const std::exception& inspection_error) {
        status = DatabaseStatus::FAILED_LOAD;
        error = strprintf(
            "Failed to inspect wallet database format '%s': %s",
            path.string(),
            inspection_error.what());
        return false;
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

const char* DatabaseFormatName(DatabaseFormat format)
{
    switch (format) {
    case DatabaseFormat::BERKELEY:
        return "Berkeley DB";
    case DatabaseFormat::SQLITE:
        return "SQLite";
    }
    return "unknown";
}

void SetSQLiteUnavailableError(
    const fs::path& path,
    bool exists,
    DatabaseStatus& status,
    std::string& error)
{
    status = DatabaseStatus::FAILED_UNSUPPORTED;
#ifdef USE_SQLITE
    error = exists ? strprintf(
                         "SQLite wallet database '%s' is recognized, but SQLite wallet storage is not implemented yet.",
                         path.string()) :
                     strprintf(
                         "Cannot create SQLite wallet database '%s': SQLite wallet storage is not implemented yet.",
                         path.string());
#else
    error = exists ? strprintf(
                         "SQLite wallet database '%s' is not supported by this build; SQLite wallet storage is not implemented in this version.",
                         path.string()) :
                     strprintf(
                         "Cannot create SQLite wallet database '%s': this build has SQLite wallet support disabled, and SQLite wallet storage is not implemented in this version.",
                         path.string());
#endif
}
} // namespace

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

bool WalletDatabasePathExists(const fs::path& path, bool& exists, std::string& error)
{
    exists = false;
    error.clear();
    fs::file_status status;
    if (!GetWalletPathStatus(path, status, error)) {
        return false;
    }
    exists = status.type() != fs::file_not_found;
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
        (options.salvage && !options.verify)) {
        status = DatabaseStatus::FAILED_INVALID_OPTIONS;
        error = "Invalid wallet database options.";
        return nullptr;
    }

    fs::path path;
    if (!GetWalletDatabasePath(filename, path, error)) {
        status = DatabaseStatus::FAILED_BAD_PATH;
        return nullptr;
    }

    DatabaseFileInfo file_info;
    if (!InspectWalletDatabaseFile(path, file_info, !options.require_create, status, error)) {
        return nullptr;
    }

    if (file_info.exists && options.require_create) {
        status = DatabaseStatus::FAILED_ALREADY_EXISTS;
        error = strprintf("Failed to create wallet database '%s': the path already exists.", path.string());
        return nullptr;
    }

    std::optional<DatabaseFormat> format = file_info.format;
    if (file_info.exists) {
        if (!format && options.salvage) {
            // Explicit salvage is the last-resort path for a BDB file whose
            // header was damaged. Normal loading never treats unknown data as
            // Berkeley DB.
            format = DatabaseFormat::BERKELEY;
        } else if (!format) {
            status = DatabaseStatus::FAILED_BAD_FORMAT;
            error = strprintf(
                "Failed to load wallet database '%s': data is not in a recognized wallet format.",
                path.string());
            return nullptr;
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
        format = options.require_format.value_or(DatabaseFormat::BERKELEY);
    }

    if (*format == DatabaseFormat::SQLITE) {
        SetSQLiteUnavailableError(path, file_info.exists, status, error);
        return nullptr;
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
    if (opened_file_info.exists && options.require_create) {
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
        SetSQLiteUnavailableError(path, true, status, error);
        return nullptr;
    }
    if (opened_file_info.exists &&
        !opened_file_info.format &&
        !options.salvage) {
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        error = strprintf(
            "Failed to load wallet database '%s': data restored while opening the Berkeley DB environment is not in a recognized wallet format.",
            path.string());
        return nullptr;
    }

    std::unique_ptr<WalletDatabase> database = MakeBerkeleyDatabase(bitdb, filename);
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
        const CDBEnv::VerifyResult result = bitdb.Verify(filename, CWalletDB::Recover);
        if (result == CDBEnv::RECOVER_FAIL) {
            status = DatabaseStatus::FAILED_VERIFY;
            error = strprintf("Berkeley DB wallet '%s' is corrupt and recovery failed.", path.string());
            return nullptr;
        }
        if (result == CDBEnv::RECOVER_OK) {
            success_status = DatabaseStatus::SUCCESS_RECOVERED;
        }
    }

    status = success_status;
    return database;
}
