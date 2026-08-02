// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "config/bitcoin-config.h"

#if !defined(WIN32) || !defined(USE_SQLITE)
#error "win32_file_lifecycle.cpp requires WIN32 and USE_SQLITE"
#endif

#include "wallet/win32_file_lifecycle.h"

#include <sqlite3.h>

#include <aclapi.h>
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cwchar>
#include <cwctype>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace wallet
{
namespace win32
{
class FileHandleAccess final
{
public:
    static void* Get(
        const File& file) noexcept
    {
        return file.Get();
    }

    static const std::string& Path(
        const File& file) noexcept
    {
        return file.m_path;
    }
};

namespace
{
constexpr uint64_t CLAIM_OFFSET = UINT64_C(0x7fffffffffffffff);
constexpr size_t COPY_BUFFER_SIZE = 64 * 1024;
std::atomic<bool> g_fail_private_file_validation_once{false};

bool ConsumePrivateFileValidationFailure()
{
    return g_fail_private_file_validation_once.exchange(false);
}

enum class AclPolicy {
    NONE,
    SOURCE_CONTROLLED,
    PRIVATE,
    ANCESTOR,
    CREATED_PRIVATE,
};

class ScopedHandle final
{
public:
    ScopedHandle() noexcept = default;
    explicit ScopedHandle(HANDLE handle) noexcept
        : m_handle(handle)
    {
    }

    ~ScopedHandle()
    {
        Reset();
    }

    ScopedHandle(ScopedHandle&& other) noexcept
        : m_handle(other.Release())
    {
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept
    {
        if (this != &other) {
            Reset(other.Release());
        }
        return *this;
    }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    explicit operator bool() const noexcept
    {
        return m_handle &&
               m_handle != INVALID_HANDLE_VALUE;
    }

    HANDLE Get() const noexcept
    {
        return m_handle;
    }

    HANDLE Release() noexcept
    {
        const HANDLE handle = m_handle;
        m_handle = nullptr;
        return handle;
    }

    void Reset(HANDLE handle = nullptr) noexcept
    {
        if (*this) {
            CloseHandle(m_handle);
        }
        m_handle = handle;
    }

private:
    HANDLE m_handle{nullptr};
};

class ScopedLocalMemory final
{
public:
    ScopedLocalMemory() noexcept = default;
    ~ScopedLocalMemory()
    {
        if (m_memory) {
            LocalFree(m_memory);
        }
    }

    ScopedLocalMemory(const ScopedLocalMemory&) = delete;
    ScopedLocalMemory& operator=(const ScopedLocalMemory&) = delete;

    void** Address() noexcept
    {
        return &m_memory;
    }

    void* Get() const noexcept
    {
        return m_memory;
    }

private:
    void* m_memory{nullptr};
};

class CleansedBuffer final
{
public:
    explicit CleansedBuffer(size_t size)
        : m_bytes(size)
    {
    }

    ~CleansedBuffer()
    {
        if (!m_bytes.empty()) {
            SecureZeroMemory(
                m_bytes.data(),
                m_bytes.size());
        }
    }

    unsigned char* Data() noexcept
    {
        return m_bytes.data();
    }

    const unsigned char* Data() const noexcept
    {
        return m_bytes.data();
    }

    size_t Size() const noexcept
    {
        return m_bytes.size();
    }

private:
    std::vector<unsigned char> m_bytes;
};

HANDLE NativeHandle(const File& file) noexcept
{
    return reinterpret_cast<HANDLE>(
        FileHandleAccess::Get(file));
}

bool IsValidHandle(HANDLE handle) noexcept
{
    return handle &&
           handle != INVALID_HANDLE_VALUE;
}

bool SameIdentity(
    const DatabaseFileIdentity& first,
    const DatabaseFileIdentity& second) noexcept
{
    return first.device == second.device &&
           first.inode == second.inode;
}

bool IsAbsentError(DWORD error) noexcept
{
    return error == ERROR_FILE_NOT_FOUND ||
           error == ERROR_PATH_NOT_FOUND;
}

void TrimWindowsMessage(std::wstring& message)
{
    while (!message.empty() &&
           (message.back() == L'\r' ||
               message.back() == L'\n' ||
               message.back() == L' ' ||
               message.back() == L'\t' ||
               message.back() == L'.')) {
        message.pop_back();
    }
}

bool WideToUtf8(
    const std::wstring& input,
    std::string& output,
    DWORD& conversion_error)
{
    output.clear();
    conversion_error = ERROR_SUCCESS;
    if (input.empty()) {
        return true;
    }
    if (input.size() >
        static_cast<size_t>(
            std::numeric_limits<int>::max())) {
        conversion_error = ERROR_BUFFER_OVERFLOW;
        return false;
    }

    const int input_size =
        static_cast<int>(input.size());
    const int required = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        input.data(),
        input_size,
        nullptr,
        0,
        nullptr,
        nullptr);
    if (required <= 0) {
        conversion_error = GetLastError();
        return false;
    }
    output.resize(static_cast<size_t>(required));
    if (WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            input.data(),
            input_size,
            output.data(),
            required,
            nullptr,
            nullptr) != required) {
        conversion_error = GetLastError();
        output.clear();
        return false;
    }
    return true;
}

std::string Utf8ForError(
    const std::wstring& input)
{
    std::string output;
    DWORD conversion_error = ERROR_SUCCESS;
    if (WideToUtf8(
            input,
            output,
            conversion_error)) {
        return output;
    }
    return "<unrepresentable wallet path>";
}

std::string WindowsMessage(DWORD error)
{
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<wchar_t*>(&buffer),
        0,
        nullptr);
    std::wstring wide;
    if (length != 0 && buffer) {
        wide.assign(buffer, length);
    }
    if (buffer) {
        LocalFree(buffer);
    }
    TrimWindowsMessage(wide);

    std::string message;
    DWORD conversion_error = ERROR_SUCCESS;
    if (!wide.empty() &&
        WideToUtf8(
            wide,
            message,
            conversion_error)) {
        return message;
    }
    return "unknown Windows error";
}

std::string WindowsError(
    const char* operation,
    const std::wstring& path,
    DWORD error)
{
    return std::string(operation) +
           " '" + Utf8ForError(path) +
           "': " + WindowsMessage(error) +
           " (Windows error " +
           std::to_string(error) + ")";
}

std::string HandleWindowsError(
    const char* operation,
    const std::string& context,
    DWORD error)
{
    const std::string target =
        context.empty() ?
            "wallet lifecycle handle" :
            "'" + context + "'";
    return std::string(operation) +
           " " + target + ": " +
           WindowsMessage(error) +
           " (Windows error " +
           std::to_string(error) + ")";
}

bool NativePath(
    const fs::path& path,
    std::wstring& native,
    std::string& error)
{
    native.clear();
    try {
        native = path.wstring();
    } catch (const std::exception& exception) {
        error =
            std::string("Failed to convert wallet path to UTF-16: ") +
            exception.what();
        return false;
    }
    if (native.empty()) {
        error = "Refusing an empty wallet lifecycle path.";
        return false;
    }
    if (native.find(L'\0') != std::wstring::npos) {
        error = "Refusing a wallet lifecycle path containing an embedded NUL.";
        return false;
    }
    return true;
}

bool IsSeparator(wchar_t character) noexcept
{
    return character == L'\\' ||
           character == L'/';
}

bool IsDriveAbsolute(
    const std::wstring& path) noexcept
{
    return path.size() >= 3 &&
           std::iswalpha(path[0]) != 0 &&
           path[1] == L':' &&
           IsSeparator(path[2]);
}

bool NormalizePath(
    const fs::path& path,
    std::wstring& full,
    std::string& error)
{
    std::wstring native;
    if (!NativePath(path, native, error)) {
        return false;
    }

    const DWORD required = GetFullPathNameW(
        native.c_str(),
        0,
        nullptr,
        nullptr);
    if (required == 0) {
        const DWORD native_error = GetLastError();
        error = WindowsError(
            "Failed to resolve wallet lifecycle path",
            native,
            native_error);
        return false;
    }
    std::vector<wchar_t> buffer(
        static_cast<size_t>(required) + 1);
    const DWORD length = GetFullPathNameW(
        native.c_str(),
        static_cast<DWORD>(buffer.size()),
        buffer.data(),
        nullptr);
    if (length == 0 ||
        length >= buffer.size()) {
        const DWORD native_error =
            length == 0 ?
                GetLastError() :
                ERROR_INSUFFICIENT_BUFFER;
        error = WindowsError(
            "Failed to resolve wallet lifecycle path",
            native,
            native_error);
        return false;
    }
    full.assign(buffer.data(), length);
    std::replace(
        full.begin(),
        full.end(),
        L'/',
        L'\\');

    if (!IsDriveAbsolute(full)) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(full) +
            "': a local drive-absolute path is required.";
        return false;
    }
    if (full.find(L':', 2) != std::wstring::npos) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(full) +
            "': alternate data streams are not allowed.";
        return false;
    }
    return true;
}

std::wstring Win32ExtendedPath(
    const std::wstring& full)
{
    return L"\\\\?\\" + full;
}

std::wstring ParentPath(
    const std::wstring& full)
{
    const size_t separator =
        full.find_last_of(L'\\');
    if (separator == std::wstring::npos ||
        separator <= 2) {
        return full.substr(0, 3);
    }
    return full.substr(0, separator);
}

bool GetCurrentUserSid(
    std::vector<unsigned char>& sid,
    std::string& error)
{
    ScopedHandle token;
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &raw_token)) {
        const DWORD native_error = GetLastError();
        error = HandleWindowsError(
            "Failed to open the process token for wallet ACL validation",
            {},
            native_error);
        return false;
    }
    token.Reset(raw_token);

    DWORD required = 0;
    GetTokenInformation(
        token.Get(),
        TokenUser,
        nullptr,
        0,
        &required);
    const DWORD size_error = GetLastError();
    if (required == 0 ||
        size_error != ERROR_INSUFFICIENT_BUFFER) {
        error = HandleWindowsError(
            "Failed to size the current-user token information",
            {},
            size_error);
        return false;
    }

    std::vector<unsigned char> information(required);
    if (!GetTokenInformation(
            token.Get(),
            TokenUser,
            information.data(),
            required,
            &required)) {
        const DWORD native_error = GetLastError();
        error = HandleWindowsError(
            "Failed to read the current-user token information",
            {},
            native_error);
        return false;
    }
    const auto* token_user =
        reinterpret_cast<const TOKEN_USER*>(
            information.data());
    if (!token_user->User.Sid ||
        !IsValidSid(token_user->User.Sid)) {
        error =
            "Failed to read a valid current-user SID for wallet ACL validation.";
        return false;
    }
    const DWORD sid_length =
        GetLengthSid(token_user->User.Sid);
    sid.resize(sid_length);
    if (!CopySid(
            sid_length,
            sid.data(),
            token_user->User.Sid)) {
        const DWORD native_error = GetLastError();
        error = HandleWindowsError(
            "Failed to retain the current-user SID for wallet ACL validation",
            {},
            native_error);
        return false;
    }
    return true;
}

bool IsCurrentUserSid(
    PSID candidate,
    const std::vector<unsigned char>& current_user) noexcept
{
    return candidate &&
           IsValidSid(candidate) &&
           !current_user.empty() &&
           EqualSid(
               candidate,
               const_cast<unsigned char*>(
                   current_user.data())) != FALSE;
}

bool IsTrustedInstallerSid(
    PSID candidate) noexcept
{
    if (!candidate ||
        !IsValidSid(candidate)) {
        return false;
    }
    static constexpr std::array<unsigned char, 6>
        NT_AUTHORITY{{0, 0, 0, 0, 0, 5}};
    static constexpr std::array<DWORD, 6>
        TRUSTED_INSTALLER_SUBAUTHORITIES{{
            80,
            956008885,
            3418522649,
            1831038044,
            1853292631,
            2271478464,
        }};
    const SID_IDENTIFIER_AUTHORITY* const authority =
        GetSidIdentifierAuthority(candidate);
    const unsigned char* const count =
        GetSidSubAuthorityCount(candidate);
    if (!authority ||
        !count ||
        !std::equal(
            NT_AUTHORITY.begin(),
            NT_AUTHORITY.end(),
            authority->Value) ||
        *count !=
            static_cast<unsigned char>(
                TRUSTED_INSTALLER_SUBAUTHORITIES.size())) {
        return false;
    }
    for (size_t index = 0;
        index <
        TRUSTED_INSTALLER_SUBAUTHORITIES.size();
        ++index) {
        const DWORD* const subauthority =
            GetSidSubAuthority(
                candidate,
                static_cast<DWORD>(index));
        if (!subauthority ||
            *subauthority !=
                TRUSTED_INSTALLER_SUBAUTHORITIES[index]) {
            return false;
        }
    }
    return true;
}

bool IsTrustedSid(
    PSID candidate,
    const std::vector<unsigned char>& current_user) noexcept
{
    return IsCurrentUserSid(
               candidate,
               current_user) ||
           (candidate &&
               IsValidSid(candidate) &&
               (IsWellKnownSid(
                    candidate,
                    WinLocalSystemSid) != FALSE ||
                   IsWellKnownSid(
                       candidate,
                       WinBuiltinAdministratorsSid) != FALSE ||
                   IsTrustedInstallerSid(candidate)));
}

bool IsSafeCreatorOwnerSid(
    PSID candidate) noexcept
{
    return candidate &&
           IsValidSid(candidate) &&
           (IsWellKnownSid(
                candidate,
                WinCreatorOwnerSid) != FALSE ||
               IsWellKnownSid(
                   candidate,
                   WinCreatorOwnerRightsSid) != FALSE);
}

bool IsAllowAceType(BYTE type) noexcept
{
    return type == ACCESS_ALLOWED_ACE_TYPE ||
           type == ACCESS_ALLOWED_COMPOUND_ACE_TYPE ||
           type == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
           type == ACCESS_ALLOWED_CALLBACK_ACE_TYPE ||
           type == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE;
}

ACCESS_MASK RelevantMask(AclPolicy policy) noexcept
{
    constexpr ACCESS_MASK CONTROL_RIGHTS =
        DELETE |
        WRITE_DAC |
        WRITE_OWNER;
    constexpr ACCESS_MASK MUTATION_RIGHTS =
        FILE_WRITE_DATA |
        FILE_APPEND_DATA |
        FILE_WRITE_EA |
        FILE_WRITE_ATTRIBUTES |
        FILE_DELETE_CHILD |
        CONTROL_RIGHTS;
    constexpr ACCESS_MASK READ_RIGHTS =
        FILE_READ_DATA |
        FILE_READ_EA |
        FILE_READ_ATTRIBUTES |
        FILE_EXECUTE |
        READ_CONTROL;

    switch (policy) {
    case AclPolicy::NONE:
        return 0;
    case AclPolicy::SOURCE_CONTROLLED:
        return MUTATION_RIGHTS;
    case AclPolicy::PRIVATE:
    case AclPolicy::CREATED_PRIVATE:
        return MUTATION_RIGHTS |
               READ_RIGHTS;
    case AclPolicy::ANCESTOR:
        return FILE_DELETE_CHILD |
               CONTROL_RIGHTS;
    }
    return std::numeric_limits<ACCESS_MASK>::max();
}

bool ValidateHandleAcl(
    HANDLE handle,
    AclPolicy policy,
    const std::wstring& path,
    std::string& error)
{
    if (policy == AclPolicy::NONE) {
        return true;
    }

    std::vector<unsigned char> current_user;
    if (!GetCurrentUserSid(
            current_user,
            error)) {
        return false;
    }

    PSID owner = nullptr;
    PACL dacl = nullptr;
    ScopedLocalMemory descriptor;
    const DWORD security_error = GetSecurityInfo(
        handle,
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION,
        &owner,
        nullptr,
        &dacl,
        nullptr,
        reinterpret_cast<PSECURITY_DESCRIPTOR*>(
            descriptor.Address()));
    if (security_error != ERROR_SUCCESS) {
        error = WindowsError(
            "Failed to inspect wallet lifecycle security",
            path,
            security_error);
        return false;
    }
    if (!descriptor.Get() ||
        !owner ||
        !IsValidSid(owner)) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(path) +
            "': its owner SID is unavailable or invalid.";
        return false;
    }

    const bool owner_valid =
        policy == AclPolicy::ANCESTOR ?
            IsTrustedSid(owner, current_user) :
            IsCurrentUserSid(owner, current_user);
    if (!owner_valid) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(path) +
            "': its owner is not trusted for this operation.";
        return false;
    }

    WINBOOL dacl_present = FALSE;
    WINBOOL dacl_defaulted = FALSE;
    PACL checked_dacl = nullptr;
    if (!GetSecurityDescriptorDacl(
            reinterpret_cast<PSECURITY_DESCRIPTOR>(
                descriptor.Get()),
            &dacl_present,
            &checked_dacl,
            &dacl_defaulted) ||
        !dacl_present ||
        !checked_dacl ||
        checked_dacl != dacl ||
        !IsValidAcl(checked_dacl)) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(path) +
            "': a valid non-null DACL is required.";
        return false;
    }

    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(
            reinterpret_cast<PSECURITY_DESCRIPTOR>(
                descriptor.Get()),
            &control,
            &revision)) {
        const DWORD native_error = GetLastError();
        error = WindowsError(
            "Failed to inspect wallet lifecycle DACL control",
            path,
            native_error);
        return false;
    }
    if (policy == AclPolicy::CREATED_PRIVATE &&
        (control & SE_DACL_PROTECTED) == 0) {
        error =
            "Refusing newly created wallet lifecycle path '" +
            Utf8ForError(path) +
            "': its DACL is not protected.";
        return false;
    }

    GENERIC_MAPPING mapping{
        FILE_GENERIC_READ,
        FILE_GENERIC_WRITE,
        FILE_GENERIC_EXECUTE,
        FILE_ALL_ACCESS};
    const ACCESS_MASK relevant =
        RelevantMask(policy);
    bool exact_created_ace = false;
    if (policy == AclPolicy::CREATED_PRIVATE &&
        checked_dacl->AceCount != 1) {
        error =
            "Refusing newly created wallet lifecycle path '" +
            Utf8ForError(path) +
            "': its protected DACL must contain exactly one ACE.";
        return false;
    }

    for (DWORD index = 0;
        index < checked_dacl->AceCount;
        ++index) {
        void* raw_ace = nullptr;
        if (!GetAce(
                checked_dacl,
                index,
                &raw_ace) ||
            !raw_ace) {
            const DWORD native_error = GetLastError();
            error = WindowsError(
                "Failed to inspect wallet lifecycle DACL ACE",
                path,
                native_error);
            return false;
        }
        const auto* header =
            static_cast<const ACE_HEADER*>(raw_ace);
        if (!IsAllowAceType(header->AceType)) {
            if (policy == AclPolicy::CREATED_PRIVATE) {
                error =
                    "Refusing newly created wallet lifecycle path '" +
                    Utf8ForError(path) +
                    "': its protected DACL contains an unexpected ACE.";
                return false;
            }
            continue;
        }
        if (header->AceSize <
            sizeof(ACE_HEADER) +
                sizeof(ACCESS_MASK)) {
            error =
                "Refusing wallet lifecycle path '" +
                Utf8ForError(path) +
                "': its DACL contains a truncated allow ACE.";
            return false;
        }

        ACCESS_MASK mask = *reinterpret_cast<const ACCESS_MASK*>(
            reinterpret_cast<const unsigned char*>(raw_ace) +
            sizeof(ACE_HEADER));
        MapGenericMask(
            &mask,
            &mapping);

        if (header->AceType !=
            ACCESS_ALLOWED_ACE_TYPE) {
            if ((mask & relevant) != 0 ||
                policy == AclPolicy::CREATED_PRIVATE) {
                error =
                    "Refusing wallet lifecycle path '" +
                    Utf8ForError(path) +
                    "': an object or callback allow ACE grants relevant access.";
                return false;
            }
            continue;
        }

        const auto* allow =
            static_cast<const ACCESS_ALLOWED_ACE*>(
                raw_ace);
        constexpr size_t SID_OFFSET =
            offsetof(
                ACCESS_ALLOWED_ACE,
                SidStart);
        constexpr size_t MINIMUM_SID_SIZE =
            offsetof(
                SID,
                SubAuthority);
        const size_t ace_size =
            header->AceSize;
        if (ace_size <
            SID_OFFSET +
                MINIMUM_SID_SIZE) {
            error =
                "Refusing wallet lifecycle path '" +
                Utf8ForError(path) +
                "': its DACL contains a truncated allow SID.";
            return false;
        }
        PSID sid = const_cast<DWORD*>(
            &allow->SidStart);
        if (!IsValidSid(sid) ||
            GetLengthSid(sid) >
                ace_size -
                    SID_OFFSET) {
            error =
                "Refusing wallet lifecycle path '" +
                Utf8ForError(path) +
                "': its DACL contains an invalid allow SID.";
            return false;
        }

        if (policy == AclPolicy::CREATED_PRIVATE) {
            const ACCESS_MASK required =
                FILE_ALL_ACCESS;
            if (!IsCurrentUserSid(
                    sid,
                    current_user) ||
                (mask & required) != required) {
                error =
                    "Refusing newly created wallet lifecycle path '" +
                    Utf8ForError(path) +
                    "': its sole ACE is not current-user full control.";
                return false;
            }
            exact_created_ace = true;
            continue;
        }

        // These inherit-only well-known SIDs grant only the owner of a
        // child, whose ownership is independently validated.
        const bool safe_creator_owner =
            IsSafeCreatorOwnerSid(sid) &&
            (header->AceFlags & INHERIT_ONLY_ACE) != 0 &&
            (header->AceFlags &
                (OBJECT_INHERIT_ACE |
                    CONTAINER_INHERIT_ACE)) != 0;
        if (!IsTrustedSid(
                sid,
                current_user) &&
            !safe_creator_owner &&
            (mask & relevant) != 0) {
            error =
                "Refusing wallet lifecycle path '" +
                Utf8ForError(path) +
                "': an untrusted allow ACE grants access relevant to this operation.";
            return false;
        }
    }

    if (policy == AclPolicy::CREATED_PRIVATE &&
        !exact_created_ace) {
        error =
            "Refusing newly created wallet lifecycle path '" +
            Utf8ForError(path) +
            "': its current-user full-control ACE was not found.";
        return false;
    }
    return true;
}

bool QueryFileState(
    HANDLE handle,
    FileState& state,
    DWORD& native_error) noexcept
{
    state = {};
    native_error = ERROR_SUCCESS;
    if (!IsValidHandle(handle)) {
        native_error = ERROR_INVALID_HANDLE;
        return false;
    }

    BY_HANDLE_FILE_INFORMATION legacy{};
    FILE_STANDARD_INFO standard{};
    if (!GetFileInformationByHandle(
            handle,
            &legacy)) {
        native_error = GetLastError();
        return false;
    }
    if (!GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            &standard,
            sizeof(standard))) {
        native_error = GetLastError();
        return false;
    }
    if (standard.EndOfFile.QuadPart < 0) {
        native_error = ERROR_FILE_INVALID;
        return false;
    }

    state.identity.device =
        static_cast<uint64_t>(
            legacy.dwVolumeSerialNumber);
    state.identity.inode =
        (static_cast<uint64_t>(
             legacy.nFileIndexHigh)
            << 32) |
        static_cast<uint64_t>(
            legacy.nFileIndexLow);
    state.size =
        static_cast<uint64_t>(
            standard.EndOfFile.QuadPart);
    state.link_count =
        standard.NumberOfLinks;
    state.directory =
        standard.Directory != FALSE ||
        (legacy.dwFileAttributes &
            FILE_ATTRIBUTE_DIRECTORY) != 0;
    state.reparse_point =
        (legacy.dwFileAttributes &
            FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    state.delete_pending =
        standard.DeletePending != FALSE;
    return true;
}

bool GetFinalHandlePath(
    HANDLE handle,
    std::wstring& path,
    DWORD& native_error)
{
    path.clear();
    native_error = ERROR_SUCCESS;
    constexpr DWORD FLAGS =
        FILE_NAME_NORMALIZED |
        VOLUME_NAME_DOS;
    const DWORD required =
        GetFinalPathNameByHandleW(
            handle,
            nullptr,
            0,
            FLAGS);
    if (required == 0) {
        native_error = GetLastError();
        return false;
    }
    std::vector<wchar_t> buffer(
        static_cast<size_t>(required) + 1);
    const DWORD length =
        GetFinalPathNameByHandleW(
            handle,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            FLAGS);
    if (length == 0 ||
        length >= buffer.size()) {
        native_error =
            length == 0 ?
                GetLastError() :
                ERROR_INSUFFICIENT_BUFFER;
        return false;
    }
    path.assign(buffer.data(), length);
    return true;
}

bool ValidateLocalNtfs(
    HANDLE handle,
    const std::wstring& path,
    std::string& error)
{
    wchar_t filesystem[MAX_PATH + 1]{};
    DWORD serial = 0;
    DWORD maximum_component = 0;
    DWORD flags = 0;
    if (!GetVolumeInformationByHandleW(
            handle,
            nullptr,
            0,
            &serial,
            &maximum_component,
            &flags,
            filesystem,
            static_cast<DWORD>(
                std::size(filesystem)))) {
        const DWORD native_error = GetLastError();
        error = WindowsError(
            "Failed to inspect wallet lifecycle volume",
            path,
            native_error);
        return false;
    }
    if (_wcsicmp(
            filesystem,
            L"NTFS") != 0 ||
        (flags & FS_PERSISTENT_ACLS) == 0) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(path) +
            "': local NTFS with persistent ACLs is required.";
        return false;
    }

    FILE_REMOTE_PROTOCOL_INFO remote{};
    if (GetFileInformationByHandleEx(
            handle,
            FileRemoteProtocolInfo,
            &remote,
            sizeof(remote))) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(path) +
            "': remote filesystems are not supported.";
        return false;
    }
    const DWORD remote_error = GetLastError();
    if (remote_error != ERROR_INVALID_PARAMETER &&
        remote_error != ERROR_INVALID_FUNCTION &&
        remote_error != ERROR_CALL_NOT_IMPLEMENTED &&
        remote_error != ERROR_NOT_SUPPORTED) {
        error = WindowsError(
            "Failed to prove that wallet lifecycle storage is local",
            path,
            remote_error);
        return false;
    }

    std::wstring final_path;
    DWORD final_error = ERROR_SUCCESS;
    if (!GetFinalHandlePath(
            handle,
            final_path,
            final_error)) {
        error = WindowsError(
            "Failed to resolve wallet lifecycle handle",
            path,
            final_error);
        return false;
    }
    if (final_path.rfind(
            L"\\\\?\\UNC\\",
            0) == 0 ||
        (final_path.rfind(
             L"\\\\",
             0) == 0 &&
            final_path.rfind(
                L"\\\\?\\",
                0) != 0)) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(path) +
            "': a local fixed drive is required.";
        return false;
    }
    if (final_path.rfind(
            L"\\\\?\\",
            0) == 0) {
        final_path.erase(0, 4);
    }
    if (!IsDriveAbsolute(final_path)) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(path) +
            "': its handle does not resolve to a local drive path.";
        return false;
    }
    const std::wstring root =
        final_path.substr(0, 3);
    if (GetDriveTypeW(
            root.c_str()) != DRIVE_FIXED) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(path) +
            "': a local fixed drive is required.";
        return false;
    }
    return true;
}

bool ValidateCommonFileState(
    const FileState& state,
    const std::wstring& path,
    bool require_regular,
    bool require_single_link,
    bool allow_delete_pending,
    std::string& error)
{
    if (state.identity.inode == 0) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(path) +
            "': a stable NTFS file index is unavailable.";
        return false;
    }
    if (state.reparse_point) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(path) +
            "': reparse points are not allowed.";
        return false;
    }
    if (require_regular &&
        state.directory) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(path) +
            "': a regular file is required.";
        return false;
    }
    if (!require_regular &&
        !state.directory) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(path) +
            "': a directory is required.";
        return false;
    }
    if (require_single_link &&
        state.link_count != 1) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(path) +
            "': exactly one filesystem link is required.";
        return false;
    }
    if (!allow_delete_pending &&
        state.delete_pending) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(path) +
            "': the object is delete-pending.";
        return false;
    }
    return true;
}

bool OpenDirectoryHandle(
    const std::wstring& path,
    ScopedHandle& handle,
    std::string& error)
{
    const std::wstring native =
        Win32ExtendedPath(path);
    handle.Reset(CreateFileW(
        native.c_str(),
        FILE_READ_ATTRIBUTES |
            READ_CONTROL,
        FILE_SHARE_READ |
            FILE_SHARE_WRITE |
            FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS |
            FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (!handle) {
        const DWORD native_error = GetLastError();
        error = WindowsError(
            "Failed to open wallet lifecycle directory without following reparse points",
            path,
            native_error);
        return false;
    }
    return true;
}

bool ValidateDirectoryPath(
    const std::wstring& full,
    bool private_final,
    FileState* final_state,
    std::string& error)
{
    if (!IsDriveAbsolute(full)) {
        error =
            "Refusing wallet lifecycle directory '" +
            Utf8ForError(full) +
            "': a local drive-absolute path is required.";
        return false;
    }

    std::vector<std::wstring> components;
    components.push_back(full.substr(0, 3));
    size_t position = 3;
    std::wstring current = components.front();
    while (position < full.size()) {
        while (position < full.size() &&
               full[position] == L'\\') {
            ++position;
        }
        if (position == full.size()) {
            break;
        }
        const size_t next =
            full.find(L'\\', position);
        const std::wstring component =
            full.substr(
                position,
                next == std::wstring::npos ?
                    std::wstring::npos :
                    next - position);
        if (component.empty() ||
            component == L"." ||
            component == L"..") {
            error =
                "Refusing wallet lifecycle directory '" +
                Utf8ForError(full) +
                "': an unsafe path component was found.";
            return false;
        }
        if (current.size() > 3) {
            current += L'\\';
        }
        current += component;
        components.push_back(current);
        if (next == std::wstring::npos) {
            break;
        }
        position = next + 1;
    }

    for (size_t index = 0;
        index < components.size();
        ++index) {
        const bool final =
            index + 1 == components.size();
        ScopedHandle handle;
        if (!OpenDirectoryHandle(
                components[index],
                handle,
                error)) {
            return false;
        }

        FileState state;
        DWORD native_error = ERROR_SUCCESS;
        if (!QueryFileState(
                handle.Get(),
                state,
                native_error)) {
            error = WindowsError(
                "Failed to inspect wallet lifecycle directory",
                components[index],
                native_error);
            return false;
        }
        if (!ValidateCommonFileState(
                state,
                components[index],
                false,
                false,
                false,
                error) ||
            !ValidateLocalNtfs(
                handle.Get(),
                components[index],
                error) ||
            !ValidateHandleAcl(
                handle.Get(),
                final && private_final ?
                    AclPolicy::PRIVATE :
                    AclPolicy::ANCESTOR,
                components[index],
                error)) {
            return false;
        }
        if (final && final_state) {
            *final_state = state;
        }
    }
    return true;
}

AclPolicy ToAclPolicy(
    SecurityPolicy policy) noexcept
{
    switch (policy) {
    case SecurityPolicy::DISCOVERY:
        return AclPolicy::NONE;
    case SecurityPolicy::SOURCE_CONTROLLED:
        return AclPolicy::SOURCE_CONTROLLED;
    case SecurityPolicy::PRIVATE:
        return AclPolicy::PRIVATE;
    }
    return AclPolicy::NONE;
}

bool LockClaimSentinel(
    HANDLE handle,
    const std::wstring& path,
    std::string& error)
{
    OVERLAPPED lock{};
    const ULARGE_INTEGER offset{
        .QuadPart = CLAIM_OFFSET};
    lock.Offset = offset.LowPart;
    lock.OffsetHigh = offset.HighPart;
    if (!LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK |
                LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &lock)) {
        const DWORD native_error = GetLastError();
        error = WindowsError(
            "Unable to claim wallet database; another Firo process may own it",
            path,
            native_error);
        return false;
    }
    return true;
}

IdentityState InspectPathIdentityInternal(
    const std::wstring& full,
    const DatabaseFileIdentity& expected,
    std::string& error)
{
    const std::wstring native =
        Win32ExtendedPath(full);
    ScopedHandle handle(CreateFileW(
        native.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ |
            FILE_SHARE_WRITE |
            FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS |
            FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (!handle) {
        const DWORD native_error = GetLastError();
        if (IsAbsentError(native_error)) {
            error.clear();
            return IdentityState::ABSENT;
        }
        error = WindowsError(
            "Failed to inspect wallet lifecycle pathname identity",
            full,
            native_error);
        return IdentityState::FAILED;
    }

    FileState state;
    DWORD native_error = ERROR_SUCCESS;
    if (!QueryFileState(
            handle.Get(),
            state,
            native_error)) {
        error = WindowsError(
            "Failed to inspect wallet lifecycle pathname identity",
            full,
            native_error);
        return IdentityState::FAILED;
    }
    if (state.directory ||
        state.reparse_point ||
        state.delete_pending ||
        state.link_count != 1 ||
        state.identity.inode == 0) {
        error =
            "Wallet lifecycle path '" +
            Utf8ForError(full) +
            "' exists but is not an eligible single-link regular file.";
        return IdentityState::OTHER;
    }
    if (!ValidateLocalNtfs(
            handle.Get(),
            full,
            error)) {
        return IdentityState::FAILED;
    }
    if (!SameIdentity(
            state.identity,
            expected)) {
        error =
            "Wallet lifecycle path '" +
            Utf8ForError(full) +
            "' names a different file identity.";
        return IdentityState::OTHER;
    }
    error.clear();
    return IdentityState::MATCH;
}

bool ValidateOpenFile(
    HANDLE handle,
    const std::wstring& full,
    SecurityPolicy policy,
    FileState& state,
    std::string& error)
{
    DWORD native_error = ERROR_SUCCESS;
    if (!QueryFileState(
            handle,
            state,
            native_error)) {
        error = WindowsError(
            "Failed to inspect wallet lifecycle file",
            full,
            native_error);
        return false;
    }
    if (!ValidateCommonFileState(
            state,
            full,
            true,
            true,
            false,
            error) ||
        !ValidateLocalNtfs(
            handle,
            full,
            error) ||
        !ValidateHandleAcl(
            handle,
            ToAclPolicy(policy),
            full,
            error)) {
        return false;
    }

    std::string identity_error;
    const IdentityState path_identity =
        InspectPathIdentityInternal(
            full,
            state.identity,
            identity_error);
    if (path_identity != IdentityState::MATCH) {
        error =
            "Refusing wallet lifecycle path '" +
            Utf8ForError(full) +
            "': its pathname changed while the retained handle was validated.";
        if (!identity_error.empty()) {
            error += " " + identity_error;
        }
        return false;
    }
    return true;
}

bool BuildPrivateSecurityAttributes(
    std::vector<unsigned char>& current_user,
    std::vector<unsigned char>& acl_storage,
    SECURITY_DESCRIPTOR& descriptor,
    SECURITY_ATTRIBUTES& attributes,
    std::string& error)
{
    if (!GetCurrentUserSid(
            current_user,
            error)) {
        return false;
    }
    const DWORD sid_length =
        static_cast<DWORD>(
            current_user.size());
    const DWORD acl_size =
        sizeof(ACL) +
        sizeof(ACCESS_ALLOWED_ACE) -
        sizeof(DWORD) +
        sid_length;
    acl_storage.resize(acl_size);
    auto* acl =
        reinterpret_cast<PACL>(
            acl_storage.data());
    if (!InitializeAcl(
            acl,
            acl_size,
            ACL_REVISION) ||
        !AddAccessAllowedAceEx(
            acl,
            ACL_REVISION,
            0,
            FILE_ALL_ACCESS,
            current_user.data())) {
        const DWORD native_error = GetLastError();
        error = HandleWindowsError(
            "Failed to construct the private wallet lifecycle DACL",
            {},
            native_error);
        return false;
    }

    if (!InitializeSecurityDescriptor(
            &descriptor,
            SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorOwner(
            &descriptor,
            current_user.data(),
            FALSE) ||
        !SetSecurityDescriptorDacl(
            &descriptor,
            TRUE,
            acl,
            FALSE) ||
        !SetSecurityDescriptorControl(
            &descriptor,
            SE_DACL_PROTECTED,
            SE_DACL_PROTECTED)) {
        const DWORD native_error = GetLastError();
        error = HandleWindowsError(
            "Failed to construct the private wallet lifecycle security descriptor",
            {},
            native_error);
        return false;
    }

    attributes = {};
    attributes.nLength =
        sizeof(attributes);
    attributes.lpSecurityDescriptor =
        &descriptor;
    attributes.bInheritHandle = FALSE;
    return true;
}

bool SetDeletePending(
    HANDLE handle,
    DWORD& native_error) noexcept
{
    FILE_DISPOSITION_INFO disposition{};
    disposition.DeleteFile = TRUE;
    if (!SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            &disposition,
            sizeof(disposition))) {
        native_error = GetLastError();
        return false;
    }
    native_error = ERROR_SUCCESS;
    return true;
}

bool CleanupCreatedFile(
    const std::wstring& full,
    HANDLE retained,
    const DatabaseFileIdentity& expected,
    std::string& detail)
{
    detail.clear();
    const std::wstring native =
        Win32ExtendedPath(full);
    ScopedHandle cleanup(CreateFileW(
        native.c_str(),
        DELETE |
            FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ |
            FILE_SHARE_WRITE |
            FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS |
            FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (!cleanup) {
        const DWORD native_error = GetLastError();
        detail = WindowsError(
            "Failed to reopen the exact created wallet file for cleanup",
            full,
            native_error);
        return false;
    }

    FileState cleanup_state;
    FileState retained_state;
    DWORD native_error = ERROR_SUCCESS;
    if (!QueryFileState(
            cleanup.Get(),
            cleanup_state,
            native_error) ||
        !SameIdentity(
            cleanup_state.identity,
            expected) ||
        cleanup_state.directory ||
        cleanup_state.reparse_point ||
        cleanup_state.link_count != 1 ||
        cleanup_state.delete_pending ||
        !QueryFileState(
            retained,
            retained_state,
            native_error) ||
        !SameIdentity(
            retained_state.identity,
            expected)) {
        detail =
            "Refusing cleanup of created wallet lifecycle path '" +
            Utf8ForError(full) +
            "': its retained exact identity cannot be certified.";
        return false;
    }
    if (!SetDeletePending(
            cleanup.Get(),
            native_error)) {
        detail = WindowsError(
            "Failed to mark the exact created wallet file delete-pending",
            full,
            native_error);
        return false;
    }
    if (!QueryFileState(
            cleanup.Get(),
            cleanup_state,
            native_error) ||
        !SameIdentity(
            cleanup_state.identity,
            expected) ||
        !cleanup_state.delete_pending) {
        detail =
            "The exact created wallet file cleanup operation returned success, but delete-pending state could not be verified.";
        return false;
    }
    return true;
}

bool ValidateDestinationVolume(
    const std::wstring& destination,
    const DatabaseFileIdentity& source_identity,
    std::string& error)
{
    const std::wstring parent =
        ParentPath(destination);
    FileState parent_state;
    if (!ValidateDirectoryPath(
            parent,
            true,
            &parent_state,
            error)) {
        return false;
    }
    if (parent_state.identity.device !=
        source_identity.device) {
        error =
            "Refusing wallet lifecycle move to '" +
            Utf8ForError(destination) +
            "': source and destination are not on the same NTFS volume.";
        return false;
    }
    return true;
}

bool ValidateRetainedFile(
    const File& file,
    const std::wstring& path,
    const DatabaseFileIdentity& expected,
    SecurityPolicy policy,
    bool allow_delete_pending,
    FileState& state,
    std::string& error)
{
    const HANDLE handle =
        NativeHandle(file);
    DWORD native_error = ERROR_SUCCESS;
    if (!QueryFileState(
            handle,
            state,
            native_error)) {
        error = WindowsError(
            "Failed to inspect retained wallet lifecycle handle",
            path,
            native_error);
        return false;
    }
    if (!SameIdentity(
            state.identity,
            expected) ||
        !ValidateCommonFileState(
            state,
            path,
            true,
            !allow_delete_pending,
            allow_delete_pending,
            error) ||
        !ValidateLocalNtfs(
            handle,
            path,
            error) ||
        !ValidateHandleAcl(
            handle,
            ToAclPolicy(policy),
            path,
            error)) {
        if (error.empty()) {
            error =
                "Retained wallet lifecycle handle for '" +
                Utf8ForError(path) +
                "' does not match the expected identity.";
        }
        return false;
    }
    return true;
}

bool OpenAndFlushFinal(
    const fs::path& path,
    const DatabaseFileIdentity& expected,
    std::string& error)
{
    File final_file;
    DatabaseFileIdentity final_identity{};
    const OpenResult opened = OpenExistingFile(
        path,
        FileAccess::READ_WRITE,
        SecurityPolicy::PRIVATE,
        false,
        final_file,
        final_identity,
        error);
    if (opened != OpenResult::OPENED ||
        !SameIdentity(
            final_identity,
            expected)) {
        if (opened == OpenResult::OPENED &&
            error.empty()) {
            error =
                "Reopened wallet lifecycle destination has an unexpected identity.";
        }
        return false;
    }
    if (!FlushFile(
            final_file,
            error)) {
        return false;
    }
    std::string close_error;
    if (!final_file.Close(
            close_error)) {
        error = close_error;
        return false;
    }
    return true;
}

bool SeekFile(
    const File& file,
    uint64_t offset,
    const char* operation,
    std::string& error)
{
    if (offset >
        static_cast<uint64_t>(
            std::numeric_limits<LONGLONG>::max())) {
        error =
            std::string(operation) +
            " refused an offset beyond the Windows signed 64-bit file range.";
        return false;
    }
    LARGE_INTEGER position{};
    position.QuadPart =
        static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(
            NativeHandle(file),
            position,
            nullptr,
            FILE_BEGIN)) {
        const DWORD native_error = GetLastError();
        error = HandleWindowsError(
            operation,
            FileHandleAccess::Path(file),
            native_error);
        return false;
    }
    return true;
}

void SetMoveError(
    const char* operation,
    const std::wstring& source,
    const std::wstring& destination,
    DWORD native_error,
    std::string& error)
{
    error =
        std::string(operation) +
        " from '" +
        Utf8ForError(source) +
        "' to '" +
        Utf8ForError(destination) +
        "': " +
        WindowsMessage(native_error) +
        " (Windows error " +
        std::to_string(native_error) +
        ")";
}

void ReconcileNoReplace(
    const std::wstring& source,
    const File& source_file,
    const DatabaseFileIdentity& source_identity,
    const std::wstring& destination,
    DWORD native_error,
    bool api_success,
    MoveResult& result)
{
    std::string ignored;
    result.source_path =
        InspectPathIdentityInternal(
            source,
            source_identity,
            ignored);
    result.destination_path =
        InspectPathIdentityInternal(
            destination,
            source_identity,
            ignored);
    result.moving_handle =
        InspectHandleIdentity(
            source_file,
            source_identity,
            ignored);
    result.native_error =
        native_error;

    if (result.destination_path ==
            IdentityState::MATCH &&
        result.source_path ==
            IdentityState::ABSENT &&
        result.moving_handle ==
            IdentityState::MATCH) {
        result.disposition =
            api_success ?
                MoveDisposition::MOVED :
                MoveDisposition::INDETERMINATE;
        return;
    }
    if (result.source_path ==
            IdentityState::MATCH &&
        result.destination_path ==
            IdentityState::OTHER &&
        result.moving_handle ==
            IdentityState::MATCH &&
        !api_success &&
        (native_error == ERROR_ALREADY_EXISTS ||
            native_error == ERROR_FILE_EXISTS)) {
        result.disposition =
            MoveDisposition::COLLISION;
        return;
    }
    if (result.source_path ==
            IdentityState::MATCH &&
        result.destination_path ==
            IdentityState::ABSENT &&
        result.moving_handle ==
            IdentityState::MATCH &&
        !api_success) {
        result.disposition =
            MoveDisposition::NOT_MOVED;
        return;
    }
    result.disposition =
        MoveDisposition::INDETERMINATE;
}

void ReconcileReplace(
    const std::wstring& source,
    const File& source_file,
    const DatabaseFileIdentity& source_identity,
    const std::wstring& destination,
    const File& replaced,
    const DatabaseFileIdentity& replaced_identity,
    DWORD native_error,
    bool api_success,
    MoveResult& result)
{
    std::string ignored;
    result.source_path =
        InspectPathIdentityInternal(
            source,
            source_identity,
            ignored);
    result.destination_path =
        InspectPathIdentityInternal(
            destination,
            source_identity,
            ignored);
    result.destination_replaced =
        InspectPathIdentityInternal(
            destination,
            replaced_identity,
            ignored);
    result.moving_handle =
        InspectHandleIdentity(
            source_file,
            source_identity,
            ignored);
    result.replaced_handle =
        InspectHandleIdentity(
            replaced,
            replaced_identity,
            ignored);
    result.native_error =
        native_error;

    FileState replaced_state;
    DWORD state_error = ERROR_SUCCESS;
    if (QueryFileState(
            NativeHandle(replaced),
            replaced_state,
            state_error) &&
        SameIdentity(
            replaced_state.identity,
            replaced_identity)) {
        result.replaced_delete_pending =
            replaced_state.delete_pending;
    }

    if (result.destination_path ==
            IdentityState::MATCH &&
        result.source_path ==
            IdentityState::ABSENT &&
        result.moving_handle ==
            IdentityState::MATCH &&
        result.replaced_handle ==
            IdentityState::MATCH &&
        result.replaced_delete_pending) {
        result.disposition =
            api_success ?
                MoveDisposition::MOVED :
                MoveDisposition::INDETERMINATE;
        return;
    }
    if (result.source_path ==
            IdentityState::MATCH &&
        result.destination_replaced ==
            IdentityState::MATCH &&
        result.moving_handle ==
            IdentityState::MATCH &&
        result.replaced_handle ==
            IdentityState::MATCH &&
        !result.replaced_delete_pending &&
        !api_success) {
        result.disposition =
            MoveDisposition::NOT_MOVED;
        return;
    }
    result.disposition =
        MoveDisposition::INDETERMINATE;
}
} // namespace

File::File(
    void* handle,
    std::string path) noexcept
    : m_handle(handle),
      m_path(std::move(path))
{
}

File::~File()
{
    Reset();
}

File::File(
    File&& other) noexcept
    : m_handle(other.m_handle),
      m_path(std::move(other.m_path))
{
    other.m_handle = nullptr;
}

File& File::operator=(
    File&& other) noexcept
{
    if (this != &other) {
        Reset();
        m_handle = other.m_handle;
        m_path = std::move(other.m_path);
        other.m_handle = nullptr;
    }
    return *this;
}

File::operator bool() const noexcept
{
    return IsValidHandle(
        NativeHandle(*this));
}

bool File::Close(
    std::string& error)
{
    error.clear();
    if (!*this) {
        m_handle = nullptr;
        m_path.clear();
        return true;
    }
    const HANDLE handle =
        NativeHandle(*this);
    m_handle = nullptr;
    const std::string path =
        std::move(m_path);
    if (CloseHandle(handle)) {
        return true;
    }
    const DWORD native_error = GetLastError();
    error = HandleWindowsError(
        "Failed to close wallet lifecycle handle",
        path,
        native_error);
    return false;
}

void File::Reset() noexcept
{
    if (*this) {
        CloseHandle(
            NativeHandle(*this));
    }
    m_handle = nullptr;
    m_path.clear();
}

void* File::Get() const noexcept
{
    return m_handle;
}

OpenResult OpenExistingFile(
    const fs::path& path,
    FileAccess access,
    SecurityPolicy policy,
    bool claim,
    File& file,
    DatabaseFileIdentity& identity,
    std::string& error)
{
    file.Reset();
    identity = {};
    error.clear();

    std::wstring full;
    if (!NormalizePath(
            path,
            full,
            error)) {
        return OpenResult::FAILED;
    }
    const std::wstring parent =
        ParentPath(full);
    if (!ValidateDirectoryPath(
            parent,
            policy != SecurityPolicy::DISCOVERY,
            nullptr,
            error)) {
        return OpenResult::FAILED;
    }

    DWORD desired_access =
        GENERIC_READ |
        FILE_READ_ATTRIBUTES |
        READ_CONTROL;
    if (access == FileAccess::READ_WRITE ||
        claim) {
        desired_access |=
            GENERIC_WRITE;
    }
    const DWORD share_mode =
        claim ?
            FILE_SHARE_READ |
                FILE_SHARE_WRITE |
                FILE_SHARE_DELETE :
            FILE_SHARE_READ |
                FILE_SHARE_WRITE;
    const std::wstring native =
        Win32ExtendedPath(full);
    ScopedHandle retained(CreateFileW(
        native.c_str(),
        desired_access,
        share_mode,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS |
            FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (!retained) {
        const DWORD native_error = GetLastError();
        if (IsAbsentError(native_error)) {
            return OpenResult::ABSENT;
        }
        error = WindowsError(
            "Failed to open wallet lifecycle file without following reparse points",
            full,
            native_error);
        return OpenResult::FAILED;
    }

    FileState state;
    if (!ValidateOpenFile(
            retained.Get(),
            full,
            policy,
            state,
            error)) {
        return OpenResult::FAILED;
    }
    if (claim &&
        !LockClaimSentinel(
            retained.Get(),
            full,
            error)) {
        return OpenResult::FAILED;
    }

    std::string path_utf8;
    DWORD conversion_error = ERROR_SUCCESS;
    if (!WideToUtf8(
            full,
            path_utf8,
            conversion_error)) {
        error = WindowsError(
            "Failed to represent opened wallet lifecycle path as UTF-8",
            full,
            conversion_error);
        return OpenResult::FAILED;
    }
    identity = state.identity;
    file = File(
        retained.Release(),
        std::move(path_utf8));
    return OpenResult::OPENED;
}

CreateResult CreatePrivateFile(
    const fs::path& path,
    bool claim,
    File& file,
    DatabaseFileIdentity& identity,
    std::string& error)
{
    file.Reset();
    identity = {};
    error.clear();

    std::wstring full;
    if (!NormalizePath(
            path,
            full,
            error)) {
        return CreateResult::FAILED;
    }
    if (!ValidateDirectoryPath(
            ParentPath(full),
            true,
            nullptr,
            error)) {
        return CreateResult::FAILED;
    }

    std::vector<unsigned char> current_user;
    std::vector<unsigned char> acl_storage;
    SECURITY_DESCRIPTOR descriptor{};
    SECURITY_ATTRIBUTES attributes{};
    if (!BuildPrivateSecurityAttributes(
            current_user,
            acl_storage,
            descriptor,
            attributes,
            error)) {
        return CreateResult::FAILED;
    }

    const std::wstring native =
        Win32ExtendedPath(full);
    ScopedHandle created(CreateFileW(
        native.c_str(),
        GENERIC_READ |
            GENERIC_WRITE |
            FILE_READ_ATTRIBUTES |
            READ_CONTROL,
        FILE_SHARE_READ |
            FILE_SHARE_WRITE |
            FILE_SHARE_DELETE,
        &attributes,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL |
            FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (!created) {
        const DWORD native_error = GetLastError();
        if (native_error == ERROR_FILE_EXISTS ||
            native_error == ERROR_ALREADY_EXISTS) {
            return CreateResult::EXISTS;
        }
        error = WindowsError(
            "Failed to exclusively create private wallet lifecycle file",
            full,
            native_error);
        return CreateResult::FAILED;
    }

    FileState state;
    DWORD native_error = ERROR_SUCCESS;
    bool valid =
        QueryFileState(
            created.Get(),
            state,
            native_error);
    if (!valid) {
        error = WindowsError(
            "Failed to inspect newly created wallet lifecycle file",
            full,
            native_error);
    } else {
        identity = state.identity;
        if (ConsumePrivateFileValidationFailure()) {
            valid = false;
            error =
                "Injected failure while validating a newly created private "
                "wallet lifecycle file.";
        } else {
            valid =
                ValidateCommonFileState(
                    state,
                    full,
                    true,
                    true,
                    false,
                    error) &&
                ValidateLocalNtfs(
                    created.Get(),
                    full,
                    error) &&
                ValidateHandleAcl(
                    created.Get(),
                    AclPolicy::CREATED_PRIVATE,
                    full,
                    error);
        }
    }
    if (valid) {
        std::string identity_error;
        valid =
            InspectPathIdentityInternal(
                full,
                state.identity,
                identity_error) ==
            IdentityState::MATCH;
        if (!valid) {
            error =
                "Newly created wallet lifecycle file lost its retained pathname identity.";
            if (!identity_error.empty()) {
                error += " " + identity_error;
            }
        }
    }
    if (valid &&
        claim) {
        valid = LockClaimSentinel(
            created.Get(),
            full,
            error);
    }

    std::string path_utf8;
    DWORD conversion_error = ERROR_SUCCESS;
    if (!WideToUtf8(
            full,
            path_utf8,
            conversion_error)) {
        if (valid) {
            error = WindowsError(
                "Failed to represent created wallet lifecycle path as UTF-8",
                full,
                conversion_error);
        }
        valid = false;
    }

    if (!valid) {
        std::string cleanup_error;
        bool cleaned = false;
        if (identity.inode != 0) {
            cleaned = CleanupCreatedFile(
                full,
                created.Get(),
                identity,
                cleanup_error);
        }
        file = File(
            created.Release(),
            std::move(path_utf8));
        if (cleaned) {
            error +=
                " The exact created file is delete-pending now, but Windows "
                "cannot prove its namespace removal durable across power loss.";
        } else if (!cleanup_error.empty()) {
            error +=
                " Exact delete-pending cleanup could not be certified: " +
                cleanup_error;
        } else {
            error +=
                " Exact delete-pending cleanup could not be attempted because the created identity was unavailable.";
        }
        return CreateResult::INDETERMINATE;
    }

    file = File(
        created.Release(),
        std::move(path_utf8));
    return CreateResult::CREATED;
}

void InjectPrivateFileValidationFailureForTesting()
{
    g_fail_private_file_validation_once.store(true);
}

void ResetFileLifecycleForTesting()
{
    g_fail_private_file_validation_once.store(false);
}

bool ValidateMigrationDirectory(
    const fs::path& directory,
    std::string& error)
{
    error.clear();
    std::wstring native;
    if (!NativePath(
            directory,
            native,
            error)) {
        return false;
    }
    if (!IsDriveAbsolute(native)) {
        error =
            "Refusing migration directory '" +
            Utf8ForError(native) +
            "': an absolute local drive path is required.";
        return false;
    }

    std::wstring full;
    if (!NormalizePath(
            directory,
            full,
            error)) {
        return false;
    }
    return ValidateDirectoryPath(
        full,
        true,
        nullptr,
        error);
}

bool PathToUtf8(
    const fs::path& path,
    std::string& utf8,
    std::string& error)
{
    utf8.clear();
    error.clear();
    std::wstring native;
    if (!NormalizePath(
            path,
            native,
            error)) {
        return false;
    }
    DWORD conversion_error = ERROR_SUCCESS;
    if (!WideToUtf8(
            native,
            utf8,
            conversion_error)) {
        error = WindowsError(
            "Failed to convert wallet path to strict UTF-8",
            native,
            conversion_error);
        return false;
    }
    return true;
}

bool GetFileState(
    const File& file,
    FileState& state,
    std::string& error)
{
    error.clear();
    DWORD native_error = ERROR_SUCCESS;
    if (!QueryFileState(
            NativeHandle(file),
            state,
            native_error)) {
        error = HandleWindowsError(
            "Failed to inspect wallet lifecycle handle",
            file.m_path,
            native_error);
        return false;
    }
    return true;
}

IdentityState InspectHandleIdentity(
    const File& file,
    const DatabaseFileIdentity& expected,
    std::string& error)
{
    error.clear();
    FileState state;
    if (!GetFileState(
            file,
            state,
            error)) {
        return IdentityState::FAILED;
    }
    if (state.directory ||
        state.reparse_point ||
        state.identity.inode == 0 ||
        !SameIdentity(
            state.identity,
            expected)) {
        error =
            "Retained wallet lifecycle handle names a different or ineligible file identity.";
        return IdentityState::OTHER;
    }
    return IdentityState::MATCH;
}

IdentityState InspectPathIdentity(
    const fs::path& path,
    const DatabaseFileIdentity& expected,
    std::string& error)
{
    error.clear();
    std::wstring full;
    if (!NormalizePath(
            path,
            full,
            error)) {
        return IdentityState::FAILED;
    }
    return InspectPathIdentityInternal(
        full,
        expected,
        error);
}

bool SQLiteHandleIdentityMatches(
    sqlite3* database,
    const DatabaseFileIdentity& expected,
    std::string& error)
{
    error.clear();
    if (!database) {
        error =
            "Cannot inspect a null SQLite wallet connection.";
        return false;
    }
    HANDLE handle = nullptr;
    const int result = sqlite3_file_control(
        database,
        "main",
        SQLITE_FCNTL_WIN32_GET_HANDLE,
        &handle);
    if (result != SQLITE_OK ||
        !IsValidHandle(handle)) {
        error =
            "SQLite could not provide its native Windows main-database HANDLE (SQLite error " +
            std::to_string(result) + ").";
        return false;
    }

    FileState state;
    DWORD native_error = ERROR_SUCCESS;
    if (!QueryFileState(
            handle,
            state,
            native_error)) {
        error = HandleWindowsError(
            "Failed to inspect SQLite's native main-database HANDLE",
            {},
            native_error);
        return false;
    }
    const std::wstring context =
        L"<SQLite main database>";
    if (!SameIdentity(
            state.identity,
            expected) ||
        !ValidateCommonFileState(
            state,
            context,
            true,
            true,
            false,
            error) ||
        !ValidateLocalNtfs(
            handle,
            context,
            error)) {
        if (error.empty()) {
            error =
                "SQLite's native main-database HANDLE does not match the retained preflight identity.";
        }
        return false;
    }
    return true;
}

bool FlushFile(
    const File& file,
    std::string& error)
{
    error.clear();
    if (!FlushFileBuffers(
            NativeHandle(file))) {
        const DWORD native_error = GetLastError();
        error = HandleWindowsError(
            "Failed to flush wallet lifecycle file",
            file.m_path,
            native_error);
        return false;
    }
    return true;
}

bool ReadExact(
    const File& file,
    uint64_t offset,
    void* output,
    size_t size,
    std::string& error)
{
    error.clear();
    if (size != 0 &&
        !output) {
        error =
            "Cannot read wallet lifecycle bytes into a null buffer.";
        return false;
    }
    if (size >
        static_cast<uint64_t>(
            std::numeric_limits<LONGLONG>::max()) -
            std::min<uint64_t>(
                offset,
                static_cast<uint64_t>(
                    std::numeric_limits<LONGLONG>::max()))) {
        error =
            "Wallet lifecycle read range exceeds the Windows signed 64-bit file range.";
        return false;
    }
    if (!SeekFile(
            file,
            offset,
            "Failed to seek wallet lifecycle file for reading",
            error)) {
        return false;
    }

    auto* bytes =
        static_cast<unsigned char*>(output);
    size_t completed = 0;
    while (completed < size) {
        const DWORD request =
            static_cast<DWORD>(
                std::min<size_t>(
                    size - completed,
                    std::numeric_limits<DWORD>::max()));
        DWORD count = 0;
        if (!ReadFile(
                NativeHandle(file),
                bytes + completed,
                request,
                &count,
                nullptr)) {
            const DWORD native_error = GetLastError();
            error = HandleWindowsError(
                "Failed to read wallet lifecycle file",
                file.m_path,
                native_error);
            return false;
        }
        if (count == 0) {
            error =
                "Failed to read wallet lifecycle file '" +
                file.m_path +
                "': unexpected end of file.";
            return false;
        }
        completed += count;
    }
    return true;
}

static bool WriteExact(
    const File& file,
    uint64_t offset,
    const void* input,
    size_t size,
    std::string& error)
{
    error.clear();
    if (size != 0 &&
        !input) {
        error =
            "Cannot write wallet lifecycle bytes from a null buffer.";
        return false;
    }
    if (size >
        static_cast<uint64_t>(
            std::numeric_limits<LONGLONG>::max()) -
            std::min<uint64_t>(
                offset,
                static_cast<uint64_t>(
                    std::numeric_limits<LONGLONG>::max()))) {
        error =
            "Wallet lifecycle write range exceeds the Windows signed 64-bit file range.";
        return false;
    }
    if (!SeekFile(
            file,
            offset,
            "Failed to seek wallet lifecycle file for writing",
            error)) {
        return false;
    }

    const auto* bytes =
        static_cast<const unsigned char*>(input);
    size_t completed = 0;
    while (completed < size) {
        const DWORD request =
            static_cast<DWORD>(
                std::min<size_t>(
                    size - completed,
                    std::numeric_limits<DWORD>::max()));
        DWORD count = 0;
        if (!WriteFile(
                NativeHandle(file),
                bytes + completed,
                request,
                &count,
                nullptr)) {
            const DWORD native_error = GetLastError();
            error = HandleWindowsError(
                "Failed to write wallet lifecycle file",
                FileHandleAccess::Path(file),
                native_error);
            return false;
        }
        if (count == 0) {
            error =
                "Failed to write wallet lifecycle file '" +
                FileHandleAccess::Path(file) +
                "': the write made no progress.";
            return false;
        }
        completed += count;
    }
    return true;
}

static bool TruncateFile(
    const File& file,
    uint64_t size,
    std::string& error)
{
    error.clear();
    if (!SeekFile(
            file,
            size,
            "Failed to seek wallet lifecycle file for truncation",
            error)) {
        return false;
    }
    if (!SetEndOfFile(
            NativeHandle(file))) {
        const DWORD native_error = GetLastError();
        error = HandleWindowsError(
            "Failed to truncate wallet lifecycle file",
            FileHandleAccess::Path(file),
            native_error);
        return false;
    }
    return true;
}

bool CopyFileContents(
    const File& source,
    const File& destination,
    std::string& error)
{
    error.clear();
    FileState source_state;
    FileState destination_state;
    if (!GetFileState(
            source,
            source_state,
            error) ||
        !GetFileState(
            destination,
            destination_state,
            error)) {
        return false;
    }
    if (source_state.directory ||
        source_state.reparse_point ||
        source_state.delete_pending ||
        source_state.link_count != 1 ||
        destination_state.directory ||
        destination_state.reparse_point ||
        destination_state.delete_pending ||
        destination_state.link_count != 1) {
        error =
            "Exact wallet lifecycle copy requires two live single-link regular files.";
        return false;
    }
    if (SameIdentity(
            source_state.identity,
            destination_state.identity)) {
        error =
            "Refusing to copy a wallet lifecycle file onto the same file identity.";
        return false;
    }
    if (!TruncateFile(
            destination,
            0,
            error)) {
        return false;
    }

    CleansedBuffer buffer(COPY_BUFFER_SIZE);
    uint64_t offset = 0;
    while (offset < source_state.size) {
        const size_t count =
            static_cast<size_t>(
                std::min<uint64_t>(
                    source_state.size - offset,
                    buffer.Size()));
        if (!ReadExact(
                source,
                offset,
                buffer.Data(),
                count,
                error) ||
            !WriteExact(
                destination,
                offset,
                buffer.Data(),
                count,
                error)) {
            return false;
        }
        offset += count;
    }
    return TruncateFile(
        destination,
        source_state.size,
        error);
}

bool FileContentsEqual(
    const File& first,
    const File& second,
    bool& equal,
    std::string& error)
{
    equal = false;
    error.clear();
    FileState first_state;
    FileState second_state;
    if (!GetFileState(
            first,
            first_state,
            error) ||
        !GetFileState(
            second,
            second_state,
            error)) {
        return false;
    }
    if (first_state.directory ||
        first_state.reparse_point ||
        first_state.identity.inode == 0 ||
        first_state.link_count > 1 ||
        second_state.directory ||
        second_state.reparse_point ||
        second_state.identity.inode == 0 ||
        second_state.link_count > 1) {
        error =
            "Exact wallet lifecycle comparison requires two retained regular files without additional hard links.";
        return false;
    }
    if (first_state.size !=
        second_state.size) {
        return true;
    }

    CleansedBuffer first_buffer(COPY_BUFFER_SIZE);
    CleansedBuffer second_buffer(COPY_BUFFER_SIZE);
    uint64_t offset = 0;
    while (offset < first_state.size) {
        const size_t count =
            static_cast<size_t>(
                std::min<uint64_t>(
                    first_state.size - offset,
                    first_buffer.Size()));
        if (!ReadExact(
                first,
                offset,
                first_buffer.Data(),
                count,
                error) ||
            !ReadExact(
                second,
                offset,
                second_buffer.Data(),
                count,
                error)) {
            return false;
        }
        if (!std::equal(
                first_buffer.Data(),
                first_buffer.Data() + count,
                second_buffer.Data())) {
            return true;
        }
        offset += count;
    }
    equal = true;
    return true;
}

MoveResult MoveFileNoReplace(
    const fs::path& source_path,
    const File& source,
    const DatabaseFileIdentity& source_identity,
    const fs::path& destination_path,
    std::string& error)
{
    MoveResult result;
    error.clear();
    std::wstring source_full;
    std::wstring destination_full;
    if (!NormalizePath(
            source_path,
            source_full,
            error) ||
        !NormalizePath(
            destination_path,
            destination_full,
            error)) {
        return result;
    }
    if (source_full == destination_full) {
        error =
            "Refusing a wallet lifecycle no-replace move whose source and destination paths are identical.";
        return result;
    }

    FileState retained_state;
    if (!ValidateRetainedFile(
            source,
            source_full,
            source_identity,
            SecurityPolicy::PRIVATE,
            false,
            retained_state,
            error) ||
        InspectPathIdentityInternal(
            source_full,
            source_identity,
            error) != IdentityState::MATCH ||
        !ValidateDestinationVolume(
            destination_full,
            source_identity,
            error) ||
        !FlushFile(
            source,
            error)) {
        ReconcileNoReplace(
            source_full,
            source,
            source_identity,
            destination_full,
            ERROR_SUCCESS,
            false,
            result);
        return result;
    }

    const std::wstring source_native =
        Win32ExtendedPath(source_full);
    const std::wstring destination_native =
        Win32ExtendedPath(destination_full);
    const bool moved =
        MoveFileExW(
            source_native.c_str(),
            destination_native.c_str(),
            MOVEFILE_WRITE_THROUGH) != FALSE;
    const DWORD native_error =
        moved ?
            ERROR_SUCCESS :
            GetLastError();
    ReconcileNoReplace(
        source_full,
        source,
        source_identity,
        destination_full,
        native_error,
        moved,
        result);

    if (result.disposition ==
        MoveDisposition::MOVED) {
        std::string final_error;
        if (OpenAndFlushFinal(
                destination_path,
                source_identity,
                final_error)) {
            result.write_through_confirmed = true;
            error.clear();
            return result;
        }
        result.disposition =
            MoveDisposition::INDETERMINATE;
        error =
            "Wallet lifecycle file moved to '" +
            Utf8ForError(destination_full) +
            "', but final identity/security/flush verification failed: " +
            final_error;
        return result;
    }
    if (result.disposition ==
        MoveDisposition::COLLISION) {
        error =
            "Wallet lifecycle destination '" +
            Utf8ForError(destination_full) +
            "' already exists; the owned source remains retained.";
    } else if (!moved) {
        SetMoveError(
            "Failed to perform write-through no-replace wallet lifecycle move",
            source_full,
            destination_full,
            native_error,
            error);
    } else {
        error =
            "Write-through no-replace wallet lifecycle move reported success, but exact path identities could not be reconciled.";
    }
    return result;
}

MoveResult MoveFileReplace(
    const fs::path& source_path,
    const File& source,
    const DatabaseFileIdentity& source_identity,
    const fs::path& destination_path,
    const File& replaced,
    const DatabaseFileIdentity& replaced_identity,
    SecurityPolicy replaced_policy,
    std::string& error)
{
    MoveResult result;
    error.clear();
    std::wstring source_full;
    std::wstring destination_full;
    if (!NormalizePath(
            source_path,
            source_full,
            error) ||
        !NormalizePath(
            destination_path,
            destination_full,
            error)) {
        return result;
    }
    if (source_full == destination_full ||
        SameIdentity(
            source_identity,
            replaced_identity)) {
        error =
            "Refusing a wallet lifecycle replacement with identical source and destination identity.";
        return result;
    }

    FileState source_state;
    FileState replaced_state;
    if (!ValidateRetainedFile(
            source,
            source_full,
            source_identity,
            SecurityPolicy::PRIVATE,
            false,
            source_state,
            error) ||
        !ValidateRetainedFile(
            replaced,
            destination_full,
            replaced_identity,
            replaced_policy,
            false,
            replaced_state,
            error) ||
        InspectPathIdentityInternal(
            source_full,
            source_identity,
            error) != IdentityState::MATCH ||
        InspectPathIdentityInternal(
            destination_full,
            replaced_identity,
            error) != IdentityState::MATCH ||
        !ValidateDestinationVolume(
            destination_full,
            source_identity,
            error) ||
        source_identity.device !=
            replaced_identity.device ||
        !FlushFile(
            source,
            error)) {
        if (error.empty() &&
            source_identity.device !=
                replaced_identity.device) {
            error =
                "Refusing a wallet lifecycle replacement across NTFS volumes.";
        }
        ReconcileReplace(
            source_full,
            source,
            source_identity,
            destination_full,
            replaced,
            replaced_identity,
            ERROR_SUCCESS,
            false,
            result);
        return result;
    }

    const std::wstring source_native =
        Win32ExtendedPath(source_full);
    const std::wstring destination_native =
        Win32ExtendedPath(destination_full);
    const bool moved =
        MoveFileExW(
            source_native.c_str(),
            destination_native.c_str(),
            MOVEFILE_REPLACE_EXISTING |
                MOVEFILE_WRITE_THROUGH) != FALSE;
    const DWORD native_error =
        moved ?
            ERROR_SUCCESS :
            GetLastError();
    ReconcileReplace(
        source_full,
        source,
        source_identity,
        destination_full,
        replaced,
        replaced_identity,
        native_error,
        moved,
        result);

    if (result.disposition ==
        MoveDisposition::MOVED) {
        std::string final_error;
        if (OpenAndFlushFinal(
                destination_path,
                source_identity,
                final_error)) {
            result.write_through_confirmed = true;
            error.clear();
            return result;
        }
        result.disposition =
            MoveDisposition::INDETERMINATE;
        error =
            "Wallet lifecycle replacement reached the destination, but final identity/security/flush verification failed: " +
            final_error;
        return result;
    }
    if (!moved) {
        SetMoveError(
            "Failed to perform write-through wallet lifecycle replacement",
            source_full,
            destination_full,
            native_error,
            error);
    } else {
        error =
            "Write-through wallet lifecycle replacement reported success, but exact source, destination, and delete-pending identities could not be reconciled.";
    }
    return result;
}

DeleteResult MarkDeletePendingExact(
    const fs::path& path,
    const DatabaseFileIdentity& expected,
    SecurityPolicy policy,
    const File* retained,
    std::string& error)
{
    DeleteResult result;
    error.clear();
    std::wstring full;
    if (!NormalizePath(
            path,
            full,
            error)) {
        return result;
    }
    result.path =
        InspectPathIdentityInternal(
            full,
            expected,
            error);
    if (result.path ==
        IdentityState::ABSENT) {
        result.retained_handle =
            retained ?
                InspectHandleIdentity(
                    *retained,
                    expected,
                    error) :
                IdentityState::ABSENT;
        if (retained &&
            result.retained_handle !=
                IdentityState::MATCH) {
            result.disposition =
                DeleteDisposition::INDETERMINATE;
            return result;
        }
        result.disposition =
            DeleteDisposition::ABSENT;
        error.clear();
        return result;
    }
    if (result.path ==
        IdentityState::OTHER) {
        result.disposition =
            DeleteDisposition::NOT_OWNED;
        return result;
    }
    if (result.path !=
        IdentityState::MATCH) {
        return result;
    }

    if (retained) {
        result.retained_handle =
            InspectHandleIdentity(
                *retained,
                expected,
                error);
        if (result.retained_handle !=
            IdentityState::MATCH) {
            result.disposition =
                DeleteDisposition::NOT_OWNED;
            return result;
        }
    } else {
        result.retained_handle =
            IdentityState::ABSENT;
    }

    if (!ValidateDirectoryPath(
            ParentPath(full),
            policy != SecurityPolicy::DISCOVERY,
            nullptr,
            error)) {
        return result;
    }
    const std::wstring native =
        Win32ExtendedPath(full);
    ScopedHandle cleanup(CreateFileW(
        native.c_str(),
        DELETE |
            FILE_READ_ATTRIBUTES |
            READ_CONTROL,
        FILE_SHARE_READ |
            FILE_SHARE_WRITE |
            FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS |
            FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (!cleanup) {
        result.native_error = GetLastError();
        error = WindowsError(
            "Failed to open exact-owned wallet lifecycle file for delete-pending cleanup",
            full,
            result.native_error);
        return result;
    }

    FileState cleanup_state;
    DWORD native_error = ERROR_SUCCESS;
    if (!QueryFileState(
            cleanup.Get(),
            cleanup_state,
            native_error)) {
        result.native_error =
            native_error;
        error = WindowsError(
            "Failed to inspect exact-owned wallet lifecycle cleanup handle",
            full,
            native_error);
        return result;
    }
    if (!SameIdentity(
            cleanup_state.identity,
            expected) ||
        !ValidateCommonFileState(
            cleanup_state,
            full,
            true,
            true,
            false,
            error) ||
        !ValidateLocalNtfs(
            cleanup.Get(),
            full,
            error) ||
        !ValidateHandleAcl(
            cleanup.Get(),
            ToAclPolicy(policy),
            full,
            error)) {
        result.disposition =
            DeleteDisposition::NOT_OWNED;
        return result;
    }

    if (!SetDeletePending(
            cleanup.Get(),
            native_error)) {
        result.native_error =
            native_error;
        const std::string delete_error = WindowsError(
            "Failed to mark exact-owned wallet lifecycle file delete-pending",
            full,
            native_error);
        std::string reconciliation_error;
        result.path =
            InspectPathIdentityInternal(
                full,
                expected,
                reconciliation_error);
        error = delete_error;
        if (!reconciliation_error.empty()) {
            error += " Path reconciliation also failed: ";
            error += reconciliation_error;
        }
        return result;
    }
    if (!QueryFileState(
            cleanup.Get(),
            cleanup_state,
            native_error) ||
        !SameIdentity(
            cleanup_state.identity,
            expected) ||
        !cleanup_state.delete_pending) {
        result.native_error =
            native_error;
        error =
            "Wallet lifecycle cleanup returned success, but exact delete-pending identity could not be verified.";
        return result;
    }

    result.delete_pending = true;
    result.disposition =
        DeleteDisposition::DELETE_PENDING;
    result.path =
        InspectPathIdentityInternal(
            full,
            expected,
            error);
    if (retained) {
        FileState retained_state;
        std::string retained_error;
        if (!GetFileState(
                *retained,
                retained_state,
                retained_error) ||
            !SameIdentity(
                retained_state.identity,
                expected) ||
            !retained_state.delete_pending) {
            result.disposition =
                DeleteDisposition::INDETERMINATE;
            result.retained_handle =
                IdentityState::FAILED;
            error =
                "Exact wallet lifecycle file was marked delete-pending, but the retained owner handle did not confirm that state.";
            if (!retained_error.empty()) {
                error += " " + retained_error;
            }
            return result;
        }
        result.retained_handle =
            IdentityState::MATCH;
    }

    // No supported ordinary-user Windows API can durably flush the directory
    // entry removal. The explicit false field prevents callers from reporting
    // stronger cleanup durability than Windows provides here.
    result.namespace_durable = false;
    error.clear();
    return result;
}

} // namespace win32
} // namespace wallet
