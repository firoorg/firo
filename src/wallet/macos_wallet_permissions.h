// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_WALLET_MACOS_WALLET_PERMISSIONS_H
#define FIRO_WALLET_MACOS_WALLET_PERMISSIONS_H

#ifdef __APPLE__

#include "fs.h"

#include <cerrno>
#include <fcntl.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace wallet::macos
{
inline bool HasSafeACLProperties(filesec_t security, bool directory) noexcept
{
    // Darwin can report successful fstatx_np after an ACL-buffer allocation
    // failure without populating filesec. Do not mistake that for no ACL.
    if (!security || filesec_get_property(security, FILESEC_MODE, nullptr) != 0) {
        return false;
    }
    int present = 0;
    acl_t acl = nullptr;
    const bool inspected =
        filesec_query_property(security, FILESEC_ACL, &present) == 0 &&
        (!present || filesec_get_property(security, FILESEC_ACL, &acl) == 0);
    if (!inspected || (present && !acl)) {
        if (acl) {
            acl_free(acl);
        }
        return false;
    }
    if (!present) {
        return true;
    }

    bool safe = acl_valid(acl) == 0;
    int entry_id = ACL_FIRST_ENTRY;
    while (safe) {
        acl_entry_t entry;
        // Darwin returns 0 for an entry and -1/EINVAL at the end, even
        // for an empty ACL. This is not Linux's 1/0 iteration convention.
        errno = 0;
        if (acl_get_entry(acl, entry_id, &entry) != 0) {
            safe = errno == EINVAL;
            break;
        }
        entry_id = ACL_NEXT_ENTRY;
        acl_tag_t tag;
        if (acl_get_tag_type(entry, &tag) != 0) {
            safe = false;
            break;
        }
        if (tag == ACL_EXTENDED_DENY) {
            continue;
        }
        acl_permset_mask_t permissions = 0;
        acl_flagset_t flags;
        if (tag != ACL_EXTENDED_ALLOW ||
            acl_get_permset_mask_np(entry, &permissions) != 0 ||
            acl_get_flagset_np(entry, &flags) != 0) {
            safe = false;
            break;
        }
        const int file_inherit = acl_get_flag_np(flags, ACL_ENTRY_FILE_INHERIT);
        if (file_inherit < 0) {
            safe = false;
            break;
        }
        // Do not resolve principals or rely on preceding deny ACEs. Reject
        // data/control grants, including inherit-only grants to new journals.
        acl_permset_mask_t allowed = ACL_READ_ATTRIBUTES | ACL_READ_EXTATTRIBUTES |
                                    ACL_READ_SECURITY | ACL_SYNCHRONIZE | ACL_EXECUTE;
        if (directory && !file_inherit) {
            allowed |= ACL_LIST_DIRECTORY;
        }
        safe = (permissions & ~allowed) == 0;
    }
    acl_free(acl);
    return safe;
}

inline bool HasSafeACL(int descriptor, bool directory) noexcept
{
    filesec_t security = filesec_init();
    if (!security) {
        return false;
    }
    struct stat metadata{};
    const bool safe = fstatx_np(descriptor, &metadata, security) == 0 &&
                      HasSafeACLProperties(security, directory);
    filesec_free(security);
    return safe;
}

inline bool PathHasSafeACL(const fs::path& path, bool directory)
{
    const std::string name = path.string();
    const int descriptor = open(name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW |
                                                O_NONBLOCK | (directory ? O_DIRECTORY : 0));
    if (descriptor < 0) {
        return false;
    }
    struct stat retained{}, named{};
    const bool safe = fstat(descriptor, &retained) == 0 &&
                      lstat(name.c_str(), &named) == 0 &&
                      (directory ? S_ISDIR(retained.st_mode) : S_ISREG(retained.st_mode)) &&
                      retained.st_dev == named.st_dev && retained.st_ino == named.st_ino &&
                      HasSafeACL(descriptor, directory);
    const int closed = close(descriptor);
    return safe && closed == 0;
}

inline bool DirectoryACLsSafe(const fs::path& directory)
{
    fs::path current = fs::absolute(directory);
    while (true) {
        if (!PathHasSafeACL(current, true)) {
            return false;
        }
        const fs::path parent = current.parent_path();
        if (parent.empty() || parent == current) {
            return true;
        }
        current = parent;
    }
}
} // namespace wallet::macos

#endif // __APPLE__
#endif // FIRO_WALLET_MACOS_WALLET_PERMISSIONS_H
