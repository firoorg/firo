// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "config/bitcoin-config.h"

#if defined(__APPLE__) && defined(USE_SQLITE)

#include "test/test_bitcoin.h"
#include "test/testutil.h"
#include "util.h"
#include "wallet/database.h"
#include "wallet/macos_wallet_permissions.h"
#include "wallet/sqlite.h"

#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>

#include <initializer_list>
#include <iterator>
#include <memory>
#include <membership.h>
#include <string>
#include <utility>
#include <uuid/uuid.h>

namespace
{
struct TestACE {
    acl_tag_t tag;
    acl_permset_mask_t permissions;
    std::initializer_list<acl_flag_t> flags{};
};

class TestACL final
{
    const fs::path m_path;
    acl_t m_original;

public:
    explicit TestACL(fs::path path)
        : m_path(std::move(path)),
          m_original(acl_get_file(m_path.string().c_str(), ACL_TYPE_EXTENDED))
    {
        if (!m_original && errno == ENOENT) {
            m_original = acl_init(0);
        }
        BOOST_REQUIRE(m_original);
    }

    ~TestACL()
    {
        acl_set_file(m_path.string().c_str(), ACL_TYPE_EXTENDED, m_original);
        acl_free(m_original);
    }

    void Set(std::initializer_list<TestACE> entries)
    {
        acl_t acl = acl_init(static_cast<int>(entries.size()));
        BOOST_REQUIRE(acl);
        uuid_t everyone;
        // Darwin's built-in "everyone" group has gid 12.
        bool success = mbr_gid_to_uuid(12, everyone) == 0;
        for (const auto& item : entries) {
            acl_entry_t entry;
            acl_flagset_t flags;
            success = success && acl_create_entry(&acl, &entry) == 0 &&
                      acl_set_tag_type(entry, item.tag) == 0 &&
                      acl_set_qualifier(entry, everyone) == 0 &&
                      acl_set_permset_mask_np(entry, item.permissions) == 0 &&
                      acl_get_flagset_np(entry, &flags) == 0;
            if (!success) {
                break;
            }
            for (const auto flag : item.flags) {
                success = success && acl_add_flag_np(flags, flag) == 0;
            }
        }
        success = success && acl_set_file(m_path.string().c_str(), ACL_TYPE_EXTENDED, acl) == 0;
        acl_free(acl);
        BOOST_REQUIRE(success);
    }

    TestACL(const TestACL&) = delete;
    TestACL& operator=(const TestACL&) = delete;
};

class MacOSWalletPermissionsSetup : public BasicTestingSetup
{
    const std::string m_previous_datadir;

public:
    const fs::path directory;

    MacOSWalletPermissionsSetup()
        : m_previous_datadir(GetArg("-datadir", "")),
          directory(fs::canonical(GetTempPath()) / fs::unique_path("macos-wallet-acl-%%%%-%%%%"))
    {
        BOOST_REQUIRE(fs::create_directory(directory));
        BOOST_REQUIRE_EQUAL(chmod(directory.string().c_str(), 0700), 0);
        ForceSetArg("-datadir", directory.string());
        ClearDatadirCache();
    }

    ~MacOSWalletPermissionsSetup()
    {
        ForceSetArg("-datadir", m_previous_datadir);
        ClearDatadirCache();
        boost::system::error_code ignored;
        fs::remove_all(directory, ignored);
    }
};

std::string ReadBytes(const fs::path& path)
{
    fs::ifstream file(path, std::ios::binary);
    BOOST_REQUIRE(file.is_open());
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

std::unique_ptr<WalletDatabase> OpenWallet(const std::string& name, bool create, std::string& error)
{
    DatabaseOptions options;
    options.require_create = create;
    options.require_existing = !create;
    options.require_format = DatabaseFormat::SQLITE;
    options.recover = false;
    DatabaseStatus status;
    return MakeSQLiteDatabase(name, options, status, error);
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(macos_wallet_permissions_tests, MacOSWalletPermissionsSetup)

BOOST_AUTO_TEST_CASE(missing_filesec_metadata_is_rejected)
{
    filesec_t security = filesec_init();
    BOOST_REQUIRE(security);
    BOOST_SCOPE_EXIT_ALL(&) { filesec_free(security); };

    int present = -1;
    BOOST_REQUIRE_EQUAL(filesec_query_property(security, FILESEC_ACL, &present), 0);
    BOOST_CHECK_EQUAL(present, 0);
    // This is the unpopulated result left by Darwin's failed buffer growth.
    BOOST_CHECK(!wallet::macos::HasSafeACLProperties(security, false));
    BOOST_CHECK(!wallet::macos::HasSafeACLProperties(security, true));

    const mode_t mode = S_IFREG | 0600;
    BOOST_REQUIRE_EQUAL(filesec_set_property(security, FILESEC_MODE, &mode), 0);
    BOOST_CHECK(wallet::macos::HasSafeACLProperties(security, false));
    BOOST_CHECK(wallet::macos::HasSafeACLProperties(security, true));
}

BOOST_AUTO_TEST_CASE(apple_acl_iteration_and_deny_only)
{
    const fs::path path = directory / "acl.dat";
    const int descriptor = open(path.string().c_str(), O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    BOOST_REQUIRE(descriptor >= 0);
    BOOST_REQUIRE_EQUAL(close(descriptor), 0);
    TestACL acl(path);
    acl.Set({});
    BOOST_CHECK(wallet::macos::PathHasSafeACL(path, false));

    acl_t empty = acl_init(0);
    BOOST_REQUIRE(empty);
    acl_entry_t entry;
    errno = 0;
    const int result = acl_get_entry(empty, ACL_FIRST_ENTRY, &entry);
    const int saved_errno = errno;
    acl_free(empty);
    BOOST_CHECK_EQUAL(result, -1);
    BOOST_CHECK_EQUAL(saved_errno, EINVAL);

    acl.Set({{ACL_EXTENDED_DENY, ACL_DELETE}});
    BOOST_CHECK(wallet::macos::PathHasSafeACL(path, false));
    acl_t deny = acl_get_file(path.string().c_str(), ACL_TYPE_EXTENDED);
    BOOST_REQUIRE(deny);
    BOOST_CHECK_EQUAL(acl_get_entry(deny, ACL_FIRST_ENTRY, &entry), 0);
    errno = 0;
    const int end_result = acl_get_entry(deny, ACL_NEXT_ENTRY, &entry);
    const int end_errno = errno;
    acl_free(deny);
    BOOST_CHECK_EQUAL(end_result, -1);
    BOOST_CHECK_EQUAL(end_errno, EINVAL);

    acl.Set({{ACL_EXTENDED_DENY, ACL_DELETE}, {ACL_EXTENDED_ALLOW, ACL_READ_DATA}});
    BOOST_CHECK(!wallet::macos::PathHasSafeACL(path, false));
    acl.Set({{ACL_EXTENDED_ALLOW, ACL_READ_ATTRIBUTES | ACL_READ_SECURITY}});
    BOOST_CHECK(wallet::macos::PathHasSafeACL(path, false));
    BOOST_CHECK(!wallet::macos::HasSafeACL(-1, false));
}

BOOST_AUTO_TEST_CASE(inheritance_rejected_before_creation_or_backup)
{
    std::string error;
    auto source = OpenWallet("source.dat", true, error);
    BOOST_REQUIRE_MESSAGE(source, error);
    {
        auto batch = source->MakeBatch();
        BOOST_REQUIRE(batch->Write(std::string("test-key"), std::string("test-value")));
    }
    const fs::path destination = directory / "backups";
    BOOST_REQUIRE(fs::create_directory(destination));
    BOOST_REQUIRE_EQUAL(chmod(destination.string().c_str(), 0700), 0);
    TestACL backup_acl(destination);
    backup_acl.Set({{ACL_EXTENDED_ALLOW, ACL_READ_DATA,
                     {ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_ONLY_INHERIT}}});
    BOOST_CHECK(!source->Backup((destination / "backup.dat").string(), error));
    BOOST_CHECK_MESSAGE(error.find("macOS ACL") != std::string::npos, error);
    BOOST_CHECK(fs::is_empty(destination));
    BOOST_CHECK(!ValidateWalletMigrationDirectory(destination, error));
    BOOST_CHECK(!wallet::macos::PathHasSafeACL(destination, true));

    backup_acl.Set({{ACL_EXTENDED_DENY, ACL_DELETE}});
    BOOST_REQUIRE_MESSAGE(source->Backup((destination / "private.dat").string(), error), error);
    BOOST_CHECK(wallet::macos::PathHasSafeACL(destination / "private.dat", false));
    source.reset();

    TestACL directory_acl(directory);
    directory_acl.Set({{ACL_EXTENDED_ALLOW, ACL_READ_DATA,
                        {ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_ONLY_INHERIT}}});
    BOOST_CHECK(!OpenWallet("rejected.dat", true, error));
    BOOST_CHECK_MESSAGE(error.find("macOS ACL") != std::string::npos, error);
    BOOST_CHECK(!fs::exists(directory / "rejected.dat"));
    for (const auto& item : fs::directory_iterator(directory)) {
        BOOST_CHECK(item.path().filename().string().find(".rejected.dat.sqlite-") != 0);
    }
}

BOOST_AUTO_TEST_CASE(existing_wallet_and_journal_acl_rejected_without_mutation)
{
    std::string error;
    auto source = OpenWallet("existing.dat", true, error);
    BOOST_REQUIRE_MESSAGE(source, error);
    source.reset();
    const fs::path path = directory / "existing.dat";
    const std::string original = ReadBytes(path);
    TestACL file_acl(path);
    file_acl.Set({{ACL_EXTENDED_ALLOW, ACL_READ_DATA}});
    struct stat metadata{};
    BOOST_REQUIRE_EQUAL(stat(path.string().c_str(), &metadata), 0);
    BOOST_CHECK_EQUAL(metadata.st_mode & 0777, 0600);
    BOOST_CHECK(!OpenWallet("existing.dat", false, error));
    BOOST_CHECK_MESSAGE(error.find("macOS ACL") != std::string::npos, error);
    BOOST_CHECK_EQUAL(ReadBytes(path), original);
    BOOST_CHECK(!wallet::macos::PathHasSafeACL(path, false));

    file_acl.Set({{ACL_EXTENDED_DENY, ACL_DELETE}});
    source = OpenWallet("existing.dat", false, error);
    BOOST_REQUIRE_MESSAGE(source, error);
    {
        auto batch = source->MakeBatch();
        BOOST_CHECK(batch->Write(std::string("deny-only"), std::string("still-writable")));
    }
    source.reset();
    const std::string before_journal = ReadBytes(path);
    const fs::path journal(path.string() + "-journal");
    const int descriptor = open(journal.string().c_str(), O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    BOOST_REQUIRE(descriptor >= 0);
    BOOST_REQUIRE_EQUAL(write(descriptor, "not-a-hot-journal", 17), 17);
    BOOST_REQUIRE_EQUAL(close(descriptor), 0);
    TestACL journal_acl(journal);
    journal_acl.Set({{ACL_EXTENDED_ALLOW, ACL_READ_DATA}});
    const std::string journal_before = ReadBytes(journal);
    BOOST_CHECK(!OpenWallet("existing.dat", false, error));
    BOOST_CHECK_MESSAGE(error.find("rollback journal") != std::string::npos, error);
    BOOST_CHECK_MESSAGE(error.find("macOS ACL") != std::string::npos, error);
    BOOST_CHECK_EQUAL(ReadBytes(path), before_journal);
    BOOST_CHECK_EQUAL(ReadBytes(journal), journal_before);
}

BOOST_AUTO_TEST_CASE(directory_control_grants_and_ancestor_acl_rejected)
{
    const fs::path child = directory / "child";
    BOOST_REQUIRE(fs::create_directory(child));
    BOOST_REQUIRE_EQUAL(chmod(child.string().c_str(), 0700), 0);
    TestACL parent_acl(directory);
    std::string error;
    for (const acl_permset_mask_t permission : {ACL_ADD_FILE, ACL_DELETE_CHILD, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER}) {
        parent_acl.Set({{ACL_EXTENDED_ALLOW, permission}});
        BOOST_CHECK(!ValidateWalletMigrationDirectory(child, error));
        BOOST_CHECK(!wallet::macos::DirectoryACLsSafe(child));
    }
    parent_acl.Set({{ACL_EXTENDED_DENY, ACL_DELETE}});
    BOOST_CHECK_MESSAGE(ValidateWalletMigrationDirectory(child, error), error);
    parent_acl.Set({{ACL_EXTENDED_ALLOW, ACL_LIST_DIRECTORY | ACL_SEARCH}});
    BOOST_CHECK_MESSAGE(ValidateWalletMigrationDirectory(child, error), error);
}

BOOST_AUTO_TEST_SUITE_END()

#endif // __APPLE__ && USE_SQLITE
