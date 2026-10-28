// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/test/wallet_test_fixture.h"
#include "wallet/wallet.h"

#include <cerrno>
#include <boost/filesystem.hpp>
#include <boost/signals2/connection.hpp>
#include <boost/test/unit_test.hpp>

namespace {
class ReadableWalletDB : public CWalletDB
{
public:
    using CWalletDB::CWalletDB;
    using CDB::Read;
};

// Inject failures through BDB's public method table, without production hooks.
class FailWalletWrite
{
    DB* db;
    decltype(DB::put) originalPut;
    decltype(DB::del) originalDel;
    void* originalPrivate;
    std::string type;

    static int Put(DB* db, DB_TXN* txn, DBT* key, DBT* value, u_int32_t flags)
    {
        auto& self = *static_cast<FailWalletWrite*>(db->app_private);
        CDataStream stream(static_cast<char*>(key->data), static_cast<char*>(key->data) + key->size, SER_DISK, CLIENT_VERSION);
        std::string type;
        stream >> type;
        if (type == self.type) {
            ++self.failures;
            return EIO;
        }
        return self.originalPut(db, txn, key, value, flags);
    }

    static int Del(DB* db, DB_TXN* txn, DBT* key, u_int32_t flags)
    {
        auto& self = *static_cast<FailWalletWrite*>(db->app_private);
        CDataStream stream(static_cast<char*>(key->data), static_cast<char*>(key->data) + key->size, SER_DISK, CLIENT_VERSION);
        std::string type;
        stream >> type;
        if (type == self.type) {
            ++self.failures;
            return EIO;
        }
        return self.originalDel(db, txn, key, flags);
    }

public:
    int failures = 0;

    FailWalletWrite(Db& handle, const std::string& recordType, bool erase = false)
        : db(handle.get_DB()), originalPut(db->put), originalDel(db->del), originalPrivate(db->app_private), type(recordType)
    {
        db->app_private = this;
        if (erase)
            db->del = Del;
        else
            db->put = Put;
    }

    ~FailWalletWrite()
    {
        db->put = originalPut;
        db->del = originalDel;
        db->app_private = originalPrivate;
    }
};

class FailRewriteOperation
{
    DB_ENV* env = bitdb.dbenv->get_DB_ENV();
    decltype(DB_ENV::txn_checkpoint) checkpoint = env->txn_checkpoint;
    decltype(DB_ENV::dbrename) rename = env->dbrename;
    void* originalPrivate = env->app_private;

    static int Checkpoint(DB_ENV* env, u_int32_t, u_int32_t, u_int32_t)
    {
        ++static_cast<FailRewriteOperation*>(env->app_private)->failures;
        return EIO;
    }
    static int Rename(DB_ENV* env, DB_TXN*, const char*, const char*, const char*, u_int32_t)
    {
        ++static_cast<FailRewriteOperation*>(env->app_private)->failures;
        return EIO;
    }

public:
    int failures = 0;
    explicit FailRewriteOperation(bool failRename)
    {
        env->app_private = this;
        if (failRename)
            env->dbrename = Rename;
        else
            env->txn_checkpoint = Checkpoint;
    }
    ~FailRewriteOperation()
    {
        env->txn_checkpoint = checkpoint;
        env->dbrename = rename;
        env->app_private = originalPrivate;
    }
};

class ReportCloseFailure
{
    DB* db;
    decltype(DB::close) originalClose;
    void* originalPrivate;
    static int Close(DB* db, u_int32_t flags)
    {
        auto& self = *static_cast<ReportCloseFailure*>(db->app_private);
        db->close = self.originalClose;
        db->app_private = self.originalPrivate;
        self.db = nullptr;
        ++self.failures;
        const int ret = self.originalClose(db, flags);
        return ret == 0 ? EIO : ret;
    }
public:
    int failures = 0;
    explicit ReportCloseFailure(Db& handle)
        : db(handle.get_DB()), originalClose(db->close), originalPrivate(db->app_private)
    {
        db->app_private = this;
        db->close = Close;
    }
    ~ReportCloseFailure()
    {
        if (db) {
            db->close = originalClose;
            db->app_private = originalPrivate;
        }
    }
};
}

BOOST_FIXTURE_TEST_SUITE(wallet_persistence_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(rewrite_discards_stale_copy)
{
    const std::string file = pwalletMain->strWalletFile;
    const auto changed = std::make_pair(std::string("name"), std::string("changed"));
    const auto removed = std::make_pair(std::string("name"), std::string("removed"));
    {
        CWalletDB source(file);
        BOOST_REQUIRE(source.WriteName("changed", "old label"));
        BOOST_REQUIRE(source.WriteName("removed", "old record"));
        // Model a partial copy left by an interrupted rewrite.
        CWalletDB partial(file + ".rewrite", "cr+");
        BOOST_REQUIRE(partial.WriteName("changed", "old label"));
        BOOST_REQUIRE(partial.WriteName("removed", "old record"));
        BOOST_REQUIRE(source.WriteName("changed", "new label"));
        BOOST_REQUIRE(source.EraseName("removed"));
    }
    bitdb.CloseDb(file + ".rewrite");
    bitdb.CheckpointLSN(file + ".rewrite");
    bitdb.mapFileUseCount.erase(file + ".rewrite");

    BOOST_REQUIRE(CDB::Rewrite(file));
    {
        ReadableWalletDB db(file);
        std::string value;
        BOOST_REQUIRE(db.Read(changed, value));
        BOOST_CHECK_EQUAL(value, "new label");
        BOOST_CHECK(!db.Read(removed, value));
    }
    BOOST_CHECK(!boost::filesystem::exists(GetDataDir() / (file + ".rewrite")));
    BOOST_REQUIRE(CDB::Rewrite(file));
}

BOOST_AUTO_TEST_CASE(rewrite_failure_preserves_source)
{
    const std::string file = pwalletMain->strWalletFile;
    const auto blocked = GetDataDir() / (file + ".rewrite");
    BOOST_REQUIRE(boost::filesystem::create_directory(blocked));
    {
        CWalletDB db(file);
        BOOST_REQUIRE(db.WriteName("retained", "must survive"));
    }
    BOOST_CHECK(!CDB::Rewrite(file));
    {
        ReadableWalletDB db(file);
        std::string value;
        BOOST_REQUIRE(db.Read(std::make_pair(std::string("name"), std::string("retained")), value));
        BOOST_CHECK_EQUAL(value, "must survive");
    }
    BOOST_REQUIRE(boost::filesystem::remove(blocked));
    BOOST_REQUIRE(CDB::Rewrite(file));
}

BOOST_AUTO_TEST_CASE(rewrite_reports_errors_and_preserves_source)
{
    const std::string file = pwalletMain->strWalletFile;
    {
        CWalletDB db(file);
        BOOST_REQUIRE(db.WriteName("retained", "must survive"));
    }
    {
        ReportCloseFailure failure(*bitdb.mapDb.at(file));
        BOOST_CHECK(!CDB::Rewrite(file));
        BOOST_CHECK_EQUAL(failure.failures, 1);
    }
    for (bool failRename : {false, true}) {
        {
            FailRewriteOperation failure(failRename);
            BOOST_CHECK(!CDB::Rewrite(file));
            BOOST_CHECK_EQUAL(failure.failures, 1);
        }
        BOOST_REQUIRE(boost::filesystem::exists(GetDataDir() / file));
        {
            ReadableWalletDB db(file);
            std::string value;
            BOOST_REQUIRE(db.Read(std::make_pair(std::string("name"), std::string("retained")), value));
            BOOST_CHECK_EQUAL(value, "must survive");
        }
        BOOST_REQUIRE(CDB::Rewrite(file));
    }
}

BOOST_AUTO_TEST_CASE(encryption_reports_failed_cleanup)
{
    const std::string file = pwalletMain->strWalletFile;
    const auto blocked = GetDataDir() / (file + ".rewrite");
    BOOST_REQUIRE(boost::filesystem::create_directory(blocked));
    CKey key;
    key.MakeNewKey(true);
    BOOST_REQUIRE(pwalletMain->AddKeyPubKey(key, key.GetPubKey()));
    const SecureString passphrase = "cleanup-test-passphrase";

    BOOST_CHECK(!pwalletMain->EncryptWallet(passphrase));
    BOOST_CHECK(pwalletMain->IsCrypted());
    BOOST_CHECK(pwalletMain->IsLocked());
    BOOST_REQUIRE(pwalletMain->Unlock(passphrase));
    CKey recovered;
    BOOST_REQUIRE(pwalletMain->GetKey(key.GetPubKey().GetID(), recovered));
    BOOST_CHECK(recovered == key);
    pwalletMain->Lock();

    bitdb.CloseDb(file);
    CWallet reloaded(file);
    bool firstRun = false;
    BOOST_REQUIRE(reloaded.LoadWallet(firstRun) == DB_LOAD_OK);
    BOOST_CHECK(reloaded.IsCrypted());
    BOOST_CHECK(reloaded.IsLocked());
    BOOST_REQUIRE(reloaded.Unlock(passphrase));
    BOOST_REQUIRE(reloaded.GetKey(key.GetPubKey().GetID(), recovered));
    BOOST_CHECK(recovered == key);
    BOOST_REQUIRE(boost::filesystem::remove(blocked));
    BOOST_REQUIRE(CDB::Rewrite(file));
}

BOOST_AUTO_TEST_CASE(spark_address_metadata_is_atomic)
{
    pwalletMain->sparkWallet->WaitForPendingTasks();
    LOCK(pwalletMain->cs_wallet);
    const auto address = pwalletMain->sparkWallet->getDefaultAddress().encode(spark::GetNetworkType());
    BOOST_REQUIRE(pwalletMain->SetSparkAddressBook(address, "original", "receive"));
    ReadableWalletDB db(pwalletMain->strWalletFile);
    int notifications = 0;
    boost::signals2::scoped_connection connection(pwalletMain->NotifySparkAddressBookChanged.connect(
        [&](CWallet*, const std::string&, const std::string&, bool, const std::string&, ChangeType) { ++notifications; }));

    for (const std::string type : {"purpose", "name"}) {
        FailWalletWrite failure(*bitdb.mapDb.at(pwalletMain->strWalletFile), type);
        BOOST_CHECK(!pwalletMain->SetSparkAddressBook(address, "lost label", "send"));
        BOOST_CHECK_EQUAL(failure.failures, 1);
        BOOST_CHECK_EQUAL(notifications, 0);
        BOOST_CHECK_EQUAL(pwalletMain->mapSparkAddressBook.at(address).name, "original");
        BOOST_CHECK_EQUAL(pwalletMain->mapSparkAddressBook.at(address).purpose, "receive");
        std::string value;
        BOOST_REQUIRE(db.Read(std::make_pair(std::string("name"), address), value));
        BOOST_CHECK_EQUAL(value, "original");
        BOOST_REQUIRE(db.Read(std::make_pair(std::string("purpose"), address), value));
        BOOST_CHECK_EQUAL(value, "receive");
    }

    BOOST_REQUIRE(pwalletMain->SetSparkAddressBook(address, "saved label", ""));
    BOOST_CHECK_EQUAL(notifications, 1);
    BOOST_CHECK_EQUAL(pwalletMain->mapSparkAddressBook.at(address).purpose, "receive");
    db.Close();
    bitdb.CloseDb(pwalletMain->strWalletFile);
    CWallet reloaded(pwalletMain->strWalletFile);
    bool firstRun = false;
    BOOST_REQUIRE(reloaded.LoadWallet(firstRun) == DB_LOAD_OK);
    BOOST_REQUIRE(reloaded.mapSparkAddressBook.count(address));
    BOOST_CHECK_EQUAL(reloaded.mapSparkAddressBook.at(address).name, "saved label");
    BOOST_CHECK_EQUAL(reloaded.mapSparkAddressBook.at(address).purpose, "receive");
}

BOOST_AUTO_TEST_CASE(spark_address_failed_creation_is_not_published)
{
    pwalletMain->sparkWallet->WaitForPendingTasks();
    LOCK(pwalletMain->cs_wallet);
    const auto address = pwalletMain->sparkWallet->generateNewAddress().encode(spark::GetNetworkType());
    ReadableWalletDB db(pwalletMain->strWalletFile);
    int notifications = 0;
    boost::signals2::scoped_connection connection(pwalletMain->NotifySparkAddressBookChanged.connect(
        [&](CWallet*, const std::string&, const std::string&, bool, const std::string&, ChangeType) { ++notifications; }));
    for (const std::string type : {"purpose", "name"}) {
        FailWalletWrite failure(*bitdb.mapDb.at(pwalletMain->strWalletFile), type);
        BOOST_CHECK(!pwalletMain->SetSparkAddressBook(address, "new label", "receive"));
        BOOST_CHECK_EQUAL(failure.failures, 1);
        BOOST_CHECK_EQUAL(notifications, 0);
        BOOST_CHECK(!pwalletMain->mapSparkAddressBook.count(address));
        std::string value;
        BOOST_CHECK(!db.Read(std::make_pair(std::string("name"), address), value));
        BOOST_CHECK(!db.Read(std::make_pair(std::string("purpose"), address), value));
    }
    BOOST_REQUIRE(pwalletMain->SetSparkAddressBook(address, "new label", "receive"));
    BOOST_CHECK_EQUAL(notifications, 1);
}

BOOST_AUTO_TEST_CASE(spark_address_replacement_is_atomic)
{
    pwalletMain->sparkWallet->WaitForPendingTasks();
    LOCK(pwalletMain->cs_wallet);
    const std::string file = pwalletMain->strWalletFile;
    const auto oldAddress = pwalletMain->sparkWallet->generateNewAddress().encode(spark::GetNetworkType());
    const auto newAddress = pwalletMain->sparkWallet->generateNewAddress().encode(spark::GetNetworkType());
    BOOST_REQUIRE(pwalletMain->SetSparkAddressBook(oldAddress, "original", "send"));
    pwalletMain->mapSparkAddressBook.at(oldAddress).destdata["test"] = "retained";
    ReadableWalletDB db(file);
    BOOST_REQUIRE(db.WriteDestData(oldAddress, "test", "retained"));
    int notifications = 0;
    boost::signals2::scoped_connection connection(pwalletMain->NotifySparkAddressBookChanged.connect(
        [&](CWallet*, const std::string&, const std::string&, bool, const std::string&, ChangeType) { ++notifications; }));

    for (bool erase : {false, true}) {
        for (const std::string type : {"name", "purpose"}) {
            FailWalletWrite failure(*bitdb.mapDb.at(file), type, erase);
            BOOST_CHECK(!pwalletMain->ReplaceSparkAddressBook(oldAddress, newAddress, "replacement", "send"));
            BOOST_CHECK_EQUAL(failure.failures, 1);
            BOOST_CHECK_EQUAL(notifications, 0);
            BOOST_CHECK_EQUAL(pwalletMain->mapSparkAddressBook.at(oldAddress).name, "original");
            BOOST_CHECK(!pwalletMain->mapSparkAddressBook.count(newAddress));
            std::string value;
            BOOST_REQUIRE(db.Read(std::make_pair(std::string("name"), oldAddress), value));
            BOOST_CHECK_EQUAL(value, "original");
            BOOST_REQUIRE(db.Read(std::make_pair(std::string("purpose"), oldAddress), value));
            BOOST_CHECK_EQUAL(value, "send");
            BOOST_REQUIRE(db.Read(std::make_pair(std::string("destdata"), std::make_pair(oldAddress, std::string("test"))), value));
            BOOST_CHECK_EQUAL(value, "retained");
            BOOST_CHECK(!db.Read(std::make_pair(std::string("name"), newAddress), value));
            BOOST_CHECK(!db.Read(std::make_pair(std::string("purpose"), newAddress), value));
        }
    }
    BOOST_REQUIRE(pwalletMain->ReplaceSparkAddressBook(oldAddress, newAddress, "replacement", "send"));
    BOOST_CHECK_EQUAL(notifications, 2);
    BOOST_CHECK(!pwalletMain->mapSparkAddressBook.count(oldAddress));
    BOOST_CHECK_EQUAL(pwalletMain->mapSparkAddressBook.at(newAddress).name, "replacement");
    db.Close();
    bitdb.CloseDb(file);
    CWallet reloaded(file);
    bool firstRun = false;
    BOOST_REQUIRE(reloaded.LoadWallet(firstRun) == DB_LOAD_OK);
    BOOST_CHECK(!reloaded.mapSparkAddressBook.count(oldAddress));
    BOOST_CHECK_EQUAL(reloaded.mapSparkAddressBook.at(newAddress).name, "replacement");
}

BOOST_AUTO_TEST_SUITE_END()
