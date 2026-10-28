// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/test/wallet_test_fixture.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>

namespace {
class ReadableWalletDB : public CWalletDB
{
public:
    using CWalletDB::CWalletDB;
    using CDB::Read;
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

BOOST_AUTO_TEST_SUITE_END()
