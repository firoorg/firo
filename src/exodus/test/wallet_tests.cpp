// Copyright (c) 2019 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "../property.h"
#include "../sigma.h"
#include "../sigmadb.h"
#include "../wallet.h"
#include "../walletmodels.h"

#include "../../wallet/test/wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <iterator>
#include <unordered_set>
#include <utility>
#include <vector>

namespace exodus {

struct WalletTestingSetup : ::WalletTestingSetup
{
    CMPMintList sigmaDb;
    Wallet wallet;

    WalletTestingSetup() :
        sigmaDb(pathTemp / "exodus_sigma_tests", true),
        wallet(pwalletMain->strWalletFile, sigmaDb)
    {
    }

    SigmaMint CreateSigmaMint(PropertyId property, DenominationId denomination)
    {
        auto id = wallet.CreateSigmaMint(property, denomination);
        return wallet.GetSigmaMint(id);
    }
};

BOOST_FIXTURE_TEST_SUITE(exodus_wallet_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(sigma_mint_create_one)
{
    auto id = wallet.CreateSigmaMint(1, 1);
    auto mint = wallet.GetSigmaMint(id);

    BOOST_CHECK_EQUAL(id.property, 1);
    BOOST_CHECK_EQUAL(id.denomination, 1);
    BOOST_CHECK(id.key.IsValid());
    BOOST_CHECK_EQUAL(id.key, SigmaPublicKey(mint.key));

    BOOST_CHECK_EQUAL(mint.used, false);
    BOOST_CHECK_EQUAL(mint.property, id.property);
    BOOST_CHECK_EQUAL(mint.denomination, id.denomination);
    BOOST_CHECK_EQUAL(mint.chainState, SigmaMintChainState());
    BOOST_CHECK(mint.key.IsValid());
    BOOST_CHECK_NE(mint.key, SigmaPrivateKey());

    auto another = CreateSigmaMint(1, 1);

    BOOST_CHECK_NE(another, mint);
}

BOOST_AUTO_TEST_CASE(sigma_mint_create_multi)
{
    std::vector<DenominationId> denominations = {0, 1, 0, 2};
    std::vector<SigmaMintId> ids(5);
    std::vector<SigmaMint> mints;

    auto next = wallet.CreateSigmaMints(1, denominations.begin(), denominations.end(), ids.begin());

    BOOST_CHECK_EQUAL(std::distance(ids.begin(), next), 4);

    BOOST_CHECK_EQUAL(ids[0].denomination, 0);
    BOOST_CHECK_EQUAL(ids[1].denomination, 1);
    BOOST_CHECK_EQUAL(ids[2].denomination, 0);
    BOOST_CHECK_EQUAL(ids[3].denomination, 2);

    for (auto it = ids.begin(); it != next; it++) {
        auto& id = *it;
        auto mint = wallet.GetSigmaMint(id);

        BOOST_CHECK_EQUAL(id.property, 1);
        BOOST_CHECK(id.key.IsValid());
        BOOST_CHECK_EQUAL(id.key, SigmaPublicKey(mint.key));

        BOOST_CHECK_EQUAL(mint.used, false);
        BOOST_CHECK_EQUAL(mint.property, id.property);
        BOOST_CHECK_EQUAL(mint.denomination, id.denomination);
        BOOST_CHECK_EQUAL(mint.chainState, SigmaMintChainState());
        BOOST_CHECK(mint.key.IsValid());
        BOOST_CHECK_NE(mint.key, SigmaPrivateKey());

        mints.push_back(std::move(mint));
    }

    BOOST_CHECK(std::adjacent_find(mints.begin(), mints.end()) == mints.end());
}

BOOST_AUTO_TEST_CASE(sigma_mint_listing_all)
{
    // Create mints.
    std::unordered_set<SigmaMintId> ids;

    ids.insert(wallet.CreateSigmaMint(1, 0));
    ids.insert(wallet.CreateSigmaMint(2, 0));
    ids.insert(wallet.CreateSigmaMint(1, 1));
    ids.insert(wallet.CreateSigmaMint(2, 0));

    BOOST_CHECK_EQUAL(ids.size(), 4);
    BOOST_CHECK(std::adjacent_find(ids.begin(), ids.end()) == ids.end());

    // List mints.
    std::vector<SigmaMint> mints;
    wallet.ListSigmaMints(std::back_inserter(mints));

    BOOST_CHECK_EQUAL(mints.size(), ids.size());
    BOOST_CHECK(std::adjacent_find(mints.begin(), mints.end()) == mints.end());

    for (auto& mint : mints) {
        auto it = ids.find(SigmaMintId(mint));

        BOOST_CHECK(it != ids.end());
        BOOST_CHECK_EQUAL(mint, wallet.GetSigmaMint(*it));

        ids.erase(it);
    }

    BOOST_CHECK_EQUAL(ids.size(), 0);
}

BOOST_AUTO_TEST_CASE(sigma_mint_listing_specific_property)
{
    // Create mints.
    std::unordered_set<SigmaMintId> ids;

    wallet.CreateSigmaMint(1, 0);
    wallet.CreateSigmaMint(1, 1);

    ids.insert(wallet.CreateSigmaMint(2, 0));
    ids.insert(wallet.CreateSigmaMint(2, 0));

    BOOST_CHECK_EQUAL(ids.size(), 2);
    BOOST_CHECK(std::adjacent_find(ids.begin(), ids.end()) == ids.end());

    // List mints.
    std::vector<SigmaMint> mints;
    wallet.ListSigmaMints(2, std::back_inserter(mints));

    BOOST_CHECK_EQUAL(mints.size(), ids.size());
    BOOST_CHECK(std::adjacent_find(mints.begin(), mints.end()) == mints.end());

    for (auto& mint : mints) {
        auto it = ids.find(SigmaMintId(mint));

        BOOST_CHECK(it != ids.end());
        BOOST_CHECK_EQUAL(mint, wallet.GetSigmaMint(*it));

        ids.erase(it);
    }

    BOOST_CHECK_EQUAL(ids.size(), 0);
}

BOOST_AUTO_TEST_CASE(sigma_mint_check_existence)
{
    auto owned = wallet.CreateSigmaMint(1, 1);
    SigmaPrivateKey priv;
    SigmaPublicKey pub;

    priv.Generate();
    pub.Generate(priv);

    SigmaMintId other(1, 1, pub);

    BOOST_CHECK(wallet.HasSigmaMint(owned));
    BOOST_CHECK_EQUAL(wallet.HasSigmaMint(other), false);
}

BOOST_AUTO_TEST_CASE(sigma_mint_get)
{
    // Get existence.
    auto owned = wallet.CreateSigmaMint(1, 1);
    auto mint = wallet.GetSigmaMint(owned);

    BOOST_CHECK_EQUAL(owned, SigmaMintId(mint));

    // Get non-existence.
    SigmaPrivateKey priv;
    SigmaPublicKey pub;

    priv.Generate();
    pub.Generate(priv);

    SigmaMintId other(1, 1, pub);

    BOOST_CHECK_THROW(wallet.GetSigmaMint(other), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(sigma_mint_set_used)
{
    auto id = wallet.CreateSigmaMint(1, 1);
    SigmaMint mint;

    wallet.SetSigmaMintUsedStatus(id, true);
    mint = wallet.GetSigmaMint(id);
    BOOST_CHECK(mint.used);

    wallet.SetSigmaMintUsedStatus(id, false);
    mint = wallet.GetSigmaMint(id);
    BOOST_CHECK_EQUAL(mint.used, false);
}

BOOST_AUTO_TEST_CASE(sigma_mint_chainstate_owned)
{
    auto id = wallet.CreateSigmaMint(1, 0);
    MintGroupId group;
    MintGroupIndex index;
    SigmaMint mint;

    // Add.
    std::tie(group, index) = sigmaDb.RecordMint(1, 0, id.key, 100);
    mint = wallet.GetSigmaMint(id);

    BOOST_CHECK_EQUAL(mint.chainState.block, 100);
    BOOST_CHECK_EQUAL(mint.chainState.group, group);
    BOOST_CHECK_EQUAL(mint.chainState.index, index);

    // Remove.
    sigmaDb.DeleteAll(100);
    mint = wallet.GetSigmaMint(id);

    BOOST_CHECK_EQUAL(mint.chainState, SigmaMintChainState());
}

BOOST_AUTO_TEST_CASE(sigma_mint_chainstate_not_owned)
{
    // Add our mint first so we can test if the other mint does not alter our mint state.
    auto id = wallet.CreateSigmaMint(1, 0);
    MintGroupId group;
    MintGroupIndex index;

    std::tie(group, index) = sigmaDb.RecordMint(1, 0, id.key, 100);

    // Add other mint.
    SigmaPrivateKey otherPriv;
    SigmaPublicKey otherPub;

    otherPriv.Generate();
    otherPub.Generate(otherPriv);

    sigmaDb.RecordMint(1, 0, otherPub, 101);

    // Our chain state should not updated.
    SigmaMint mint;

    mint = wallet.GetSigmaMint(id);

    BOOST_CHECK_EQUAL(mint.chainState.block, 100);
    BOOST_CHECK_EQUAL(mint.chainState.group, group);
    BOOST_CHECK_EQUAL(mint.chainState.index, index);

    // Other mint should not added to our wallet.
    BOOST_CHECK_THROW(
        wallet.GetSigmaMint(SigmaMintId(1, 0, otherPub)),
        std::invalid_argument
    );

    // Remove other mint and our chain state should not updated.
    sigmaDb.DeleteAll(101);

    mint = wallet.GetSigmaMint(id);

    BOOST_CHECK_EQUAL(mint.chainState.block, 100);
    BOOST_CHECK_EQUAL(mint.chainState.group, group);
    BOOST_CHECK_EQUAL(mint.chainState.index, index);
}

BOOST_AUTO_TEST_CASE(get_spendable_mint_in_nonexist_group)
{
    LOCK(pwalletMain->cs_wallet);
    BOOST_CHECK(wallet.GetSpendableSigmaMint(0, 0) == boost::none);
}

BOOST_AUTO_TEST_CASE(get_a_spendable_coin)
{
    LOCK(pwalletMain->cs_wallet);
    auto id = wallet.CreateSigmaMint(0, 0);
    sigmaDb.RecordMint(0, 0, id.publicKey, 1000);

    BOOST_CHECK(wallet.GetSpendableSigmaMint(0, 0) != boost::none);
}

BOOST_AUTO_TEST_CASE(get_oldest_spenable_mint)
{
    LOCK(pwalletMain->cs_wallet);
    auto id = wallet.CreateSigmaMint(0, 0);
    auto id2 = wallet.CreateSigmaMint(0, 0);
    sigmaDb.RecordMint(0, 0, id.publicKey, 1000);
    sigmaDb.RecordMint(0, 0, id2.publicKey, 1001);

    auto mint = wallet.GetSpendableSigmaMint(0, 0);
    BOOST_CHECK(mint != boost::none);
    BOOST_CHECK_EQUAL(1000, mint.get().chainState.block);
}

BOOST_AUTO_TEST_CASE(have_only_spend_coin)
{
    LOCK(pwalletMain->cs_wallet);
    auto id = wallet.CreateSigmaMint(0, 0);
    sigmaDb.RecordMint(0, 0, id.publicKey, 1000);
    wallet.SetSigmaMintUsedTransaction(id, uint256S("1"));

    BOOST_CHECK(wallet.GetSpendableSigmaMint(0, 0) ==  boost::none);
}

BOOST_AUTO_TEST_SUITE_END()

}
