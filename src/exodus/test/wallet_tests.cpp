// Copyright (c) 2019 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "../property.h"
#include "../sigma.h"
#include "../sigmadb.h"
#include "../wallet.h"
#include "../walletmodels.h"

#include "../../wallet/test/wallet_test_fixture.h"

#include <boost/optional/optional_io.hpp>
#include <boost/test/unit_test.hpp>

#include <iterator>
#include <ostream>
#include <stdexcept>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

namespace std {

template<class Char, class Traits, unsigned Size>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const base_blob<Size>& v)
{
    return os << v.GetHex();
}

} // namespace std

namespace exodus {

struct WalletTestingSetup : ::WalletTestingSetup
{
    SigmaDatabase sigmaDb;
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
    BOOST_CHECK_EQUAL(id, mint.id);

    BOOST_CHECK(mint.spendTx.IsNull());
    BOOST_CHECK_EQUAL(mint.chainState, SigmaMintChainState());
    BOOST_CHECK(mint.id.key.IsValid());
    BOOST_CHECK_NE(mint.id.key, SigmaPublicKey());

    auto priv = wallet.GetKey(mint);
    SigmaPublicKey pub(priv);
    BOOST_CHECK_EQUAL(mint.id.key, pub);

    auto another = CreateSigmaMint(1, 1);

    BOOST_CHECK_NE(another, mint);
}

BOOST_AUTO_TEST_CASE(sigma_mint_create_multi)
{
    std::vector<DenominationId> denominations = {0, 1, 0, 2};
    std::vector<SigmaMintId> ids(5);
    std::unordered_set<SigmaMint> mints;

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
        BOOST_CHECK_EQUAL(id.key, mint.id.key);

        BOOST_CHECK(mint.spendTx.IsNull());
        BOOST_CHECK_EQUAL(mint.id.property, id.property);
        BOOST_CHECK_EQUAL(mint.id.denomination, id.denomination);
        BOOST_CHECK_EQUAL(mint.chainState, SigmaMintChainState());
        BOOST_CHECK(mint.id.key.IsValid());
        BOOST_CHECK_NE(mint.id.key, SigmaPublicKey());

        BOOST_CHECK(mints.insert(std::move(mint)).second);

        auto priv = wallet.GetKey(mint);
        SigmaPublicKey pub(priv);
        BOOST_CHECK_EQUAL(pub, mint.id.key);
    }
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

    // List mints.
    std::unordered_set<SigmaMint> mints;

    wallet.ListSigmaMints(std::inserter(mints, mints.end()));

    BOOST_CHECK_EQUAL(mints.size(), ids.size());

    for (auto& mint : mints) {
        auto it = ids.find(mint.id);

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

    BOOST_CHECK_EQUAL(wallet.HasSigmaMint(owned), true);
    BOOST_CHECK_EQUAL(wallet.HasSigmaMint(other), false);
}

BOOST_AUTO_TEST_CASE(sigma_mint_get)
{
    // Get existence.
    auto owned = wallet.CreateSigmaMint(1, 1);
    auto mint = wallet.GetSigmaMint(owned);

    BOOST_CHECK_EQUAL(owned, mint.id);

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
    auto tx = uint256S("64c4c22a45ad449be61c52a431d11e81f7fd0ee2f2235bf02944fb0b3dd07adb");
    auto id = wallet.CreateSigmaMint(1, 1);
    SigmaMint mint;

    wallet.SetSigmaMintUsedTransaction(id, tx);
    mint = wallet.GetSigmaMint(id);
    BOOST_CHECK_EQUAL(mint.spendTx, tx);

    wallet.SetSigmaMintUsedTransaction(id, uint256());
    mint = wallet.GetSigmaMint(id);
    BOOST_CHECK(mint.spendTx.IsNull());
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
    BOOST_CHECK_EQUAL(wallet.GetSpendableSigmaMint(3, 0), boost::none);
}

BOOST_AUTO_TEST_CASE(get_a_spendable_coin)
{
    auto id = wallet.CreateSigmaMint(3, 0);
    sigmaDb.RecordMint(3, 0, id.key, 1000);

    BOOST_CHECK_NE(wallet.GetSpendableSigmaMint(3, 0), boost::none);
}

BOOST_AUTO_TEST_CASE(get_oldest_spenable_mint)
{
    auto id1 = wallet.CreateSigmaMint(3, 0);
    auto id2 = wallet.CreateSigmaMint(3, 0);

    sigmaDb.RecordMint(3, 0, id1.key, 1000);
    sigmaDb.RecordMint(3, 0, id2.key, 1001);

    auto mint = wallet.GetSpendableSigmaMint(3, 0);

    BOOST_CHECK_NE(mint, boost::none);
    BOOST_CHECK_EQUAL((*mint).chainState.block, 1000);
}

BOOST_AUTO_TEST_CASE(have_only_spend_coin)
{
    auto id = wallet.CreateSigmaMint(3, 0);

    sigmaDb.RecordMint(3, 0, id.key, 1000);

    wallet.SetSigmaMintUsedTransaction(id, uint256S("890e968f9b65dbacd576100c9b1c446f06471ed27df845ab7a24931cb640b388"));

    BOOST_CHECK_EQUAL(wallet.GetSpendableSigmaMint(3, 0), boost::none);
}

BOOST_AUTO_TEST_SUITE_END()

}
