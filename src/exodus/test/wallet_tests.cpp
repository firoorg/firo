// Copyright (c) 2019 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "../property.h"
#include "../sigmadb.h"
#include "../sigmaprimitives.h"
#include "../wallet.h"
#include "../walletmodels.h"

#include "../../wallet/wallet.h"
#include "../../wallet/walletexcept.h"

#include "../../wallet/test/wallet_test_fixture.h"

#include <boost/optional/optional_io.hpp>
#include <boost/test/unit_test.hpp>

#include <iterator>
#include <ostream>
#include <stdexcept>
#include <string>
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
    WalletTestingSetup()
    {
        sigmaDb = new SigmaDatabase(pathTemp / "exodus_sigma_tests", true, 10);
        wallet = new Wallet(pwalletMain->strWalletFile);
        wallet->ReloadMasterKey();
    }

    ~WalletTestingSetup()
    {
        delete wallet; wallet = nullptr;
        delete sigmaDb; sigmaDb = nullptr;
    }

    SigmaMint CreateSigmaMint(PropertyId property, SigmaDenomination denomination)
    {
        auto id = wallet->CreateSigmaMint(property, denomination);
        return wallet->GetSigmaMint(id);
    }
};

BOOST_FIXTURE_TEST_SUITE(exodus_wallet_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(sigma_mint_create_one)
{
    auto id = wallet->CreateSigmaMint(1, 2);
    auto mint = wallet->GetSigmaMint(id);

    BOOST_CHECK(id.pubKey.IsValid());
    BOOST_CHECK_EQUAL(1, id.property);
    BOOST_CHECK_EQUAL(2, id.denomination);
    BOOST_CHECK_EQUAL(id.property, mint.property);
    BOOST_CHECK_EQUAL(id.denomination, mint.denomination);

    BOOST_CHECK(!mint.IsSpent());
    BOOST_CHECK_EQUAL(mint.chainState, SigmaMintChainState());

    auto priv = wallet->GetKey(mint);
    SigmaPublicKey pub(priv, DefaultSigmaParams);
    BOOST_CHECK_EQUAL(id.pubKey, pub);

    auto another = CreateSigmaMint(1, 2);

    BOOST_CHECK_NE(another, mint);
}

BOOST_AUTO_TEST_CASE(sigma_mint_create_multi)
{
    std::vector<SigmaDenomination> denominations = {0, 1, 0, 2};
    std::vector<SigmaMintId> ids(5);
    std::unordered_set<SigmaMint> mints;

    auto next = wallet->CreateSigmaMints(1, denominations.begin(), denominations.end(), ids.begin());

    BOOST_CHECK_EQUAL(std::distance(ids.begin(), next), 4);

    BOOST_CHECK_EQUAL(ids[0].denomination, 0);
    BOOST_CHECK_EQUAL(ids[1].denomination, 1);
    BOOST_CHECK_EQUAL(ids[2].denomination, 0);
    BOOST_CHECK_EQUAL(ids[3].denomination, 2);

    for (auto it = ids.begin(); it != next; it++) {
        auto& id = *it;
        auto mint = wallet->GetSigmaMint(id);

        BOOST_CHECK_EQUAL(id.property, 1);
        BOOST_CHECK_EQUAL(mint.property, id.property);
        BOOST_CHECK_EQUAL(id.denomination, mint.denomination);
        BOOST_CHECK(id.pubKey.IsValid());

        BOOST_CHECK_NE(id.pubKey, SigmaPublicKey());

        BOOST_CHECK(!mint.IsSpent());
        BOOST_CHECK_EQUAL(mint.chainState, SigmaMintChainState());

        BOOST_CHECK(mints.insert(std::move(mint)).second);

        auto priv = wallet->GetKey(mint);
        SigmaPublicKey pub(priv, DefaultSigmaParams);
        BOOST_CHECK_EQUAL(pub, id.pubKey);
    }
}

BOOST_AUTO_TEST_CASE(sigma_spend_create_no_spendable_mint)
{
    // No any mints.
    BOOST_CHECK_THROW(wallet->CreateSigmaSpend(3, 0), InsufficientFunds);

    // Different denomination and property type.
    auto mintId = wallet->CreateSigmaMint(3, 0);

    BOOST_CHECK_THROW(wallet->CreateSigmaSpend(3, 1), InsufficientFunds);
    BOOST_CHECK_THROW(wallet->CreateSigmaSpend(4, 0), InsufficientFunds);

    // Pending mint.
    BOOST_CHECK_THROW(wallet->CreateSigmaSpend(3, 0), InsufficientFunds);

    // Already spent.
    sigmaDb->RecordMint(3, 0, mintId.pubKey, 100);
    wallet->SetSigmaMintUsedTransaction(mintId, uint256S("890e968f9b65dbacd576100c9b1c446f06471ed27df845ab7a24931cb640b388"));

    BOOST_CHECK_THROW(wallet->CreateSigmaSpend(3, 0), InsufficientFunds);
}

BOOST_AUTO_TEST_CASE(sigma_spend_create_with_spendable_mints)
{
    // Create first full group and one mint in a next group.
    auto expectedMintId = wallet->CreateSigmaMint(3, 0);
    sigmaDb->RecordMint(3, 0, expectedMintId.pubKey, 100);

    for (unsigned i = 1; i <= sigmaDb->groupSize; i++) {
        auto mintid = wallet->CreateSigmaMint(3, 0);
        sigmaDb->RecordMint(3, 0, mintid.pubKey, 100 + i);
    }

    auto spend = wallet->CreateSigmaSpend(3, 0);

    BOOST_CHECK_EQUAL(spend.mint, expectedMintId);
    BOOST_CHECK_EQUAL(spend.group, 0);
    BOOST_CHECK_EQUAL(spend.groupSize, sigmaDb->groupSize);
}

BOOST_AUTO_TEST_CASE(sigma_spend_create_not_enough_anonimity)
{
    auto mintId = wallet->CreateSigmaMint(3, 0);
    sigmaDb->RecordMint(3, 0, mintId.pubKey, 100);

    BOOST_CHECK_EXCEPTION(wallet->CreateSigmaSpend(3, 0), WalletError, [] (const WalletError& e) {
        return e.what() == std::string("Amount of coins in anonimity set is not enough to spend");
    });
}

BOOST_AUTO_TEST_CASE(sigma_mint_listing_all)
{
    // Create mints.
    std::unordered_set<SigmaMintId> ids;

    ids.insert(wallet->CreateSigmaMint(1, 0));
    ids.insert(wallet->CreateSigmaMint(2, 0));
    ids.insert(wallet->CreateSigmaMint(1, 1));
    ids.insert(wallet->CreateSigmaMint(2, 0));

    BOOST_CHECK_EQUAL(ids.size(), 4);

    // List mints.
    std::unordered_set<SigmaMint> mints;

    wallet->ListSigmaMints(std::inserter(mints, mints.end()));

    BOOST_CHECK_EQUAL(mints.size(), ids.size());

    for (auto& mint : mints) {
        SigmaPublicKey pub(wallet->GetKey(mint), DefaultSigmaParams);
        auto it = ids.find(SigmaMintId(mint.property, mint.denomination, pub));

        BOOST_CHECK(it != ids.end());
        BOOST_CHECK_EQUAL(mint, wallet->GetSigmaMint(*it));

        ids.erase(it);
    }

    BOOST_CHECK_EQUAL(ids.size(), 0);
}

BOOST_AUTO_TEST_CASE(sigma_mint_check_existence)
{
    auto owned = wallet->CreateSigmaMint(1, 1);
    SigmaPrivateKey priv;
    SigmaPublicKey pub;

    priv.Generate();
    pub.Generate(priv, DefaultSigmaParams);

    SigmaMintId other(1, 1, pub);

    BOOST_CHECK_EQUAL(wallet->HasSigmaMint(owned), true);
    BOOST_CHECK_EQUAL(wallet->HasSigmaMint(other), false);
}

BOOST_AUTO_TEST_CASE(sigma_mint_get)
{
    // Get existence.
    auto owned = wallet->CreateSigmaMint(1, 1);
    auto mint = wallet->GetSigmaMint(owned);

    SigmaPublicKey pub(wallet->GetKey(mint), DefaultSigmaParams);
    BOOST_CHECK_EQUAL(owned, SigmaMintId(mint.property, mint.denomination, pub));

    // Get non-existence.
    SigmaPrivateKey otherPriv;
    SigmaPublicKey otherPub;

    otherPriv.Generate();
    otherPub.Generate(otherPriv, DefaultSigmaParams);

    SigmaMintId other(1, 1, otherPub);

    BOOST_CHECK_THROW(wallet->GetSigmaMint(other), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(sigma_mint_set_used)
{
    auto tx = uint256S("64c4c22a45ad449be61c52a431d11e81f7fd0ee2f2235bf02944fb0b3dd07adb");
    auto id = wallet->CreateSigmaMint(1, 1);
    SigmaMint mint;

    wallet->SetSigmaMintUsedTransaction(id, tx);
    mint = wallet->GetSigmaMint(id);
    BOOST_CHECK_EQUAL(mint.spendTx, tx);

    wallet->SetSigmaMintUsedTransaction(id, uint256());
    mint = wallet->GetSigmaMint(id);
    BOOST_CHECK(!mint.IsSpent());
}

BOOST_AUTO_TEST_CASE(sigma_mint_chainstate_owned)
{
    auto id = wallet->CreateSigmaMint(1, 0);
    SigmaMintGroup group;
    SigmaMintIndex index;
    SigmaMint mint;

    // Add.
    std::tie(group, index) = sigmaDb->RecordMint(1, 0, id.pubKey, 100);
    mint = wallet->GetSigmaMint(id);

    BOOST_CHECK_EQUAL(mint.chainState.block, 100);
    BOOST_CHECK_EQUAL(mint.chainState.group, group);
    BOOST_CHECK_EQUAL(mint.chainState.index, index);

    // Remove.
    sigmaDb->DeleteAll(100);
    mint = wallet->GetSigmaMint(id);

    BOOST_CHECK_EQUAL(mint.chainState, SigmaMintChainState());
}

BOOST_AUTO_TEST_CASE(sigma_mint_chainstate_not_owned)
{
    // Add our mint first so we can test if the other mint does not alter our mint state.
    auto id = wallet->CreateSigmaMint(1, 0);
    SigmaMintGroup group;
    SigmaMintIndex index;

    std::tie(group, index) = sigmaDb->RecordMint(1, 0, id.pubKey, 100);

    // Add other mint.
    SigmaPrivateKey otherPriv;
    SigmaPublicKey otherPub;

    otherPriv.Generate();
    otherPub.Generate(otherPriv, DefaultSigmaParams);

    sigmaDb->RecordMint(1, 0, otherPub, 101);

    // Our chain state should not updated.
    SigmaMint mint;

    mint = wallet->GetSigmaMint(id);

    BOOST_CHECK_EQUAL(mint.chainState.block, 100);
    BOOST_CHECK_EQUAL(mint.chainState.group, group);
    BOOST_CHECK_EQUAL(mint.chainState.index, index);

    // Other mint should not added to our wallet.
    BOOST_CHECK_THROW(
        wallet->GetSigmaMint(SigmaMintId(1, 0, otherPub)),
        std::runtime_error
    );

    // Remove other mint and our chain state should not updated.
    sigmaDb->DeleteAll(101);

    mint = wallet->GetSigmaMint(id);

    BOOST_CHECK_EQUAL(mint.chainState.block, 100);
    BOOST_CHECK_EQUAL(mint.chainState.group, group);
    BOOST_CHECK_EQUAL(mint.chainState.index, index);
}

BOOST_AUTO_TEST_SUITE_END()

}
