// Copyright (c) 2019 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "../../wallet/wallet.h"
#include "../../wallet/test/wallet_test_fixture.h"

#include "../wallet.h"

namespace exodus {

class TestWallet : public Wallet
{
public:
    TestWallet(const std::string& walletFile, CMPMintList& sigmaDb) : Wallet(walletFile, sigmaDb)
    {
    }

    SigmaEntry GetSigmaEntry(const SigmaMintId& id)
    {
        return Wallet::GetSigmaEntry(id);
    }

    void ListSigmaEntries(std::list<SigmaEntry>& entries)
    {
        Wallet::ListSigmaEntries(std::back_inserter(entries));
    }

    void ListSigmaEntries(uint32_t propertyId, std::list<SigmaEntry>& entries)
    {
        Wallet::ListSigmaEntries(propertyId, std::back_inserter(entries));
    }

    bool HasSigmaEntry(const SigmaMintId& id)
    {
        return Wallet::HasSigmaEntry(id);
    }
};

struct ExodusWalletTestingSetup : WalletTestingSetup
{
    CMPMintList sigmaDb;
    TestWallet wallet;

    ExodusWalletTestingSetup() :
        sigmaDb(pathTemp / "exodus_sigma_tests", true),
        wallet(pwalletMain->strWalletFile, sigmaDb)
    {
    }

    SigmaEntry CreateAndGetEntry(uint32_t propertyId, uint8_t denomination)
    {
        auto id = wallet.CreateSigmaMint(propertyId, denomination);
        return wallet.GetSigmaEntry(id);
    }
};

BOOST_FIXTURE_TEST_SUITE(exodus_wallet_tests, ExodusWalletTestingSetup)

BOOST_AUTO_TEST_CASE(create_sigma_mint)
{
    auto entry = CreateAndGetEntry(1, 1);
    BOOST_CHECK(entry.privateKey.IsValid());
    BOOST_CHECK(entry.privateKey != SigmaPrivateKey());
    BOOST_CHECK(entry.chainState == SigmaMintChainState());

    auto anotherEntry = CreateAndGetEntry(1, 1);

    BOOST_CHECK(anotherEntry != entry);
}

BOOST_AUTO_TEST_CASE(get_sigma_entry)
{
    auto retrieved = CreateAndGetEntry(1, 1);
    auto retrieved2 = wallet.GetSigmaEntry(retrieved.GetId());
    BOOST_CHECK(retrieved == retrieved2);
    BOOST_CHECK(retrieved != exodus::SigmaEntry());
    BOOST_CHECK(retrieved.tx.IsNull());
}

BOOST_AUTO_TEST_CASE(make_entry_as_used)
{
    auto entry = CreateAndGetEntry(1, 1);
    BOOST_CHECK_NO_THROW(
        wallet.SetSigmaMintUsedTransaction(entry.GetId(), uint256S("1")));
    auto updated = wallet.GetSigmaEntry(entry.GetId());
    BOOST_CHECK(updated.tx == uint256S("1"));

    BOOST_CHECK_NO_THROW(
        wallet.SetSigmaMintUsedTransaction(entry.GetId(), uint256()));
    updated = wallet.GetSigmaEntry(entry.GetId());
    BOOST_CHECK(updated.tx.IsNull());
}

BOOST_AUTO_TEST_CASE(list_entry_no_coins)
{
    std::list<exodus::SigmaEntry> listSigma;
    wallet.ListSigmaEntries(listSigma);
    BOOST_CHECK_EQUAL(0, listSigma.size());
}

BOOST_AUTO_TEST_CASE(list_entry_have_two_coins_same_property)
{
    auto id = wallet.CreateSigmaMint(1, 1);
    auto id2 = wallet.CreateSigmaMint(1, 1);

    std::list<exodus::SigmaEntry> listSigma;
    wallet.ListSigmaEntries(listSigma);
    BOOST_CHECK_EQUAL(2, listSigma.size());

    auto first = exodus::SigmaPublicKey(listSigma.front().privateKey);
    listSigma.pop_front();
    auto second = exodus::SigmaPublicKey(listSigma.front().privateKey);
    BOOST_CHECK(
        (id.publicKey == first && id2.publicKey == second)
        || (id.publicKey == second && id2.publicKey == first)
    );
}

BOOST_AUTO_TEST_CASE(list_entry_have_two_coins_different_property)
{
    auto prop1Entry = CreateAndGetEntry(1, 1);
    auto prop2Entry = CreateAndGetEntry(2, 1);

    std::list<exodus::SigmaEntry> listSigma;
    wallet.ListSigmaEntries(listSigma);
    BOOST_CHECK_EQUAL(2, listSigma.size());

    std::list<exodus::SigmaEntry> listProp1Sigma;
    wallet.ListSigmaEntries(1, listProp1Sigma);
    BOOST_CHECK_EQUAL(1, listProp1Sigma.size());
    BOOST_CHECK(prop1Entry == listProp1Sigma.front());

    std::list<exodus::SigmaEntry> listProp2Sigma;
    wallet.ListSigmaEntries(2, listProp2Sigma);
    BOOST_CHECK_EQUAL(1, listProp2Sigma.size());
    BOOST_CHECK(prop2Entry == listProp2Sigma.front());
}

BOOST_AUTO_TEST_CASE(is_exists)
{
    auto existsEntry = CreateAndGetEntry(1, 1);

    exodus::SigmaPrivateKey nonExistsPriv;
    nonExistsPriv.Generate();

    exodus::SigmaPublicKey nonExistsPubKey(nonExistsPriv);

    BOOST_CHECK(wallet.HasSigmaEntry(existsEntry.GetId()));
    BOOST_CHECK(!wallet.HasSigmaEntry(
        exodus::SigmaMintId(nonExistsPubKey, 1, 1)));
}

BOOST_AUTO_TEST_CASE(sigma_mint_chainstate_owned)
{
    auto mint = wallet.CreateSigmaMint(1, 0);
    MintGroupId group;
    MintGroupIndex index;
    SigmaMintChainState state;

    // Add.
    std::tie(group, index) = sigmaDb.RecordMint(1, 0, mint.publicKey, 100);
    state = wallet.GetSigmaMintChainState(mint);

    BOOST_CHECK_EQUAL(state.block, 100);
    BOOST_CHECK_EQUAL(state.group, group);
    BOOST_CHECK_EQUAL(state.index, index);

    // Remove.
    sigmaDb.DeleteAll(100);
    state = wallet.GetSigmaMintChainState(mint);

    BOOST_CHECK_EQUAL(state, SigmaMintChainState());
}

BOOST_AUTO_TEST_CASE(sigma_mint_chainstate_not_owned)
{
    SigmaMintChainState state;

    // Add our mint first so we can test if the other mint does not alter our mint state.
    auto owned = wallet.CreateSigmaMint(1, 0);
    MintGroupId group;
    MintGroupIndex index;

    std::tie(group, index) = sigmaDb.RecordMint(1, 0, owned.publicKey, 100);

    // Add other mint.
    SigmaPrivateKey otherPriv;
    SigmaPublicKey otherPub;

    otherPriv.Generate();
    otherPub.Generate(otherPriv);

    sigmaDb.RecordMint(1, 0, otherPub, 101);

    // Our chain state should not updated.
    state = wallet.GetSigmaMintChainState(owned);

    BOOST_CHECK_EQUAL(state.block, 100);
    BOOST_CHECK_EQUAL(state.group, group);
    BOOST_CHECK_EQUAL(state.index, index);

    // Other mint should not added to our wallet.
    BOOST_CHECK_THROW(
        wallet.GetSigmaMintChainState(SigmaMintId(otherPub, 1, 0)),
        std::runtime_error
    );

    // Remove other mint and our chain state should not updated.
    sigmaDb.DeleteAll(101);

    state = wallet.GetSigmaMintChainState(owned);

    BOOST_CHECK_EQUAL(state.block, 100);
    BOOST_CHECK_EQUAL(state.group, group);
    BOOST_CHECK_EQUAL(state.index, index);
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
