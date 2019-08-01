// Copyright (c) 2019 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "wallet/wallet.h"
#include "wallet/test/wallet_test_fixture.h"

#include "../wallet.h"

class Wallet : public exodus::Wallet
{
public:
    Wallet(const std::string& walletFile)
        : exodus::Wallet(walletFile)
    {
    }

    exodus::SigmaEntry GetSigmaEntry(const exodus::SigmaMintId& id)
    {
        return exodus::Wallet::GetSigmaEntry(id);
    }

    void ListSigmaEntries(std::list<exodus::SigmaEntry>& listSigma)
    {
        exodus::Wallet::ListSigmaEntries(std::back_inserter(listSigma));
    }

    void ListSigmaEntries(uint32_t propertyId, std::list<exodus::SigmaEntry>& listSigma)
    {
        exodus::Wallet::ListSigmaEntries(propertyId, std::back_inserter(listSigma));
    }

    bool HasSigmaEntry(const exodus::SigmaMintId& id)
    {
        return exodus::Wallet::HasSigmaEntry(id);
    }
};

struct ExodusSigmaTestingSetup : WalletTestingSetup
{
    ExodusSigmaTestingSetup()
    {
        wallet = new Wallet(pwalletMain->strWalletFile);
    }

    ~ExodusSigmaTestingSetup()
    {
        delete wallet;
        wallet = nullptr;
    }
    Wallet *wallet;

    exodus::SigmaEntry createAndGetEntry(uint32_t propertyId, uint8_t denomination) {
        auto pubKey = wallet->CreateSigmaMint(propertyId, denomination);
        return wallet->GetSigmaEntry(
            exodus::SigmaMintId(pubKey.GetCommitment(), propertyId, denomination)
        );
    }
};

BOOST_FIXTURE_TEST_SUITE(exodus_wallet_tests, ExodusSigmaTestingSetup)

BOOST_AUTO_TEST_CASE(getid)
{
    exodus::SigmaEntry entry;
    exodus::SigmaPrivateKey priv;
    do {
        priv.Generate();
    } while (!priv.IsValid());
    exodus::SigmaPublicKey pub(priv);

    entry.serialNumber = priv.GetSerial();
    entry.randomness = priv.GetRandomness();
    entry.propertyId = 1;
    entry.denomination = 2;

    auto id = entry.GetId();

    BOOST_CHECK(id.commitment == pub.GetCommitment());
    BOOST_CHECK(id.propertyId == 1);
    BOOST_CHECK(id.denomination == 2);
}

BOOST_AUTO_TEST_CASE(create_sigma_mint)
{
    auto entry = createAndGetEntry(1, 1);
    BOOST_CHECK(entry.getPrivateKey().IsValid());
    BOOST_CHECK(exodus::SigmaPrivateKey() != entry.getPrivateKey());

    auto anotherEntry = createAndGetEntry(1, 1);

    BOOST_CHECK(anotherEntry != entry);
}

BOOST_AUTO_TEST_CASE(get_sigma_entry)
{
    auto retrieved = createAndGetEntry(1, 1);
    auto retrieved2 = wallet->GetSigmaEntry(retrieved.GetId());
    BOOST_CHECK(retrieved == retrieved2);
    BOOST_CHECK(retrieved != exodus::SigmaEntry());
    BOOST_CHECK(!retrieved.isUsed);
}

BOOST_AUTO_TEST_CASE(update_and_delete_entry_from_chain)
{
    auto entry = createAndGetEntry(1, 1);
    BOOST_CHECK(wallet->UpdateSigmaMint(entry.GetId(), 10, 1600, 100));
    auto beforeUpdated = wallet->GetSigmaEntry(entry.GetId());
    BOOST_CHECK_EQUAL(10, beforeUpdated.groupId);
    BOOST_CHECK_EQUAL(1600, beforeUpdated.index);
    BOOST_CHECK_EQUAL(100, beforeUpdated.block);

    BOOST_CHECK(wallet->ClearSigmaMintChainState(entry.GetId()));

    auto updated = wallet->GetSigmaEntry(entry.GetId());
    BOOST_CHECK_EQUAL(0, updated.groupId);
    BOOST_CHECK_EQUAL(0, updated.index);
    BOOST_CHECK_EQUAL(-1, updated.block);
    BOOST_CHECK(!updated.isUsed);
}

BOOST_AUTO_TEST_CASE(make_entry_as_used)
{
    auto entry = createAndGetEntry(1, 1);
    BOOST_CHECK(wallet->SetSigmaMintUsedStatus(entry.GetId(), true));
    auto updated = wallet->GetSigmaEntry(entry.GetId());
    BOOST_CHECK(updated.isUsed);

    BOOST_CHECK(wallet->SetSigmaMintUsedStatus(entry.GetId(), false));
    updated = wallet->GetSigmaEntry(entry.GetId());
    BOOST_CHECK(!updated.isUsed);
}

BOOST_AUTO_TEST_CASE(list_entry_no_coins)
{
    std::list<exodus::SigmaEntry> listSigma;
    wallet->ListSigmaEntries(listSigma);
    BOOST_CHECK_EQUAL(0, listSigma.size());
}

BOOST_AUTO_TEST_CASE(list_entry_have_two_coins_same_property)
{
    auto pubKey = wallet->CreateSigmaMint(1, 1);
    auto pubKey2 = wallet->CreateSigmaMint(1, 1);

    std::list<exodus::SigmaEntry> listSigma;
    wallet->ListSigmaEntries(listSigma);
    BOOST_CHECK_EQUAL(2, listSigma.size());

    auto commitment = pubKey.GetCommitment();
    auto commitment2 = pubKey2.GetCommitment();

    auto first = listSigma.front().getPublicKey().GetCommitment();
    listSigma.pop_front();
    auto second = listSigma.front().getPublicKey().GetCommitment();
    BOOST_CHECK(
        (commitment == first && commitment2 == second)
        || (commitment == second && commitment2 == first)
    );
}

BOOST_AUTO_TEST_CASE(list_entry_have_two_coins_different_property)
{
    auto prop1Entry = createAndGetEntry(1, 1);
    auto prop2Entry = createAndGetEntry(2, 1);

    std::list<exodus::SigmaEntry> listSigma;
    wallet->ListSigmaEntries(listSigma);
    BOOST_CHECK_EQUAL(2, listSigma.size());

    std::list<exodus::SigmaEntry> listProp1Sigma;
    wallet->ListSigmaEntries(1, listProp1Sigma);
    BOOST_CHECK_EQUAL(1, listProp1Sigma.size());
    BOOST_CHECK(prop1Entry == listProp1Sigma.front());

    std::list<exodus::SigmaEntry> listProp2Sigma;
    wallet->ListSigmaEntries(2, listProp2Sigma);
    BOOST_CHECK_EQUAL(1, listProp2Sigma.size());
    BOOST_CHECK(prop2Entry == listProp2Sigma.front());
}

BOOST_AUTO_TEST_CASE(is_exists)
{
    auto existsEntry = createAndGetEntry(1, 1);

    exodus::SigmaPrivateKey nonExistsPriv;
    do {
        nonExistsPriv.Generate();
    } while (!nonExistsPriv.IsValid());
    exodus::SigmaPublicKey nonExistsPubKey(nonExistsPriv);

    BOOST_CHECK(wallet->HasSigmaEntry(existsEntry.GetId()));
    BOOST_CHECK(!wallet->HasSigmaEntry(
        exodus::SigmaMintId(nonExistsPubKey.GetCommitment(), 1, 1)));
}

BOOST_AUTO_TEST_SUITE_END()
