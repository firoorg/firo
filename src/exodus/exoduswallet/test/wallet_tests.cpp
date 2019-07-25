// Copyright (c) 2019 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "wallet/wallet.h"
#include "wallet/test/wallet_test_fixture.h"

#include "../wallet.h"

struct ExodusSigmaTestingSetup : WalletTestingSetup
{
    ExodusSigmaTestingSetup()
        : WalletTestingSetup()
    {
        exodusTestWallet = new exodus::ExodusWallet(pwalletMain->strWalletFile);
    }

    ~ExodusSigmaTestingSetup()
    {
        delete exodusTestWallet;
        exodusTestWallet = nullptr;
    }
    exodus::ExodusWallet *exodusTestWallet;
};

BOOST_FIXTURE_TEST_SUITE(exodus_wallet_tests, ExodusSigmaTestingSetup)

BOOST_AUTO_TEST_CASE(create_sigma_private_key)
{
    auto defaultKey = exodus::SigmaPrivateKey();
    auto key = exodusTestWallet->CreateSigmaPrivateKey();
    BOOST_CHECK(key.IsValid());
    BOOST_CHECK(exodus::SigmaPrivateKey() != key);
    BOOST_CHECK(exodusTestWallet->CreateSigmaPrivateKey() != key);
}

BOOST_AUTO_TEST_CASE(get_set_sigma_entry)
{
    auto key = exodusTestWallet->CreateSigmaPrivateKey();
    exodus::SigmaPublicKey pubKey(key);
    auto entry = exodusTestWallet->RecordSigmaKey(1, 1, key);
    auto retrieved = exodusTestWallet->GetSigmaEntry(pubKey.GetCommitment());
    BOOST_CHECK(entry == retrieved);
    BOOST_CHECK(entry != exodus::CSigmaEntry());
    BOOST_CHECK(!entry.isUsed);
}

BOOST_AUTO_TEST_CASE(update_entry)
{
    auto key = exodusTestWallet->CreateSigmaPrivateKey();
    exodus::SigmaPublicKey pubKey(key);
    exodusTestWallet->RecordSigmaKey(1, 1, key);
    BOOST_CHECK(exodusTestWallet->UpdateSigma(pubKey.GetCommitment(), 10, 11, 100));
    auto updated = exodusTestWallet->GetSigmaEntry(pubKey.GetCommitment());
    BOOST_CHECK_EQUAL(10, updated.groupID);
    BOOST_CHECK_EQUAL(11, updated.index);
    BOOST_CHECK_EQUAL(100, updated.nBlock);
    BOOST_CHECK(!updated.isUsed);
}

BOOST_AUTO_TEST_CASE(delete_entry_from_chain)
{
    auto key = exodusTestWallet->CreateSigmaPrivateKey();
    exodus::SigmaPublicKey pubKey(key);
    exodusTestWallet->RecordSigmaKey(1, 1, key);
    BOOST_CHECK(exodusTestWallet->UpdateSigma(pubKey.GetCommitment(), 10, 11, 100));
    BOOST_CHECK(exodusTestWallet->DeleteFromChain(pubKey.GetCommitment()));
    auto updated = exodusTestWallet->GetSigmaEntry(pubKey.GetCommitment());
    BOOST_CHECK_EQUAL(-1, updated.nBlock);
    BOOST_CHECK(!updated.isUsed);
}

BOOST_AUTO_TEST_CASE(make_entry_as_used)
{
    auto key = exodusTestWallet->CreateSigmaPrivateKey();
    exodus::SigmaPublicKey pubKey(key);
    exodusTestWallet->RecordSigmaKey(1, 1, key);
    BOOST_CHECK(exodusTestWallet->UpdateSigma(pubKey.GetCommitment(), 10, 11, 100));
    BOOST_CHECK(exodusTestWallet->SetUsedStatus(pubKey.GetCommitment(), true));
    auto updated = exodusTestWallet->GetSigmaEntry(pubKey.GetCommitment());
    BOOST_CHECK(updated.isUsed);

    BOOST_CHECK(exodusTestWallet->SetUsedStatus(pubKey.GetCommitment(), false));
    updated = exodusTestWallet->GetSigmaEntry(pubKey.GetCommitment());
    BOOST_CHECK(!updated.isUsed);
}

BOOST_AUTO_TEST_CASE(list_entry_no_coins)
{
    std::list<exodus::CSigmaEntry> listSigma;
    exodusTestWallet->ListSigmaEntries(listSigma);
    BOOST_CHECK_EQUAL(0, listSigma.size());
}

BOOST_AUTO_TEST_CASE(list_entry_have_two_coins_same_property)
{
    auto key = exodusTestWallet->CreateSigmaPrivateKey();
    exodusTestWallet->RecordSigmaKey(1, 1, key);

    auto key2 = exodusTestWallet->CreateSigmaPrivateKey();
    exodusTestWallet->RecordSigmaKey(1, 1, key2);


    std::list<exodus::CSigmaEntry> listSigma;
    exodusTestWallet->ListSigmaEntries(listSigma);
    BOOST_CHECK_EQUAL(2, listSigma.size());
}

BOOST_AUTO_TEST_CASE(list_entry_have_two_coins_different_property)
{
    auto key = exodusTestWallet->CreateSigmaPrivateKey();
    auto prop1Entry = exodusTestWallet->RecordSigmaKey(1, 1, key);

    auto key2 = exodusTestWallet->CreateSigmaPrivateKey();
    auto prop2Entry = exodusTestWallet->RecordSigmaKey(2, 1, key2);


    std::list<exodus::CSigmaEntry> listSigma;
    exodusTestWallet->ListSigmaEntries(listSigma);
    BOOST_CHECK_EQUAL(2, listSigma.size());

    std::list<exodus::CSigmaEntry> listProp1Sigma;
    exodusTestWallet->ListSigmaEntries(1, listProp1Sigma);
    BOOST_CHECK_EQUAL(1, listProp1Sigma.size());
    BOOST_CHECK(prop1Entry == listProp1Sigma.front());

    std::list<exodus::CSigmaEntry> listProp2Sigma;
    exodusTestWallet->ListSigmaEntries(2, listProp2Sigma);
    BOOST_CHECK_EQUAL(1, listProp2Sigma.size());
    BOOST_CHECK(prop2Entry == listProp2Sigma.front());
}

BOOST_AUTO_TEST_CASE(is_exists)
{
    auto existsKey = exodusTestWallet->CreateSigmaPrivateKey();
    exodus::SigmaPublicKey existsPubKey(existsKey);
    exodusTestWallet->RecordSigmaKey(1, 1, existsKey);

    auto nonExistsKey = exodusTestWallet->CreateSigmaPrivateKey();
    exodus::SigmaPublicKey nonExistsPubKey(nonExistsKey);

    BOOST_CHECK(exodusTestWallet->HasSigmaEntry(existsPubKey.GetCommitment()));
    BOOST_CHECK(!exodusTestWallet->HasSigmaEntry(nonExistsPubKey.GetCommitment()));
}

BOOST_AUTO_TEST_SUITE_END()
