// Copyright (c) 2019 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../sigmadb.h"
#include "../sigmawallet.h"
#include "../walletmodels.h"

#include "../../key.h"
#include "../../main.h"
#include "../../utiltime.h"
#include "../../validationinterface.h"

#include "../../rpc/server.h"

#include "../../wallet/db.h"
#include "../../wallet/rpcwallet.h"
#include "../../wallet/wallet.h"
#include "../../wallet/walletdb.h"

#include "../../wallet/test/wallet_test_fixture.h"

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem.hpp>
#include <boost/function_output_iterator.hpp>
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace std {

template<typename Char, typename Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const vector<SigmaMintId>& mints)
{
    vector<basic_string<Char, Traits>> strings;

    for (auto& m : mints) {
        basic_stringstream<Char, Traits> s;
        s << m;
        strings.push_back(s.str());
    }

    return os << '[' << boost::algorithm::join(strings, ", ") << ']';
}

} // namespace std

namespace elysium {

using MintPoolEntry = SigmaWallet::MintPoolEntry;
namespace {

class TestSigmaWallet : public SigmaWallet
{

public:
    TestSigmaWallet()
    {
    }

public:
    uint32_t ChangeIndex()
    {
        return BIP44_ELYSIUM_MINT_INDEX;
    }

    SigmaPrivateKey GeneratePrivateKeyFromSeed(uint512 const &seed)
    {
        return GeneratePrivateKey(seed);
    }

    std::array<uint8_t, 64> Sign(SigmaMintId const &id, unsigned char const *payload, size_t payloadSize)
    {
        return std::array<uint8_t, 64>();
    }

    void LoadMintPool()
    {
        SigmaWallet::LoadMintPool();
    }

    void SaveMintPool()
    {
        SigmaWallet::SaveMintPool();
    }

    bool RemoveFromMintPool(SigmaPublicKey const &publicKey)
    {
        return SigmaWallet::RemoveFromMintPool(publicKey);
    }

    size_t FillMintPool()
    {
        return SigmaWallet::FillMintPool();
    }

    MintPool& GetMintPool()
    {
        return mintPool;
    }

    std::vector<MintPoolEntry> GetMintPoolEntry()
    {
        std::vector<MintPoolEntry> r;
        for (auto const & e : mintPool) {
            r.push_back(e);
        }

        return r;
    }

protected:
    SigmaPrivateKey GeneratePrivateKey(uint512 const &seed)
    {
        SigmaPrivateKey priv;

        // first 32 bytes as seed
        uint256 serialSeed;
        std::copy(seed.begin(), seed.begin() + 32, serialSeed.begin());
        priv.serial.memberFromSeed(serialSeed.begin());

        // last 32 bytes as seed
        uint256 randomnessSeed;
        std::copy(seed.begin() + 32, seed.end(), randomnessSeed.begin());
        priv.randomness.memberFromSeed(randomnessSeed.begin());

        return priv;
    }

    unsigned GetChange() const {
        return BIP44_ELYSIUM_MINT_INDEX;
    }

    bool WriteExodusMint(SigmaMintId const &id, SigmaMint const &mint, CWalletDB *db = nullptr)
    {
        auto local = EnsureDBConnection(db);
        return db->WriteExodusMint(id, mint);
    }

    bool ReadExodusMint(SigmaMintId const &id, SigmaMint &mint, CWalletDB *db = nullptr) const
    {
        auto local = EnsureDBConnection(db);
        return db->ReadExodusMint(id, mint);
    }

    bool EraseExodusMint(SigmaMintId const &id, CWalletDB *db = nullptr)
    {
        auto local = EnsureDBConnection(db);
        return db->EraseExodusMint(id);
    }

    bool HasExodusMint(SigmaMintId const &id, CWalletDB *db = nullptr) const
    {
        auto local = EnsureDBConnection(db);
        return db->HasExodusMint(id);
    }

    bool WriteExodusMintId(uint160 const &hash, SigmaMintId const &mintId, CWalletDB *db = nullptr)
    {
        auto local = EnsureDBConnection(db);
        return db->WriteExodusMintID(hash, mintId);
    }

    bool ReadExodusMintId(uint160 const &hash, SigmaMintId &mintId, CWalletDB *db = nullptr) const
    {
        auto local = EnsureDBConnection(db);
        return db->ReadExodusMintID(hash, mintId);
    }

    bool EraseExodusMintId(uint160 const &hash, CWalletDB *db = nullptr)
    {
        auto local = EnsureDBConnection(db);
        return db->EraseExodusMintID(hash);
    }

    bool HasExodusMintId(uint160 const &hash, CWalletDB *db = nullptr) const
    {
        auto local = EnsureDBConnection(db);
        return db->HasExodusMintID(hash);
    }

    bool WriteExodusMintPool(std::vector<MintPoolEntry> const &mints, CWalletDB *db = nullptr)
    {
        auto local = EnsureDBConnection(db);
        return db->WriteExodusMintPool(mints);
    }

    bool ReadExodusMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db = nullptr)
    {
        auto local = EnsureDBConnection(db);
        return db->ReadExodusMintPool(mints);
    }

    void ListExodusMints(std::function<void(SigmaMintId&, SigmaMint&)> inserter, CWalletDB *db = nullptr)
    {
        auto local = EnsureDBConnection(db);
        db->ListExodusMints<SigmaMintId, SigmaMint>(inserter);
    }
};

struct SigmaWalletTestingSetup : WalletTestingSetup
{
    std::unique_ptr<TestSigmaWallet> wallet;

    SigmaWalletTestingSetup() : wallet(new TestSigmaWallet())
    {
        wallet->ReloadMasterKey();
    }
};

} // unnamed namespace

BOOST_FIXTURE_TEST_SUITE(exodus_sigmawallet_tests, SigmaWalletTestingSetup)

BOOST_AUTO_TEST_CASE(verify_mint_pool_have_been_generened)
{
    auto mintPool = wallet->GetMintPoolEntry();
    BOOST_CHECK_EQUAL(20, mintPool.size());
}

BOOST_AUTO_TEST_CASE(save_and_load_mintpool)
{
    auto mints = wallet->GetMintPoolEntry();

    // delete last mint from pool and save
    auto &pool = wallet->GetMintPool();
    pool.erase(pool.find(19), pool.end());
    wallet->SaveMintPool();

    // delete more 9 mints
    pool.erase(pool.find(10), pool.end());
    auto mutatedMintPools = wallet->GetMintPoolEntry();
    BOOST_CHECK_EQUAL(10, mutatedMintPools.size());
    BOOST_CHECK_EQUAL(
        true,
        std::equal(
            mutatedMintPools.begin(),
            mutatedMintPools.end(),
            mints.begin()
        )
    );

    // load mint pool back
    wallet->LoadMintPool();

    auto loadedMintPools = wallet->GetMintPoolEntry();
    BOOST_CHECK_EQUAL(19, loadedMintPools.size());
    BOOST_CHECK_EQUAL(
        true,
        std::equal(
            loadedMintPools.begin(),
            loadedMintPools.end(),
            mints.begin()
        )
    );
}

BOOST_AUTO_TEST_CASE(verify_mintpool_on_fresh_startup)
{
    // get sequence
    auto mints = wallet->GetMintPoolEntry();

    std::vector<uint32_t> mintPoolIndexs;
    for (auto const &mint : mints) {
        mintPoolIndexs.push_back(mint.index);
    }

    // generate sequence
    std::vector<uint32_t> seq;
    seq.resize(mintPoolIndexs.size());

    std::generate(seq.begin(), seq.end(), [n = 0] () mutable { return n++; });

    BOOST_CHECK(seq == mintPoolIndexs);
}

BOOST_AUTO_TEST_CASE(tryrecover_random_coin)
{
    SigmaPrivateKey priv;
    priv.Generate();

    SigmaPublicKey pub(priv, DefaultSigmaParams);
    SigmaMintId id(1, 0, pub);


    auto mintPool = wallet->GetMintPoolEntry();

    // verify state before
    BOOST_CHECK_EQUAL(false, wallet->HasMint(id));

    // `false` should be returned
    BOOST_CHECK_EQUAL(false, wallet->TryRecoverMint(
        id, SigmaMintChainState(1000, 0, 1000)
    ));

    // verify after, mint wallet should not change
    auto mintPoolAfter = wallet->GetMintPoolEntry();

    BOOST_CHECK(mintPool == mintPoolAfter);
    BOOST_CHECK_EQUAL(false, wallet->HasMint(id));
}

BOOST_AUTO_TEST_CASE(tryrecover_mintpool_coin)
{
    auto mintPool = wallet->GetMintPoolEntry();
    SigmaMintId id(1, 0, mintPool.front().key);

    // verify state before
    BOOST_CHECK_EQUAL(false, wallet->HasMint(id));

    BOOST_CHECK_EQUAL(true, wallet->TryRecoverMint(
        id,
        SigmaMintChainState(1000, 0, 1000)
    ));

    // verify state after, mint wallet should be updated
    auto mintPoolAfter = wallet->GetMintPoolEntry();

    BOOST_CHECK(mintPool != mintPoolAfter);

    // mintPool[1:] == mintPoolAfter[:size - 1]
    BOOST_CHECK_EQUAL(true,
        std::equal(mintPool.begin() + 1, mintPool.end(), mintPoolAfter.begin()));

    BOOST_CHECK_EQUAL(20, mintPoolAfter.size()); // ensure mint pool is refilled
    BOOST_CHECK_EQUAL(20, mintPoolAfter.back().index); // make sure new coin contain next index
    BOOST_CHECK_EQUAL(true, wallet->HasMint(id));
}

BOOST_AUTO_TEST_CASE(tryrecover_already_in_wallet_coin)
{
    auto id = wallet->GenerateMint(3, 0);
    auto mintPool = wallet->GetMintPoolEntry();

    // verify state before
    BOOST_CHECK_EQUAL(true, wallet->HasMint(id));

    BOOST_CHECK_EQUAL(false, wallet->TryRecoverMint(
        id,
        SigmaMintChainState(1000, 0, 1000)
    ));

    // verify state after, mint wallet should not be changed
    auto mintPoolAfter = wallet->GetMintPoolEntry();

    BOOST_CHECK(mintPool == mintPoolAfter);

    BOOST_CHECK_EQUAL(true, wallet->HasMint(id));
}

BOOST_AUTO_TEST_CASE(listmints_empty_wallet)
{
    std::vector<std::pair<SigmaMintId, SigmaMint>> mints;
    wallet->ListMints(std::back_inserter(mints));
    BOOST_CHECK_EQUAL(0, mints.size());
}

BOOST_AUTO_TEST_CASE(listmints_non_empty_wallet)
{
    auto unconfirmed = wallet->GenerateMint(10, 0);
    auto unspend = wallet->GenerateMint(10, 0);
    auto spend = wallet->GenerateMint(10, 0);

    wallet->UpdateMintChainstate(unspend, SigmaMintChainState(100, 0, 1000));
    wallet->UpdateMintChainstate(spend, SigmaMintChainState(100, 0, 1001));
    wallet->UpdateMintSpendTx(spend, uint256S("766a4af4a36df1cd40e60f049f14d8a10fc9f9f20f7f88d89cafd415725d9415"));

    std::vector<SigmaMintId> result;

    wallet->ListMints(boost::make_function_output_iterator([&] (const std::pair<SigmaMintId, SigmaMint>& m) {
        result.push_back(m.first);
    }));

    BOOST_CHECK_EQUAL(
        true,
        std::is_permutation(result.begin(), result.end(), std::begin({ unconfirmed, unspend, spend }))
    );
}

BOOST_AUTO_TEST_CASE(delete_out_wallet_mint)
{
    SigmaPrivateKey privKey;
    privKey.Generate();
    SigmaPublicKey pubKey(privKey, DefaultSigmaParams);

    SigmaMintId id(10, 0, pubKey);

    BOOST_CHECK_EXCEPTION(
        wallet->DeleteUnconfirmedMint(id),
        std::runtime_error,
        [](std::runtime_error const &e) -> bool{
            return std::string("no mint data in wallet") == e.what();
        }
    );
}

BOOST_AUTO_TEST_CASE(push_mint_back)
{
    auto id = wallet->GenerateMint(1, 0);
    auto mint = wallet->GetMint(id);

    BOOST_CHECK(wallet->HasMint(id));
    BOOST_CHECK(!wallet->IsMintInPool(id.pubKey));
    wallet->DeleteUnconfirmedMint(id);
    BOOST_CHECK(!wallet->HasMint(id));
    BOOST_CHECK(wallet->IsMintInPool(id.pubKey));

    auto mintPoolAfter = wallet->GetMintPoolEntry();

    BOOST_CHECK_EQUAL(21, mintPoolAfter.size());
    BOOST_CHECK(mint.seedId == mintPoolAfter.front().seedId);
}

BOOST_AUTO_TEST_CASE(clear_chain_state)
{
    // generate 10 coins and set state
    std::vector<SigmaMint> generatedMints;
    for (size_t i = 0; i < 10; i++) {
        auto id = wallet->GenerateMint(1, 0);
        auto mint = wallet->GetMint(id);

        SigmaMintChainState state(100, 0, i);
        wallet->UpdateMintChainstate(id, state);

        if (i % 2) {
            wallet->UpdateMintSpendTx(id, uint256S(std::to_string(i)));
            mint.spendTx = uint256S(std::to_string(i));
        }

        mint.chainState = state;
        generatedMints.push_back(mint);
    }

    std::vector<SigmaMint> mints;
    wallet->ListMints(boost::make_function_output_iterator(
        [&mints](std::pair<SigmaMintId, SigmaMint> const &idAndMint){
            mints.push_back(idAndMint.second);
        })
    );

    BOOST_CHECK_EQUAL(
        true,
        std::is_permutation(
            generatedMints.begin(), generatedMints.end(),
            mints.begin()
        )
    );

    // clear state and check
    wallet->ClearMintsChainState();

    std::vector<SigmaMint> clearedMints;
    wallet->ListMints(boost::make_function_output_iterator(
        [&clearedMints](std::pair<SigmaMintId, SigmaMint> const &idAndMint){
            clearedMints.push_back(idAndMint.second);
        })
    );

    BOOST_CHECK_EQUAL(10, clearedMints.size());
    BOOST_CHECK_EQUAL(
        true,
        std::is_permutation(
            mints.begin(), mints.end(),
            clearedMints.begin(),
            [](SigmaMint const &a, SigmaMint const &b) -> bool {
                return a.seedId == b.seedId;
            }
        )
    );

    for (auto const &m : clearedMints) {
        BOOST_CHECK_EQUAL(false, m.IsOnChain());
        BOOST_CHECK_EQUAL(false, m.IsSpent());
    }
}

BOOST_AUTO_TEST_CASE(fill_mint_pool)
{
    auto &mintPool = wallet->GetMintPool();

    auto indexLess = [](
        MintPoolEntry const &a, MintPoolEntry const &b) -> bool {
            return a.index < b.index;
    };

    // last coin should be 19
    BOOST_CHECK_EQUAL(
        19,
        std::max_element(mintPool.begin(), mintPool.end(), indexLess)->index
    );

    // erase index 0, 10 and 15
    mintPool.erase(mintPool.find(0));
    mintPool.erase(mintPool.find(10));
    mintPool.erase(mintPool.find(15));

    // filled, 3 coins should be added
    wallet->FillMintPool();

    mintPool = wallet->GetMintPool();
    BOOST_CHECK_EQUAL(20, mintPool.size());

    // verify
    BOOST_CHECK(mintPool.find(0) == mintPool.end());
    BOOST_CHECK(mintPool.find(10) == mintPool.end());
    BOOST_CHECK(mintPool.find(15) == mintPool.end());

    // last coin should be 22
    BOOST_CHECK_EQUAL(
        22,
        std::max_element(mintPool.begin(), mintPool.end(), indexLess)->index
    );

    // 20, 21, 22 should be added
    BOOST_CHECK(mintPool.find(20) != mintPool.end());
    BOOST_CHECK(mintPool.find(21) != mintPool.end());
    BOOST_CHECK(mintPool.find(22) != mintPool.end());
}

BOOST_AUTO_TEST_CASE(remove_from_mintpool)
{
    auto &mintPool = wallet->GetMintPool();

    // remove indice 0, 10 and 15 by pubkey
    wallet->RemoveFromMintPool(mintPool.find(0)->key);
    BOOST_CHECK_EQUAL(19, mintPool.size());

    wallet->RemoveFromMintPool(mintPool.find(10)->key);
    BOOST_CHECK_EQUAL(18, mintPool.size());

    wallet->RemoveFromMintPool(mintPool.find(15)->key);
    BOOST_CHECK_EQUAL(17, mintPool.size());

    // coins should be deleted
    BOOST_CHECK(mintPool.find(0) == mintPool.end());
    BOOST_CHECK(mintPool.find(10) == mintPool.end());
    BOOST_CHECK(mintPool.find(15) == mintPool.end());
}

BOOST_AUTO_TEST_CASE(restore_wallet)
{
    // Generate mints before reset wallet.
    std::vector<SigmaMintId> before;

    before.push_back(wallet->GenerateMint(3, 0));
    before.push_back(wallet->GenerateMint(3, 1));
    before.push_back(wallet->GenerateMint(4, 2));

    // Delete current wallet.
    auto file = pwalletMain->strWalletFile;
    CKey masterPriv;

    BOOST_CHECK_EQUAL(pwalletMain->GetKey(pwalletMain->GetHDChain().masterKeyID, masterPriv), true);

    delete wallet.release();
    UnregisterValidationInterface(pwalletMain);
    delete pwalletMain;
    bitdb.RemoveDb(file);

    BOOST_CHECK_EQUAL(boost::filesystem::exists(pathTemp / file), false);

    // Create a new fresh wallet with the same master key as previous wallet.
    auto masterPub = masterPriv.GetPubKey();
    auto masterId = masterPub.GetID();
    bool firstRun;

    pwalletMain = new CWallet(file);

    LOCK(pwalletMain->cs_wallet);

    BOOST_CHECK_EQUAL(pwalletMain->LoadWallet(firstRun), DB_LOAD_OK);
    BOOST_CHECK_EQUAL(firstRun, true);

    auto& meta = pwalletMain->mapKeyMetadata[masterId];
    meta.nCreateTime = GetTime();
    meta.hdKeypath = "m";
    meta.hdMasterKeyID = masterId;

    BOOST_CHECK_EQUAL(pwalletMain->AddKeyPubKey(masterPriv, masterPub), true);
    BOOST_CHECK_EQUAL(pwalletMain->SetHDMasterKey(masterPub), true);
    pwalletMain->SetBestChain(chainActive.GetLocator());

    RegisterValidationInterface(pwalletMain);
    RegisterWalletRPCCommands(tableRPC);

    wallet.reset(new TestSigmaWallet());
    wallet->ReloadMasterKey();

    // Generate mints again and it should have exactly the same as before.
    std::vector<SigmaMintId> after;

    for (auto& id : before) {
        after.push_back(wallet->GenerateMint(id.property, id.denomination));
    }

    BOOST_CHECK_EQUAL(after, before);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium
