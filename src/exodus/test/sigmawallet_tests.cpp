// Copyright (c) 2019 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../sigmadb.h"
#include "../sigmawallet.h"

#include "../../wallet/test/wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>

namespace exodus {

class TestSigmaWallet : public SigmaWallet
{

public:
    TestSigmaWallet()
    {
    }

public:
    SigmaPrivateKey GeneratePrivateKey(uint512 const &seed)
    {
        return SigmaWallet::GeneratePrivateKey(seed);
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
};

struct SigmaWalletTestingSetup : ::WalletTestingSetup
{
    SigmaWalletTestingSetup()
    {
        sigmaWallet.ReloadMasterKey();
    }

    TestSigmaWallet sigmaWallet;
};

BOOST_FIXTURE_TEST_SUITE(exodus_sigmawallet_tests, SigmaWalletTestingSetup)

BOOST_AUTO_TEST_CASE(generate_private_key)
{
    uint512 seed;
    seed.SetHex(
        "5ead609e466f37c92b671e3725da4cd98adafdb23496369c09196f30f8d716dc9f67"
        "9026b2f94984f94a289208a2941579ef321dee63d8fd6346ef665c6f60df"
    );

    auto key = sigmaWallet.GeneratePrivateKey(seed);

    BOOST_CHECK_EQUAL(
        std::string("cb30cc143888ef4e09bb4cfd6d0a699e3c089f42419a8a200132e3190e0e5951"),
        key.serial.GetHex());

    BOOST_CHECK_EQUAL(
        std::string("d2e5b830ab1fa8235a9af7db4fd554de5757a0e594acbfc1a4526c3fb26bcbbd"),
        key.randomness.GetHex());
}

BOOST_AUTO_TEST_CASE(verify_mint_pool_have_been_generened)
{
    auto mintPool = sigmaWallet.GetMintPoolEntry();
    BOOST_CHECK_EQUAL(20, mintPool.size());
}

BOOST_AUTO_TEST_CASE(save_and_load_mintpool)
{
    auto mints = sigmaWallet.GetMintPoolEntry();

    // delete last mint from pool and save
    auto &pool = sigmaWallet.GetMintPool();
    pool.erase(pool.find(19), pool.end());
    sigmaWallet.SaveMintPool();

    // delete more 9 mints
    pool.erase(pool.find(10), pool.end());
    auto mutatedMintPools = sigmaWallet.GetMintPoolEntry();
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
    sigmaWallet.LoadMintPool();

    auto loadedMintPools = sigmaWallet.GetMintPoolEntry();
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
    auto mints = sigmaWallet.GetMintPoolEntry();

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


    auto mintPool = sigmaWallet.GetMintPoolEntry();

    // verify state before
    BOOST_CHECK_EQUAL(false, sigmaWallet.HasMint(id));

    // `false` should be returned
    BOOST_CHECK_EQUAL(false, sigmaWallet.TryRecoverMint(
        id, SigmaMintChainState(1000, 0, 1000)
    ));

    // verify after, mint wallet should not change
    auto mintPoolAfter = sigmaWallet.GetMintPoolEntry();

    BOOST_CHECK(mintPool == mintPoolAfter);
    BOOST_CHECK_EQUAL(false, sigmaWallet.HasMint(id));
}

BOOST_AUTO_TEST_CASE(tryrecover_mintpool_coin)
{
    auto mintPool = sigmaWallet.GetMintPoolEntry();
    SigmaMintId id(1, 0, mintPool.front().key);

    // verify state before
    BOOST_CHECK_EQUAL(false, sigmaWallet.HasMint(id));

    BOOST_CHECK_EQUAL(true, sigmaWallet.TryRecoverMint(
        id,
        SigmaMintChainState(1000, 0, 1000)
    ));

    // verify state after, mint wallet should be updated
    auto mintPoolAfter = sigmaWallet.GetMintPoolEntry();

    BOOST_CHECK(mintPool != mintPoolAfter);

    // mintPool[1:] == mintPoolAfter[:size - 1]
    BOOST_CHECK_EQUAL(true,
        std::equal(mintPool.begin() + 1, mintPool.end(), mintPoolAfter.begin()));

    BOOST_CHECK_EQUAL(20, mintPoolAfter.size()); // ensure mint pool is refilled
    BOOST_CHECK_EQUAL(20, mintPoolAfter.back().index); // make sure new coin contain next index
    BOOST_CHECK_EQUAL(true, sigmaWallet.HasMint(id));
}

BOOST_AUTO_TEST_CASE(tryrecover_already_in_wallet_coin)
{
    PropertyId prop = 1;
    SigmaDenomination denom = 0;

    SigmaPrivateKey priv;
    std::tie(std::ignore, priv) = sigmaWallet.GenerateMint(prop, denom);

    SigmaMintId id(prop, denom, SigmaPublicKey(priv, DefaultSigmaParams));

    auto mintPool = sigmaWallet.GetMintPoolEntry();

    // verify state before
    BOOST_CHECK_EQUAL(true, sigmaWallet.HasMint(id));

    BOOST_CHECK_EQUAL(false, sigmaWallet.TryRecoverMint(
        id,
        SigmaMintChainState(1000, 0, 1000)
    ));

    // verify state after, mint wallet should not be changed
    auto mintPoolAfter = sigmaWallet.GetMintPoolEntry();

    BOOST_CHECK(mintPool == mintPoolAfter);

    BOOST_CHECK_EQUAL(true, sigmaWallet.HasMint(id));
}

BOOST_AUTO_TEST_CASE(listmints_empty_wallet)
{
    std::vector<SigmaMint> mints;
    sigmaWallet.ListMints(std::back_inserter(mints));
    BOOST_CHECK_EQUAL(0, mints.size());
}

BOOST_AUTO_TEST_CASE(listmints_non_empty_wallet)
{
    // generate 3 coins which is
    // 1. unconfirmed
    // 2. confirmed and unspend
    // 3. spend
    PropertyId prop = 10;
    SigmaDenomination denom = 0;

    auto unconfirmed = sigmaWallet.GenerateMint(prop, denom);
    auto unspend = sigmaWallet.GenerateMint(prop, denom);
    sigmaWallet.UpdateMintChainstate(
        SigmaMintId(prop, denom, SigmaPublicKey(unspend.second, DefaultSigmaParams)),
        SigmaMintChainState(100, 0, 1000));

    auto spend = sigmaWallet.GenerateMint(prop, denom);
    sigmaWallet.UpdateMintChainstate(
        SigmaMintId(prop, denom, SigmaPublicKey(spend.second, DefaultSigmaParams)),
        SigmaMintChainState(100, 0, 1001));

    sigmaWallet.UpdateMintSpendTx(
        SigmaMintId(prop, denom, SigmaPublicKey(spend.second, DefaultSigmaParams)),
        uint256S("1"));

    // prepare testing function
    auto sigmaMintComparer = [](SigmaMint const &a, SigmaMint const &b) -> bool {
        return a.property == b.property &&
            a.denomination == b.denomination &&
            a.seedId == b.seedId;
    };



    std::vector<SigmaMint> mints;
    sigmaWallet.ListMints(std::back_inserter(mints));
    BOOST_CHECK_EQUAL(
        true,
        std::is_permutation(
            mints.begin(), mints.end(),
            std::vector<SigmaMint>{
                unconfirmed.first, unspend.first, spend.first
            }.begin(),
            sigmaMintComparer
        )
    );
}

BOOST_AUTO_TEST_CASE(delete_out_wallet_mint)
{
    SigmaPrivateKey privKey;
    privKey.Generate();
    SigmaPublicKey pubKey(privKey, DefaultSigmaParams);

    SigmaMintId id(10, 0, pubKey);

    BOOST_CHECK_EXCEPTION(
        sigmaWallet.DeleteUnconfirmedMint(id),
        std::runtime_error,
        [](std::runtime_error const &e) -> bool{
            return std::string("no mint data in wallet") == e.what();
        }
    );
}

BOOST_AUTO_TEST_CASE(push_mint_back)
{
    auto mintPool = sigmaWallet.GetMintPoolEntry();

    SigmaMint mint;
    SigmaPrivateKey privKey;
    std::tie(mint, privKey) = sigmaWallet.GenerateMint(1, 0);

    SigmaMintId id(1, 0, SigmaPublicKey(privKey, DefaultSigmaParams));

    BOOST_CHECK(sigmaWallet.HasMint(id));
    BOOST_CHECK(!sigmaWallet.IsMintInPool(id.pubKey));
    sigmaWallet.DeleteUnconfirmedMint(id);
    BOOST_CHECK(!sigmaWallet.HasMint(id));
    BOOST_CHECK(sigmaWallet.IsMintInPool(id.pubKey));

    auto mintPoolAfter = sigmaWallet.GetMintPoolEntry();

    BOOST_CHECK_EQUAL(21, mintPoolAfter.size());
    BOOST_CHECK(mint.seedId == mintPoolAfter.front().seedId);
}

BOOST_AUTO_TEST_CASE(clear_chain_state)
{
    // generate 10 coins and set state
    std::vector<SigmaMint> generatedMints;
    for (size_t i = 0; i < 10; i++) {
        SigmaMint mint;
        SigmaPrivateKey privKey;
        std::tie(mint, privKey) = sigmaWallet.GenerateMint(1, 0);

        SigmaPublicKey pubKey(privKey, DefaultSigmaParams);

        SigmaMintId id(1, 0, pubKey);
        SigmaMintChainState state(100, 0, i);
        sigmaWallet.UpdateMintChainstate(id, state);

        if (i % 2) {
            sigmaWallet.UpdateMintSpendTx(id, uint256S(std::to_string(i)));
            mint.spendTx = uint256S(std::to_string(i));
        }

        mint.chainState = state;
        generatedMints.push_back(mint);
    }

    // verify created coins is valid
    std::vector<SigmaMint> mints;
    sigmaWallet.ListMints(std::back_inserter(mints));

    BOOST_CHECK_EQUAL(
        true,
        std::is_permutation(
            generatedMints.begin(), generatedMints.end(),
            mints.begin(),
            [](SigmaMint const &a, SigmaMint const &b) -> bool {
                return a == b;
            }
        )
    );

    // clear state and check
    sigmaWallet.ClearMintsChainState();

    std::vector<SigmaMint> clearedMints;
    sigmaWallet.ListMints(std::back_inserter(clearedMints));

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
    auto &mintPool = sigmaWallet.GetMintPool();

    std::vector<uint32_t> erasedIdxs = {0, 10, 15};
    for (auto idx : erasedIdxs) {
        mintPool.erase(mintPool.find(idx));
    }

    sigmaWallet.FillMintPool();

    mintPool = sigmaWallet.GetMintPool();
    BOOST_CHECK_EQUAL(20, mintPool.size());

    for (uint32_t idx = 0; idx < mintPool.size() + erasedIdxs.size(); idx++) {

        auto shouldBeDeleted = std::find(erasedIdxs.begin(), erasedIdxs.end(), idx) != erasedIdxs.end();
        auto foundInPool = mintPool.find(idx) != mintPool.end();

        BOOST_CHECK_EQUAL(
            !shouldBeDeleted,
            foundInPool
        );
    }
}

BOOST_AUTO_TEST_CASE(remove_from_mintpool)
{
    auto &mintPool = sigmaWallet.GetMintPool();

    std::vector<uint32_t> removedIdxs = {0, 10, 15};
    std::vector<uint32_t> expectedSizeAfterRemove = {19, 18, 17};

    for (size_t i = 0; i < removedIdxs.size(); i++) {
        auto idx = removedIdxs[i];
        auto expectedSize = expectedSizeAfterRemove[i];

        sigmaWallet.RemoveFromMintPool(mintPool.find(idx)->key);

        // verify auto refill
        BOOST_CHECK_EQUAL(expectedSize, mintPool.size());
        BOOST_CHECK_EQUAL(
            true,
            mintPool.find(idx) == mintPool.end()
        );
    }
}

BOOST_AUTO_TEST_SUITE_END()

}