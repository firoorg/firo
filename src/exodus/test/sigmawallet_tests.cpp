// Copyright (c) 2019 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../sigmadb.h"
#include "../sigmawallet.h"

#include "../../wallet/test/wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>

namespace exodus {

class TestSigmaWallet : public SigmaWallet {

public:
    TestSigmaWallet() : SigmaWallet()
    {
    }

public:
    bool GeneratePrivateKey(uint512 const &seed, exodus::SigmaPrivateKey &coin)
    {
        return SigmaWallet::GeneratePrivateKey(seed, coin);
    }

    template<class OutIt>
    void GetMintPoolEntry(OutIt it) {
        for (auto const & e : mintPool) {
            *it++ = e;
        }
    }
};

struct SigmaWalletTestingSetup : ::WalletTestingSetup
{
    SigmaWalletTestingSetup() : sigmaWallet()
    {
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

    SigmaPrivateKey key;
    sigmaWallet.GeneratePrivateKey(seed, key);

    BOOST_CHECK_EQUAL(
        std::string("4d75cc284921b44e9acbf67cdabbd8a5c61057a4fa5b7aedbe01994e55e3c0b6"),
        key.serial.GetHex());

    BOOST_CHECK_EQUAL(
        std::string("d2e5b830ab1fa8235a9af7db4fd554de5757a0e594acbfc1a4526c3fb26bcbbd"),
        key.randomness.GetHex());
}

BOOST_AUTO_TEST_CASE(verify_mint_pool_have_been_generened)
{
    std::vector<MintPoolEntry> mintPool;
    sigmaWallet.GetMintPoolEntry(std::back_inserter(mintPool));
    BOOST_CHECK_EQUAL(20, mintPool.size());
}

BOOST_AUTO_TEST_CASE(tryrecover_random_coin)
{
    SigmaPrivateKey priv;
    priv.Generate();

    SigmaPublicKey pub(priv, DefaultSigmaParams);
    SigmaMintId id(1, 0, pub);


    std::vector<MintPoolEntry> mintPool;
    sigmaWallet.GetMintPoolEntry(std::back_inserter(mintPool));

    // verify state before
    BOOST_CHECK_EQUAL(false, sigmaWallet.HasMint(id));

    // `false` should be returned
    BOOST_CHECK_EQUAL(false, sigmaWallet.TryRecoverMint(
        id, SigmaMintChainState(1000, 0, 1000)
    ));

    // verify after, mint wallet should not change
    std::vector<MintPoolEntry> mintPoolAfter;
    sigmaWallet.GetMintPoolEntry(std::back_inserter(mintPoolAfter));

    BOOST_CHECK(mintPool == mintPoolAfter);
    BOOST_CHECK_EQUAL(false, sigmaWallet.HasMint(id));
}

BOOST_AUTO_TEST_CASE(tryrecover_mintpool_coin)
{
    std::vector<MintPoolEntry> mintPool;
    sigmaWallet.GetMintPoolEntry(std::back_inserter(mintPool));
    SigmaMintId id(1, 0, mintPool.front().key);

    // verify state before
    BOOST_CHECK_EQUAL(false, sigmaWallet.HasMint(id));

    BOOST_CHECK_EQUAL(true, sigmaWallet.TryRecoverMint(
        id,
        SigmaMintChainState(1000, 0, 1000)
    ));

    // verify state after, mint wallet should be updated
    std::vector<MintPoolEntry> mintPoolAfter;
    sigmaWallet.GetMintPoolEntry(std::back_inserter(mintPoolAfter));

    BOOST_CHECK(mintPool != mintPoolAfter);

    // mintPool[1:] == mintPoolAfter[:size - 1]
    BOOST_CHECK_EQUAL(true,
        std::equal(mintPool.begin() + 1, mintPool.end(), mintPoolAfter.begin()));

    BOOST_CHECK_EQUAL(true, sigmaWallet.HasMint(id));
}

BOOST_AUTO_TEST_CASE(tryrecover_already_in_wallet_coin)
{
    PropertyId prop = 1;
    SigmaDenomination denom = 0;

    SigmaPrivateKey priv;
    std::tie(std::ignore, priv) = sigmaWallet.GenerateMint(prop, denom);

    SigmaMintId id(prop, denom, SigmaPublicKey(priv, DefaultSigmaParams));

    std::vector<MintPoolEntry> mintPool;
    sigmaWallet.GetMintPoolEntry(std::back_inserter(mintPool));

    // verify state before
    BOOST_CHECK_EQUAL(true, sigmaWallet.HasMint(id));

    BOOST_CHECK_EQUAL(false, sigmaWallet.TryRecoverMint(
        id,
        SigmaMintChainState(1000, 0, 1000)
    ));

    // verify state after, mint wallet should not be changed
    std::vector<MintPoolEntry> mintPoolAfter;
    sigmaWallet.GetMintPoolEntry(std::back_inserter(mintPoolAfter));

    BOOST_CHECK(mintPool == mintPoolAfter);

    BOOST_CHECK_EQUAL(true, sigmaWallet.HasMint(id));
}

BOOST_AUTO_TEST_CASE(listmints_empty_wallet)
{
    std::vector<SigmaMint> mints;
    sigmaWallet.ListMints(std::back_inserter(mints), false, false);
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

    auto testListMints =
        [&](std::vector<SigmaMint> const &expected, bool unusedOnly, bool matureOnly) {

        std::vector<SigmaMint> mints;
        sigmaWallet.ListMints(std::back_inserter(mints), unusedOnly, matureOnly);
        BOOST_CHECK_EQUAL(expected.size(), mints.size());
        BOOST_CHECK_EQUAL(
            true,
            std::is_permutation(
                mints.begin(), mints.end(),
                expected.begin(),
                sigmaMintComparer
            )
        );
    };

    // test
    testListMints({unconfirmed.first, unspend.first, spend.first}, false, false);
    testListMints({unconfirmed.first, unspend.first}, true, false);
    testListMints({unspend.first, spend.first}, false, true);
    testListMints({unspend.first}, true, true);
}

BOOST_AUTO_TEST_SUITE_END()

}