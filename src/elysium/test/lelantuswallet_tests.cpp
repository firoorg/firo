// Copyright (c) 2020 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../../lelantus.h"
#include "../../test/fixtures.h"

#include "../wallet/test/wallet_test_fixture.h"

#include "../lelantusdb.h"
#include "../lelantuswallet.h"

#include <boost/test/unit_test.hpp>

class TestLelantusWallet : public LelantusWallet
{
public:
    TestLelantusWallet() : LelantusWallet(new LelantusWallet::Database)
    {
    }

public:
    MintPool& GetMintPool()
    {
        return mintPool;
    }

    uint32_t GetSeedIndex(CKeyID const &seedId/*, uint32_t &change*/)
    {
        uint32_t change;
        return LelantusWallet::GetSeedIndex(seedId, change);
    }
};

struct LelantusWalletTestingSetup : LelantusTestingSetup
{
    std::unique_ptr<TestLelantusWallet> wallet;

    LelantusWalletTestingSetup() : wallet(new TestLelantusWallet)
    {
        lelantusDb = new LelantusDb(pathTemp / "elysium_lelantus_tests", true);
        wallet->ReloadMasterKey();
    }
};

namespace lelantus {

BOOST_FIXTURE_TEST_SUITE(elysium_lelantuswallet_tests, LelantusWalletTestingSetup)

#define CHECK_EXPECTED_INDEX(e, r) BOOST_CHECK_EQUAL(e, wallet->GetSeedIndex(r.GetMintPoolEntry().seedId));

BOOST_AUTO_TEST_CASE(mint_reservation)
{
    auto &mintPool = wallet->GetMintPool();

    {
        // commit nothing
        auto recv1 = wallet->GenerateMint(3, 10 * COIN);
        CHECK_EXPECTED_INDEX(0, recv1);

        auto recv2 = wallet->GenerateMint(3, 20 * COIN);
        CHECK_EXPECTED_INDEX(1, recv2);

        BOOST_CHECK_EQUAL(20, mintPool.size());
    }
    BOOST_CHECK_EQUAL(22, mintPool.size());

    {
        // commit some coin
        auto recv1 = wallet->GenerateMint(3, 10 * COIN);
        CHECK_EXPECTED_INDEX(0, recv1);

        auto recv2 = wallet->GenerateMint(3, 20 * COIN);
        CHECK_EXPECTED_INDEX(1, recv2);

        BOOST_CHECK_EQUAL(20, mintPool.size());

        recv1.Commit();
    }
    BOOST_CHECK_EQUAL(21, mintPool.size());

    {
        // commit skip some index
        // commit some coin
        auto recv1 = wallet->GenerateMint(3, 10 * COIN);
        CHECK_EXPECTED_INDEX(1, recv1);

        auto recv2 = wallet->GenerateMint(3, 20 * COIN);
        CHECK_EXPECTED_INDEX(2, recv2);

        BOOST_CHECK_EQUAL(20, mintPool.size());

        recv2.Commit();
    }
    BOOST_CHECK_EQUAL(21, mintPool.size());

    {
        // next time should got index 1
        auto recv1 = wallet->GenerateMint(3, 10 * COIN);
        CHECK_EXPECTED_INDEX(1, recv1);

        recv1.Commit();
    }
    BOOST_CHECK_EQUAL(20, mintPool.size()); // should not be added back

    {
        // next time should get index 3 since index 2 is used
        auto recv1 = wallet->GenerateMint(3, 10 * COIN);
        CHECK_EXPECTED_INDEX(3, recv1);

        recv1.Commit();
    }
    BOOST_CHECK_EQUAL(20, mintPool.size()); // should not be added back again
}

#undef CHECK_EXPECTED_INDEX

BOOST_AUTO_TEST_CASE(joinsplit_building)
{
    constexpr PropertyId property = 3;
    constexpr size_t AllMints = 10;

    GenerateBlocks(110);

    std::vector<MintEntryId> ids;
    for (size_t i = 0; i != AllMints; i++) {
        auto r = wallet->GenerateMint(property, 100 * COIN);
        r.Commit();

        CDataStream  ss(SER_NETWORK, PROTOCOL_VERSION);
        lelantus::GenerateMintSchnorrProof(r.coin, ss);

        std::vector<unsigned char> data(ss.begin(), ss.end());
        lelantusDb->WriteMint(property, r.coin.getPublicCoin(), 100, r.id, 100 * COIN, data);

        ids.push_back(r.id);
    }
    lelantusDb->CommitCoins();

    for (size_t i = 0; i != AllMints; i++) {
        LelantusMintChainState chainState(100, 0, i);
        BOOST_CHECK_NO_THROW(wallet->UpdateMintChainstate(ids[i], chainState));
    }

    uint256 metaData = ArithToUint256(2);
    std::vector<SpendableCoin> spendables;
    boost::optional<LelantusWallet::MintReservation> mintReservation;
    LelantusAmount changeAmount;

    BOOST_CHECK_NO_THROW(wallet->CreateJoinSplit(
        property, 200 * COIN, metaData, spendables, mintReservation, changeAmount));
}

BOOST_AUTO_TEST_SUITE_END()

}; // namespace lelantus