#include "../lelantus.h"
#include "../validation.h"

#include "fixtures.h"
#include "test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace std {

template<typename Char, typename Traits, typename Item1, typename Item2>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const pair<Item1, Item2>& p)
{
    return os << '(' << p.first << ", " << p.second << ')';
}

}

namespace lelantus {

class LelantusStateTests : public LelantusTestingSetup {
public:
    LelantusStateTests() : LelantusTestingSetup(),
        lelantusState(CLelantusState::GetState()) {
    }

    ~LelantusStateTests() {
        lelantusState->Reset();
    }

public:
    CBlock GetCBlock(CBlockIndex const *blockIdx) {
        CBlock block;
        if (!ReadBlockFromDisk(block, blockIdx, ::Params().GetConsensus())) {
            throw std::invalid_argument("No block index data");
        }

        return block;
    }

    void PopulateLelantusTxInfo(
        CBlock &block,
        std::vector<secp_primitives::GroupElement> const &mints,
        std::vector<std::pair<Scalar, int>> const &serials) {
        block.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();
        block.lelantusTxInfo->mints.insert(block.lelantusTxInfo->mints.end(), mints.begin(), mints.end());

        for (auto const &s : serials) {
            block.lelantusTxInfo->spentSerials.emplace(s);
        }
    }

public:
    CLelantusState *lelantusState;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_state_tests, LelantusStateTests)

BOOST_AUTO_TEST_CASE(add_mints_to_state)
{
    // Try to add some mints to state.

    GenerateBlocks(110);

    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints({1 * COIN, 2 * COIN, 1 * CENT}, txs);

    auto blockIdx1 = GenerateBlock({txs[0]});
    auto block1 = GetCBlock(blockIdx1);
    PopulateLelantusTxInfo(block1, {mints[0].GetPubcoinValue()}, {});

    lelantusState->AddMintsToStateAndBlockIndex(blockIdx1, &block1);

    auto blockIdx2 = GenerateBlock({txs[1]});
    auto block2 = GetCBlock(blockIdx2);
    PopulateLelantusTxInfo(block2, {mints[1].GetPubcoinValue()}, {});

    lelantusState->AddMintsToStateAndBlockIndex(blockIdx2, &block2);

    // verify heigh and id was assigned.
    BOOST_CHECK_EQUAL(std::make_pair(chainActive.Height() - 1, 1), lelantusState->GetMintedCoinHeightAndId(mints[0].GetPubcoinValue()));
    BOOST_CHECK_EQUAL(std::make_pair(chainActive.Height(), 1), lelantusState->GetMintedCoinHeightAndId(mints[1].GetPubcoinValue()));
    BOOST_CHECK_EQUAL(std::make_pair(-1, -1), lelantusState->GetMintedCoinHeightAndId(mints[2].GetPubcoinValue()));

    // test has coin
    BOOST_CHECK(lelantusState->HasCoin(mints[0].GetPubcoinValue()));
    BOOST_CHECK(lelantusState->HasCoin(mints[1].GetPubcoinValue()));
    BOOST_CHECK(!lelantusState->HasCoin(mints[2].GetPubcoinValue()));

    // test has coin hash
    GroupElement received;
    BOOST_CHECK(lelantusState->HasCoinHash(received, mints[0].GetPubCoinHash()));
    BOOST_CHECK(mints[0].GetPubcoinValue() == received);

    BOOST_CHECK(!lelantusState->HasCoinHash(received, mints[2].GetPubCoinHash()));

    BOOST_CHECK_EQUAL(2, lelantusState->GetTotalCoins());

    // check group info
    CLelantusState::LelantusCoinGroupInfo group, fakeGroup;
    BOOST_CHECK(lelantusState->GetCoinGroupInfo(1, group));
    BOOST_CHECK(!lelantusState->GetCoinGroupInfo(0, fakeGroup));
    BOOST_CHECK(!lelantusState->GetCoinGroupInfo(2, fakeGroup));

    BOOST_CHECK(blockIdx1 == group.firstBlock);
    BOOST_CHECK(blockIdx2 == group.lastBlock);
    BOOST_CHECK_EQUAL(2, group.nCoins);

    BOOST_CHECK_EQUAL(1, lelantusState->GetLatestCoinID());
}

BOOST_AUTO_TEST_CASE(serial_adding)
{
    GenerateBlocks(110);

    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints({1 * COIN, 2 * COIN, 1 * CENT}, txs);

    GenerateBlock(txs);

    auto blockIdx = chainActive.Tip();
    auto block = GetCBlock(blockIdx);
    PopulateLelantusTxInfo(block, {mints[0].GetPubcoinValue()}, {});

    lelantusState->AddMintsToStateAndBlockIndex(blockIdx, &block);

    Scalar serial1(1), serial2(2);
    auto serialHash1 = primitives::GetSerialHash(serial1);
    auto serialHash2 = primitives::GetSerialHash(serial2);

    lelantusState->AddSpend(serial1, 1);

    Scalar receivedSerial;
    BOOST_CHECK(lelantusState->IsUsedCoinSerial(serial1));
    BOOST_CHECK(lelantusState->IsUsedCoinSerialHash(receivedSerial, serialHash1));
    BOOST_CHECK(serial1 == receivedSerial);

    BOOST_CHECK(!lelantusState->IsUsedCoinSerial(serial2));
    BOOST_CHECK(!lelantusState->IsUsedCoinSerialHash(receivedSerial, serialHash2));
}

BOOST_AUTO_TEST_CASE(mempool)
{
    GenerateBlocks(110);

    std::vector<CMutableTransaction> txs;
    auto mint = GenerateMints({1 * COIN}, txs)[0];

    GenerateBlock(txs);

    auto blockIdx = chainActive.Tip();
    auto block = GetCBlock(blockIdx);
    PopulateLelantusTxInfo(block, {mint.GetPubcoinValue()}, {});

    lelantusState->AddMintsToStateAndBlockIndex(blockIdx, &block);

    Scalar spendSerial(1);
    lelantusState->AddSpend(spendSerial, 1);

    // test mint mempool
    // - can not add on-chain coin
    BOOST_CHECK(!lelantusState->CanAddMintToMempool(mint.GetPubcoinValue()));

    // - can not add duplicated coin
    GroupElement randMint;
    randMint.randomize();

    BOOST_CHECK(lelantusState->CanAddMintToMempool(randMint));
    lelantusState->AddMintsToMempool({randMint});
    BOOST_CHECK(!lelantusState->CanAddMintToMempool(randMint));

    // - remove from mempool then can add again
    lelantusState->RemoveMintFromMempool(randMint);
    BOOST_CHECK(lelantusState->CanAddMintToMempool(randMint));

    // test spend mempool
    // - can not add on-chain spend
    BOOST_CHECK(!lelantusState->CanAddSpendToMempool(spendSerial));

    // - can not add duplicated serial
    Scalar anotherSerial(2);
    auto txid = ArithToUint256(1);

    BOOST_CHECK(lelantusState->CanAddSpendToMempool(anotherSerial));
    lelantusState->AddSpendToMempool({anotherSerial}, txid);
    BOOST_CHECK(!lelantusState->CanAddSpendToMempool(anotherSerial));

    BOOST_CHECK(txid ==
        lelantusState->GetMempoolConflictingTxHash(anotherSerial));

    Scalar fakeSerial(3);
    BOOST_CHECK(uint256() ==
        lelantusState->GetMempoolConflictingTxHash(fakeSerial));

    // - remove spend then can add again
    lelantusState->RemoveSpendFromMempool({anotherSerial});
    BOOST_CHECK(lelantusState->CanAddSpendToMempool(anotherSerial));
    lelantusState->AddSpendToMempool({anotherSerial}, txid);
    BOOST_CHECK(!lelantusState->CanAddSpendToMempool(anotherSerial));
}

BOOST_AUTO_TEST_CASE(add_remove_block)
{
    // No coins and serials
    auto index1 = GenerateBlock({});
    auto block1 = GetCBlock(index1);
    PopulateLelantusTxInfo(block1, {}, {});

    lelantusState->AddBlock(index1);

    BOOST_CHECK_EQUAL(0, lelantusState->GetMints().size());
    BOOST_CHECK_EQUAL(0, lelantusState->GetSpends().size());

    // some mints
    GroupElement mint1, mint2;
    mint1.randomize();
    mint2.randomize();

    auto index2 = GenerateBlock({});
    auto block2 = GetCBlock(index2);
    PopulateLelantusTxInfo(block2, {mint1, mint2}, {});

    lelantusState->AddMintsToStateAndBlockIndex(index2, &block2);
    lelantusState->AddBlock(index2);

    BOOST_CHECK_EQUAL(2, lelantusState->GetMints().size());
    BOOST_CHECK_EQUAL(0, lelantusState->GetSpends().size());

    // some serials
    Scalar serial1, serial2;
    serial1.randomize();
    serial2.randomize();

    auto index3 = GenerateBlock({});
    auto block3 = GetCBlock(index3);
    PopulateLelantusTxInfo(block3, {}, {{serial1, 1}, {serial2, 1}});
    index3->lelantusSpentSerials = block3.lelantusTxInfo->spentSerials;

    lelantusState->AddBlock(index3);

    BOOST_CHECK_EQUAL(2, lelantusState->GetMints().size());
    BOOST_CHECK_EQUAL(2, lelantusState->GetSpends().size());

    // both mint and serial
    GroupElement mint3;
    mint3.randomize();

    Scalar serial3;
    serial3.randomize();

    auto index4 = GenerateBlock({});
    auto block4 = GetCBlock(index4);
    PopulateLelantusTxInfo(block4, {mint3}, {{serial3, 2}});
    lelantusState->AddMintsToStateAndBlockIndex(index4, &block4);
    index4->lelantusSpentSerials = block4.lelantusTxInfo->spentSerials;

    lelantusState->AddBlock(index4);

    BOOST_CHECK_EQUAL(3, lelantusState->GetMints().size());
    BOOST_CHECK_EQUAL(3, lelantusState->GetSpends().size());

    // remove last block
    lelantusState->RemoveBlock(index4);

    BOOST_CHECK_EQUAL(2, lelantusState->GetMints().size());
    BOOST_CHECK_EQUAL(2, lelantusState->GetSpends().size());

    // verify mints and spends on blocks
    BOOST_CHECK(lelantusState->HasCoin(mint1));
    BOOST_CHECK(lelantusState->HasCoin(mint2));
    BOOST_CHECK(!lelantusState->HasCoin(mint3));

    BOOST_CHECK(lelantusState->IsUsedCoinSerial(serial1));
    BOOST_CHECK(lelantusState->IsUsedCoinSerial(serial2));
    BOOST_CHECK(!lelantusState->IsUsedCoinSerial(serial3));
}

BOOST_AUTO_TEST_CASE(get_coin_group)
{
    GenerateBlocks(120);

    std::vector<CAmount> amounts(12, COIN);
    std::vector<CMutableTransaction> txs;

    auto mints = GenerateMints(amounts, txs);

    std::vector<PublicCoin> coins;
    std::vector<CBlockIndex*> indexes;
    std::vector<CBlock> blocks;

    for (size_t i = 0; i != mints.size(); i += 2) {
        auto index = GenerateBlock({txs[i], txs[i + 1]});
        auto block = GetCBlock(index);
        coins.push_back(mints[i + 1].GetPubcoinValue());
        coins.push_back(mints[i].GetPubcoinValue());

        PopulateLelantusTxInfo(
            block,
            {
                mints[i].GetPubcoinValue(),
                mints[i + 1].GetPubcoinValue()
            }, {});

        indexes.push_back(index);
        blocks.push_back(block);

        GenerateBlock({});
    }

    size_t maxSize = 6;
    size_t startCoin = 2;
    auto lelantusState = new CLelantusState(maxSize, startCoin);

    auto addMintsToState = [&](CBlockIndex *index, CBlock const &block) {
        lelantusState->AddMintsToStateAndBlockIndex(index, &block);
    };

    auto verifyMints = [&](size_t i, size_t j, std::vector<PublicCoin> const &coinSet) {
        std::vector<PublicCoin> expected(coins.begin() + i, coins.begin() + j);
        std::reverse(expected.begin(), expected.end());

        BOOST_CHECK(expected == coinSet);
    };

    auto verifyGroup = [&](int expectedId, size_t expectedCoins, CBlockIndex *expectedFirst, CBlockIndex *expectedLast, int testId = 0) -> bool {
        if (!testId) {
            testId = lelantusState->GetLatestCoinID();
        }

        CLelantusState::LelantusCoinGroupInfo group;

        BOOST_CHECK(lelantusState->GetCoinGroupInfo(testId, group));
        if (expectedId > 0) { // verify last Id
            BOOST_CHECK_EQUAL(expectedId, testId);
        }

        BOOST_CHECK_EQUAL(expectedCoins, group.nCoins);
        BOOST_CHECK_EQUAL(expectedFirst, group.firstBlock);
        BOOST_CHECK_EQUAL(expectedLast, group.lastBlock);
    };

    // 6 coins, 1(6), 2(0)
    addMintsToState(indexes[0], blocks[0]);
    addMintsToState(indexes[1], blocks[1]);
    addMintsToState(indexes[2], blocks[2]);

    verifyGroup(1, 6, indexes[0], indexes[2]);

    uint256 blockHashOut1;
    std::vector<PublicCoin> coinOut1;
    BOOST_CHECK_EQUAL(6, lelantusState->GetCoinSetForSpend(
        &chainActive,
        indexes[2]->nHeight,
        1,
        blockHashOut1,
        coinOut1));

    verifyMints(0, 6, coinOut1);
    BOOST_CHECK(indexes[2]->GetBlockHash() == blockHashOut1);

    // 8 coins, 1(6), 2(4)
    addMintsToState(indexes[3], blocks[3]);
    verifyGroup(2, 4, indexes[2], indexes[3]);
    verifyGroup(1, 6, indexes[0], indexes[2], 1);

    uint256 blockHashOut2;
    std::vector<PublicCoin> coinOut2;
    BOOST_CHECK_EQUAL(4, lelantusState->GetCoinSetForSpend(
        &chainActive,
        indexes[3]->nHeight + 1, // specify limit with no mints block
        2,
        blockHashOut2,
        coinOut2));

    verifyMints(4, 8, coinOut2);
    BOOST_CHECK(indexes[3]->GetBlockHash() == blockHashOut2);

    // 10 coins, 1(6), 2(6)
    addMintsToState(indexes[4], blocks[4]);

    verifyGroup(2, 6, indexes[2], indexes[4]);
    verifyGroup(1, 6, indexes[0], indexes[2], 1);

    uint256 blockHashOut3;
    std::vector<PublicCoin> coinOut3;
    BOOST_CHECK_EQUAL(6, lelantusState->GetCoinSetForSpend(
        &chainActive,
        indexes[4]->nHeight,
        2,
        blockHashOut3,
        coinOut3));

    verifyMints(4, 10, coinOut3);
    BOOST_CHECK(indexes[4]->GetBlockHash() == blockHashOut3);

    // 12 coins, 1(6), 2(6), 3(4)
    addMintsToState(indexes[5], blocks[5]);

    verifyGroup(3, 4, indexes[4], indexes[5]);
    verifyGroup(2, 6, indexes[2], indexes[4], 2);
    verifyGroup(1, 6, indexes[0], indexes[2], 1);

    uint256 blockHashOut4;
    std::vector<PublicCoin> coinOut4;
    BOOST_CHECK_EQUAL(4, lelantusState->GetCoinSetForSpend(
        &chainActive,
        indexes[5]->nHeight,
        3,
        blockHashOut4,
        coinOut4));

    verifyMints(8, 12, coinOut4);

    // Get first group
    uint256 blockHashOut5;
    std::vector<PublicCoin> coinOut5;
    BOOST_CHECK_EQUAL(6, lelantusState->GetCoinSetForSpend(
        &chainActive,
        indexes[5]->nHeight,
        1,
        blockHashOut5,
        coinOut5));

    verifyMints(0, 6, coinOut5);
    BOOST_CHECK(indexes[2]->GetBlockHash() == blockHashOut5);

    // Get first group with low max height
    uint256 blockHashOut6;
    std::vector<PublicCoin> coinOut6;
    BOOST_CHECK_EQUAL(2, lelantusState->GetCoinSetForSpend(
        &chainActive,
        indexes[0]->nHeight,
        1,
        blockHashOut6,
        coinOut6));

    verifyMints(0, 2, coinOut6);
    BOOST_CHECK(indexes[0]->GetBlockHash() == blockHashOut6);

    lelantusState->RemoveBlock(indexes[5]);
    verifyGroup(2, 6, indexes[2], indexes[4]);
    verifyGroup(1, 6, indexes[0], indexes[2], 1);
}

BOOST_AUTO_TEST_SUITE_END()

}