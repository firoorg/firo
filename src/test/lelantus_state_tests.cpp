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

    auto blockIdx = GenerateBlock({txs[0]});
    auto block = GetCBlock(blockIdx);
    PopulateLelantusTxInfo(block, {mints[0].GetPubcoinValue()}, {});

    lelantusState->AddMintsToStateAndBlockIndex(blockIdx, &block);

    blockIdx = GenerateBlock({txs[1]});
    block = GetCBlock(blockIdx);
    PopulateLelantusTxInfo(block, {mints[1].GetPubcoinValue()}, {});

    lelantusState->AddMintsToStateAndBlockIndex(blockIdx, &block);

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

// TODO:
// - test surge detection. should not work for now.
// - test get coins to spend

BOOST_AUTO_TEST_SUITE_END()

}