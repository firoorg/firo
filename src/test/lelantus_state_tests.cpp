#include "../lelantus.h"
#include "../validation.h"

#include "fixtures.h"
#include "test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace lelantus {

class LelantusStateTests : public LelantusTestingSetup {
public:
    LelantusStateTests() : LelantusTestingSetup(),
        lelantusState(CLelantusState::GetState()) {
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
        std::vector<secp_primitives::GroupElement> const &mints) {
        block.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();
        block.lelantusTxInfo->mints.insert(block.lelantusTxInfo->mints.end(), mints.begin(), mints.end());
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

    GenerateBlock({txs[0]});

    auto blockIdx = chainActive.Tip();
    auto block = GetCBlock(blockIdx);
    PopulateLelantusTxInfo(block, {mints[0].GetPubcoinValue()});

    lelantusState->AddMintsToStateAndBlockIndex(blockIdx, &block);

    GenerateBlock({txs[1]});

    blockIdx = chainActive.Tip();
    block = GetCBlock(blockIdx);
    PopulateLelantusTxInfo(block, {mints[1].GetPubcoinValue()});

    lelantusState->AddMintsToStateAndBlockIndex(blockIdx, &block);

    auto r = lelantusState->GetMintedCoinHeightAndId(mints[0].GetPubcoinValue())
    ;

    // verify heigh and id was assigned.
    BOOST_CHECK(std::make_pair(chainActive.Height() - 1, 1) == lelantusState->GetMintedCoinHeightAndId(mints[0].GetPubcoinValue()));
    BOOST_CHECK(std::make_pair(chainActive.Height(), 1) == lelantusState->GetMintedCoinHeightAndId(mints[1].GetPubcoinValue()));
    BOOST_CHECK(std::make_pair(-1, -1) == lelantusState->GetMintedCoinHeightAndId(mints[2].GetPubcoinValue()));

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
    PopulateLelantusTxInfo(block, {mints[0].GetPubcoinValue()});

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
    PopulateLelantusTxInfo(block, {mint.GetPubcoinValue()});

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

// TODO:
// - test surge detection. should not work for now.
// - test get coins to spend

BOOST_AUTO_TEST_SUITE_END()

}