#include "../spark/state.h"
#include "../validation.h"
#include "../wallet/wallet.h"
#include "fixtures.h"
#include "test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace std
{

template <typename Char, typename Traits, typename Item1, typename Item2>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const pair<Item1, Item2>& p)
{
    return os << '(' << p.first << ", " << p.second << ')';
}

} // namespace std


class SparkStateTests : public SparkTestingSetup
{
public:
    SparkStateTests() : SparkTestingSetup(),
                        sparkState(spark::CSparkState::GetState())
    {
    }

    ~SparkStateTests()
    {
        sparkState->Reset();
    }

public:
    CBlock GetCBlock(CBlockIndex const* blockIdx)
    {
        CBlock block;
        if (!ReadBlockFromDisk(block, blockIdx, ::Params().GetConsensus())) {
            throw std::invalid_argument("No block index data");
        }

        return block;
    }

    void PopulateSparkTxInfo(
        CBlock& block,
        std::vector<spark::Coin> const& mints,
        std::vector<std::pair<GroupElement, int> > const& lTags)
    {
        block.sparkTxInfo = std::make_shared<spark::CSparkTxInfo>();
        block.sparkTxInfo->mints.insert(block.sparkTxInfo->mints.end(), mints.begin(), mints.end());

        for (auto const& lTag : lTags) {
            block.sparkTxInfo->spentLTags.emplace(lTag);
        }
    }
public:
    spark::CSparkState* sparkState;
};

BOOST_FIXTURE_TEST_SUITE(spark_state_tests, SparkStateTests)

BOOST_AUTO_TEST_CASE(add_mints_to_state)
{
    GenerateBlocks(1100);

    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints({1 * COIN, 2 * COIN, 1 * CENT}, txs);

    mempool.clear();
    auto blockIdx1 = GenerateBlock({txs[0]});
    auto block1 = GetCBlock(blockIdx1);
    PopulateSparkTxInfo(block1, {pwalletMain->sparkWallet->getCoinFromMeta(mints[0])}, {});

    sparkState->AddMintsToStateAndBlockIndex(blockIdx1, &block1);

    auto blockIdx2 = GenerateBlock({txs[1]});
    auto block2 = GetCBlock(blockIdx2);
    PopulateSparkTxInfo(block2, {pwalletMain->sparkWallet->getCoinFromMeta(mints[1])}, {});
    
    sparkState->AddMintsToStateAndBlockIndex(blockIdx2, &block2);
   
    //verify heigh and id was assigned.
    BOOST_CHECK_EQUAL(std::make_pair(chainActive.Height() - 1, 1), sparkState->GetMintedCoinHeightAndId(pwalletMain->sparkWallet->getCoinFromMeta(mints[0])));
    BOOST_CHECK_EQUAL(std::make_pair(chainActive.Height(), 1), sparkState->GetMintedCoinHeightAndId(pwalletMain->sparkWallet->getCoinFromMeta(mints[1])));
    BOOST_CHECK_EQUAL(std::make_pair(-1, -1), sparkState->GetMintedCoinHeightAndId(pwalletMain->sparkWallet->getCoinFromMeta(mints[2])));

    // test has coin
    BOOST_CHECK(sparkState->HasCoin(pwalletMain->sparkWallet->getCoinFromMeta(mints[0])));
    BOOST_CHECK(sparkState->HasCoin(pwalletMain->sparkWallet->getCoinFromMeta(mints[1])));
    BOOST_CHECK(!sparkState->HasCoin(pwalletMain->sparkWallet->getCoinFromMeta(mints[2])));

    // test has coin hash
    auto cn0 = pwalletMain->sparkWallet->getCoinFromMeta(mints[0]);
    BOOST_CHECK(sparkState->HasCoinHash(cn0, cn0.getHash()));
    auto cn1 = pwalletMain->sparkWallet->getCoinFromMeta(mints[1]);
    BOOST_CHECK(sparkState->HasCoinHash(cn1, cn1.getHash()));
    auto cn2 = pwalletMain->sparkWallet->getCoinFromMeta(mints[2]);
    BOOST_CHECK(!sparkState->HasCoinHash(cn2, cn2.getHash()));

    BOOST_CHECK_EQUAL(2, sparkState->GetTotalCoins());

    // check group info
    spark::CSparkState::SparkCoinGroupInfo group, fakeGroup;
    BOOST_CHECK(sparkState->GetCoinGroupInfo(1, group));
    BOOST_CHECK(!sparkState->GetCoinGroupInfo(0, fakeGroup));
    BOOST_CHECK(!sparkState->GetCoinGroupInfo(2, fakeGroup));

    BOOST_CHECK(blockIdx1 == group.firstBlock);
    BOOST_CHECK(blockIdx2 == group.lastBlock);

    BOOST_CHECK_EQUAL(4, group.nCoins);

    BOOST_CHECK_EQUAL(1, sparkState->GetLatestCoinID());

    sparkState->Reset();
    mempool.clear();
}

BOOST_AUTO_TEST_CASE(lTag_adding)
{
    GenerateBlocks(1001);
    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints({1 * COIN, 2 * COIN, 1 * CENT}, txs);

    GenerateBlock(txs);

    auto blockIdx = chainActive.Tip();
    auto block = GetCBlock(blockIdx);
    PopulateSparkTxInfo(block, {{pwalletMain->sparkWallet->getCoinFromMeta(mints[0])}}, {});

    sparkState->AddMintsToStateAndBlockIndex(blockIdx, &block);

    GroupElement lTag1, lTag2;
    lTag1.randomize();
    lTag2.randomize();
    auto lTagHash1 = primitives::GetLTagHash(lTag1);
    auto lTagHash2 = primitives::GetLTagHash(lTag2);

    sparkState->AddSpend(lTag1, 1);

    GroupElement receivedLTag;
    BOOST_CHECK(sparkState->IsUsedLTag(lTag1));
    BOOST_CHECK(sparkState->IsUsedLTagHash(receivedLTag, lTagHash1));
    BOOST_CHECK(lTag1 == receivedLTag);

    BOOST_CHECK(!sparkState->IsUsedLTag(lTag2));
    BOOST_CHECK(!sparkState->IsUsedLTagHash(receivedLTag, lTagHash2));

    // add lTags to group that doesn't exist, should fail
    BOOST_CHECK_THROW(sparkState->AddSpend(GroupElement(), 100), std::invalid_argument);

    sparkState->Reset();
    mempool.clear();
}

BOOST_AUTO_TEST_CASE(mempool)
{
    GenerateBlocks(1001);
    std::vector<CMutableTransaction> txs;
    auto mint = GenerateMints({1 * COIN}, txs)[0];

    GenerateBlock(txs);

    auto blockIdx = chainActive.Tip();
    auto block = GetCBlock(blockIdx);
    PopulateSparkTxInfo(block, {{pwalletMain->sparkWallet->getCoinFromMeta(mint)}}, {});

    sparkState->AddMintsToStateAndBlockIndex(blockIdx, &block);

    GroupElement spendLTag;
    spendLTag.randomize();
    sparkState->AddSpend(spendLTag, 1);

    // test mint mempool
    // - can not add on-chain coin
    BOOST_CHECK(!sparkState->CanAddMintToMempool(pwalletMain->sparkWallet->getCoinFromMeta(mint)));

    // - can not add duplicated coin
    spark::Coin randMint;
    BOOST_CHECK(sparkState->CanAddMintToMempool(randMint));
    sparkState->AddMintsToMempool({randMint});
    BOOST_CHECK(!sparkState->CanAddMintToMempool(randMint));

    // - remove from mempool then can add again
    sparkState->RemoveMintFromMempool(randMint);
    BOOST_CHECK(sparkState->CanAddMintToMempool(randMint));

    // test spend mempool
    // - can not add on-chain spend
    BOOST_CHECK(!sparkState->CanAddSpendToMempool(spendLTag));

    // - can not add duplicated serial
    GroupElement anotherLTag;
    anotherLTag.randomize();

    auto txid = ArithToUint256(1);

    BOOST_CHECK(sparkState->CanAddSpendToMempool(anotherLTag));
    sparkState->AddSpendToMempool({anotherLTag}, txid);
    BOOST_CHECK(!sparkState->CanAddSpendToMempool(anotherLTag));

    BOOST_CHECK(txid == sparkState->GetMempoolConflictingTxHash(anotherLTag));

    GroupElement fakeLTag;
    fakeLTag.randomize();
    BOOST_CHECK(uint256() == sparkState->GetMempoolConflictingTxHash(fakeLTag));

    // - remove spend then can add again
    sparkState->RemoveSpendFromMempool({anotherLTag});
    BOOST_CHECK(sparkState->CanAddSpendToMempool(anotherLTag));
    sparkState->AddSpendToMempool({anotherLTag}, txid);
    BOOST_CHECK(!sparkState->CanAddSpendToMempool(anotherLTag));

    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(add_remove_block)
{
    GenerateBlocks(1001);

    auto index1 = GenerateBlock({});
    auto block1 = GetCBlock(index1);
    PopulateSparkTxInfo(block1, {}, {});

    sparkState->AddBlock(index1);

    BOOST_CHECK_EQUAL(0, sparkState->GetMints().size());
    BOOST_CHECK_EQUAL(0, sparkState->GetSpends().size());

    // some mints
    std::vector<CMutableTransaction> txs;
    auto mint1 = GenerateMints({1 * COIN}, txs)[0];
    auto mint2 = GenerateMints({2 * COIN}, txs)[0];

    auto index2 = GenerateBlock({});
    auto block2 = GetCBlock(index2);
    PopulateSparkTxInfo(block2, {pwalletMain->sparkWallet->getCoinFromMeta(mint1), pwalletMain->sparkWallet->getCoinFromMeta(mint2)}, {});

    sparkState->AddMintsToStateAndBlockIndex(index2, &block2);
    sparkState->AddBlock(index2);

    BOOST_CHECK_EQUAL(2, sparkState->GetMints().size());
    BOOST_CHECK_EQUAL(0, sparkState->GetSpends().size());

    // some serials
    GroupElement lTag1, lTag2;
    lTag1.randomize();
    lTag2.randomize();

    auto index3 = GenerateBlock({});
    auto block3 = GetCBlock(index3);
    PopulateSparkTxInfo(block3, {}, {{lTag1, 1}, {lTag2, 1}});
    index3->spentLTags = block3.sparkTxInfo->spentLTags;

    sparkState->AddBlock(index3);

    BOOST_CHECK_EQUAL(2, sparkState->GetMints().size());
    BOOST_CHECK_EQUAL(2, sparkState->GetSpends().size());

    // both mint and lTag
    auto mint3 = GenerateMints({3 * COIN}, txs)[0];

    GroupElement lTag3;
    lTag3.randomize();

    auto index4 = GenerateBlock({});
    auto block4 = GetCBlock(index4);
    PopulateSparkTxInfo(block4, {pwalletMain->sparkWallet->getCoinFromMeta(mint3)}, {{lTag3, 1}});
    sparkState->AddMintsToStateAndBlockIndex(index4, &block4);
    index4->spentLTags = block4.sparkTxInfo->spentLTags;

    sparkState->AddBlock(index4);

    BOOST_CHECK_EQUAL(3, sparkState->GetMints().size());
    BOOST_CHECK_EQUAL(3, sparkState->GetSpends().size());

    // remove last block
    sparkState->RemoveBlock(index4);

    BOOST_CHECK_EQUAL(2, sparkState->GetMints().size());
    BOOST_CHECK_EQUAL(2, sparkState->GetSpends().size());

    // verify mints and spends on blocks
    BOOST_CHECK(sparkState->HasCoin(pwalletMain->sparkWallet->getCoinFromMeta(mint1)));
    BOOST_CHECK(sparkState->HasCoin(pwalletMain->sparkWallet->getCoinFromMeta(mint2)));
    BOOST_CHECK(!sparkState->HasCoin(pwalletMain->sparkWallet->getCoinFromMeta(mint3)));

    BOOST_CHECK(sparkState->IsUsedLTag(lTag1));
    BOOST_CHECK(sparkState->IsUsedLTag(lTag2));
    BOOST_CHECK(!sparkState->IsUsedLTag(lTag3));

    sparkState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
