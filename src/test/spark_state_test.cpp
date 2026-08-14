#include "../chainparams.h"
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

// Generate a random char vector from a random scalar
static std::vector<unsigned char> random_char_vector() {
    Scalar temp;
    temp.randomize();
    std::vector<unsigned char> result;
    result.resize(spark::SCALAR_ENCODING);
    temp.serialize(result.data());

    return result;
}

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

    spark::Coin CreateCoin(char type, CAmount value)
    {
        spark::SpendKey spendKey(params);
        spark::FullViewKey fullViewKey(spendKey);
        spark::IncomingViewKey incomingViewKey(fullViewKey);
        spark::Address address(incomingViewKey, 1);
        spark::Scalar k;
        k.randomize();

        spark::Coin coin(
            params, type, k, address, value, "memo", random_char_vector());
        // Spend coins do not serialize v, but keep local copies initialized.
        coin.v = value;
        return coin;
    }
public:
    spark::CSparkState* sparkState;
};

BOOST_FIXTURE_TEST_SUITE(spark_state_tests, SparkStateTests)

BOOST_AUTO_TEST_CASE(add_mints_to_state)
{
    GenerateBlocks(500);

    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints({1 * COIN, 2 * COIN, 3 * COIN}, txs);

    sort(mints.begin(), mints.end(),
    [](const CSparkMintMeta& a, const CSparkMintMeta& b)->bool {
        return a.v < b.v;
    });

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

BOOST_AUTO_TEST_CASE(reconnect_clears_derived_privacy_data)
{
    auto* sparkNameManager = CSparkNameManager::GetInstance();
    sparkNameManager->Reset();

    CBlockIndex *index = GenerateBlock({});
    BOOST_REQUIRE(index != nullptr);
    CBlock block = GetCBlock(index);
    PopulateSparkTxInfo(block, {}, {});

    {
        GroupElement group;
        group.randomize();
        auto& pd = index->ensurePrivacyData();
        pd.sparkMintedCoins[1] = {};
        pd.spentLTags[group] = 1;
        pd.sparkSetHash[1] = {1};
        pd.sparkTxHashContext[group] = {uint256S("01"), {1}};
        pd.ltagTxhash[uint256S("02")] = uint256S("03");
        pd.addedSparkNames["added"] =
            CSparkNameBlockIndexData("added", "address", 1, "");
        pd.removedSparkNames["removed"] =
            CSparkNameBlockIndexData("removed", "address", 1, "");
        pd.activeDisablingSporks.emplace(
            "feature", std::make_pair(10, 20));
    }

    CValidationState state;
    BOOST_REQUIRE(
        spark::ConnectBlockSpark(state, Params(), index, &block, true));
    {
        const auto& checked = index->privacyData();
        BOOST_CHECK_EQUAL(checked.sparkMintedCoins.size(), 1U);
        BOOST_CHECK_EQUAL(checked.spentLTags.size(), 1U);
        BOOST_CHECK_EQUAL(checked.sparkSetHash.size(), 1U);
        BOOST_CHECK_EQUAL(checked.sparkTxHashContext.size(), 1U);
        BOOST_CHECK_EQUAL(checked.ltagTxhash.size(), 1U);
        BOOST_CHECK_EQUAL(checked.addedSparkNames.size(), 1U);
        BOOST_CHECK_EQUAL(checked.removedSparkNames.size(), 1U);
    }

    BOOST_REQUIRE(
        spark::ConnectBlockSpark(state, Params(), index, &block, false));

    BOOST_REQUIRE(index->hasPrivacyData());
    const auto& rebuilt = index->privacyData();
    BOOST_CHECK(rebuilt.sparkMintedCoins.empty());
    BOOST_CHECK(rebuilt.spentLTags.empty());
    BOOST_CHECK(rebuilt.sparkSetHash.empty());
    BOOST_CHECK(rebuilt.sparkTxHashContext.empty());
    BOOST_CHECK(rebuilt.ltagTxhash.empty());
    BOOST_CHECK(rebuilt.addedSparkNames.empty());
    BOOST_CHECK_EQUAL(rebuilt.removedSparkNames.size(), 1U);
    BOOST_CHECK(
        rebuilt.removedSparkNames.find("removed") !=
        rebuilt.removedSparkNames.end());
    BOOST_CHECK_EQUAL(rebuilt.activeDisablingSporks.size(), 1U);

    // Removed names are undo data. A replay against already-applied name state
    // cannot rediscover an expiry entry, but a later disconnect must restore it.
    std::string restoredAddress;
    BOOST_CHECK(sparkNameManager->RemoveBlock(index));
    BOOST_CHECK(
        sparkNameManager->GetSparkAddress("removed", restoredAddress));
    BOOST_CHECK_EQUAL(restoredAddress, "address");
    sparkNameManager->Reset();
}

BOOST_AUTO_TEST_CASE(lTag_adding)
{
    GenerateBlocks(501);
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

    sparkState->Reset();
    mempool.clear();
}

BOOST_AUTO_TEST_CASE(mempool)
{
    GenerateBlocks(501);
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

    // Generate keys
    const spark::Params* params = spark::Params::get_default();
    spark::SpendKey spend_key(params);
    spark::FullViewKey full_view_key(spend_key);
    spark::IncomingViewKey incoming_view_key(full_view_key);

    // Generate address
    spark::Address address(incoming_view_key, 1);

    // Generate coin
    Scalar k;
    k.randomize();
    spark::Coin randMint = spark::Coin(
            params,
            spark::COIN_TYPE_MINT,
            k,
            address,
            100,
            "memo",
            random_char_vector()
            );

    BOOST_CHECK(sparkState->CanAddMintToMempool(randMint));
    const uint256 mintTxid = ArithToUint256(1);
    sparkState->AddMintsToMempool({randMint}, mintTxid);
    BOOST_CHECK(!sparkState->CanAddMintToMempool(randMint));
    {
        LOCK(::mempool.cs);
        BOOST_CHECK(
            ::mempool.sparkState.GetMempoolConflictingMintTxHash(randMint) ==
            mintTxid);
    }

    // - remove from mempool then can add again
    sparkState->RemoveMintFromMempool(randMint);
    BOOST_CHECK(sparkState->CanAddMintToMempool(randMint));
    {
        LOCK(::mempool.cs);
        BOOST_CHECK(
            ::mempool.sparkState.GetMempoolConflictingMintTxHash(randMint).IsNull());
    }

    // test spend mempool
    // - can not add on-chain spend
    BOOST_CHECK(!sparkState->CanAddSpendToMempool(spendLTag));

    // - can not add duplicated serial
    GroupElement anotherLTag;
    anotherLTag.randomize();

    auto txid = ArithToUint256(2);

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

BOOST_AUTO_TEST_CASE(duplicate_mint_consensus_activation)
{
    struct RestoreActivationHeights {
        Consensus::Params& consensus;
        int singleInput;
        int v2;
        RestoreActivationHeights()
            : consensus(const_cast<Consensus::Params&>(::Params().GetConsensus()))
            , singleInput(consensus.nSparkSingleInputStartBlock)
            , v2(consensus.nSparkChaumV2StartBlock)
        {
        }
        ~RestoreActivationHeights()
        {
            consensus.nSparkSingleInputStartBlock = singleInput;
            consensus.nSparkChaumV2StartBlock = v2;
        }
    } restoreActivationHeights;

    const int activationHeight = chainActive.Height() + 2;
    UpdateRegtestSparkActivationHeights(
        &activationHeight, &activationHeight);

    const spark::Coin mint = CreateCoin(spark::COIN_TYPE_MINT, 1 * COIN);
    const spark::Coin spendMint = CreateCoin(spark::COIN_TYPE_SPEND, 2 * COIN);

    const auto check = [](
            const std::vector<spark::Coin>& mints,
            int height,
            CValidationState& state) {
        if (height < ::Params().GetConsensus().nSparkChaumV2StartBlock)
            return true;
        return spark::CheckSparkMintDuplicates(state, mints, height);
    };

    CValidationState preActivationState;
    BOOST_CHECK(check(
        {mint, mint}, activationHeight - 1, preActivationState));

    CValidationState mintDuplicateState;
    BOOST_CHECK(!check(
        {mint, mint}, activationHeight, mintDuplicateState));
    int mintDuplicateDoS = 0;
    BOOST_REQUIRE(mintDuplicateState.IsInvalid(mintDuplicateDoS));
    BOOST_CHECK_EQUAL(mintDuplicateDoS, 100);
    BOOST_CHECK_EQUAL(
        mintDuplicateState.GetRejectReason(), "bad-txns-spark-mint-duplicate");

    CValidationState spendMintDuplicateState;
    BOOST_CHECK(!check(
        {spendMint, spendMint},
        activationHeight,
        spendMintDuplicateState));
    BOOST_CHECK_EQUAL(
        spendMintDuplicateState.GetRejectReason(),
        "bad-txns-spark-mint-duplicate");

    CValidationState distinctState;
    BOOST_CHECK(check(
        {mint, spendMint}, activationHeight, distinctState));

    sparkState->AddMint(
        mint, spark::CMintedCoinInfo::make(1, activationHeight - 1));
    CValidationState activeChainState;
    BOOST_CHECK(!check(
        {mint}, activationHeight, activeChainState));
    BOOST_CHECK_EQUAL(
        activeChainState.GetRejectReason(), "bad-txns-spark-mint-duplicate");

    // VerifyDB may see the candidate block's own mint in global Spark state.
    // An occurrence at the candidate height is not an earlier duplicate.
    const spark::Coin replayMint =
        CreateCoin(spark::COIN_TYPE_MINT, 3 * COIN);
    sparkState->AddMint(
        replayMint, spark::CMintedCoinInfo::make(1, activationHeight));
    CValidationState historicalReplayState;
    BOOST_CHECK(check(
        {replayMint}, activationHeight, historicalReplayState));

    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(copy_from_isolates_minted_coins)
{
    const spark::Coin mint = CreateCoin(spark::COIN_TYPE_MINT, 1 * COIN);
    CBlock block;
    PopulateSparkTxInfo(block, {mint}, {});
    CBlockIndex index;
    index.pprev = chainActive.Tip();
    index.nHeight = chainActive.Height() + 1;
    sparkState->AddMintsToStateAndBlockIndex(&index, &block);
    BOOST_REQUIRE(sparkState->HasCoin(mint));

    spark::CSparkState snapshot;
    snapshot.CopyFrom(*sparkState);
    BOOST_CHECK(snapshot.HasCoin(mint));
    BOOST_CHECK_EQUAL(snapshot.GetTotalCoins(), sparkState->GetTotalCoins());
    BOOST_CHECK(
        snapshot.GetMintedCoinHeightAndId(mint) ==
        sparkState->GetMintedCoinHeightAndId(mint));

    const spark::Coin extra = CreateCoin(spark::COIN_TYPE_MINT, 2 * COIN);
    BOOST_REQUIRE(
        snapshot.AddMint(extra, spark::CMintedCoinInfo::make(1, index.nHeight + 1)));
    BOOST_CHECK(snapshot.HasCoin(extra));
    BOOST_CHECK(!sparkState->HasCoin(extra));
}

BOOST_AUTO_TEST_CASE(duplicate_mint_legacy_disconnect)
{
    const spark::Coin mint = CreateCoin(spark::COIN_TYPE_MINT, 1 * COIN);

    CBlock firstBlock;
    PopulateSparkTxInfo(firstBlock, {mint}, {});
    CBlockIndex firstIndex;
    firstIndex.pprev = chainActive.Tip();
    firstIndex.nHeight = chainActive.Height() + 1;
    sparkState->AddMintsToStateAndBlockIndex(&firstIndex, &firstBlock);

    CBlock duplicateBlock;
    PopulateSparkTxInfo(duplicateBlock, {mint, mint}, {});
    CBlockIndex duplicateIndex;
    duplicateIndex.pprev = &firstIndex;
    duplicateIndex.nHeight = firstIndex.nHeight + 1;
    sparkState->AddMintsToStateAndBlockIndex(&duplicateIndex, &duplicateBlock);

    BOOST_REQUIRE_EQUAL(sparkState->GetTotalCoins(), 1U);
    BOOST_REQUIRE_EQUAL(
        duplicateIndex.privacyData().sparkMintedCoins.at(1).size(), 2U);

    sparkState->RemoveBlock(&duplicateIndex);

    BOOST_CHECK(sparkState->HasCoin(mint));
    BOOST_CHECK(
        sparkState->GetMintedCoinHeightAndId(mint) ==
        std::make_pair(firstIndex.nHeight, 1));
    spark::CSparkState::SparkCoinGroupInfo group;
    BOOST_REQUIRE(sparkState->GetCoinGroupInfo(1, group));
    BOOST_CHECK_EQUAL(group.nCoins, 1);
    BOOST_CHECK(group.lastBlock == &firstIndex);

    sparkState->RemoveBlock(&firstIndex);
    BOOST_CHECK(!sparkState->HasCoin(mint));
    BOOST_CHECK(!sparkState->GetCoinGroupInfo(1, group));

    // Rebuilding from persisted block-index entries must preserve the same
    // occurrence and remain safe to disconnect.
    sparkState->AddBlock(&firstIndex);
    sparkState->AddBlock(&duplicateIndex);
    BOOST_REQUIRE_EQUAL(sparkState->GetTotalCoins(), 1U);
    sparkState->RemoveBlock(&duplicateIndex);
    BOOST_CHECK(
        sparkState->GetMintedCoinHeightAndId(mint) ==
        std::make_pair(firstIndex.nHeight, 1));
    sparkState->RemoveBlock(&firstIndex);
    BOOST_CHECK_EQUAL(sparkState->GetTotalCoins(), 0U);

    // A later duplicate can also be indexed in a different anonymity-set
    // group. Disconnecting that group must still preserve the earlier mint.
    auto& firstMints = firstIndex.ensurePrivacyData().sparkMintedCoins;
    auto& duplicateMints =
        duplicateIndex.ensurePrivacyData().sparkMintedCoins;
    firstMints.clear();
    duplicateMints.clear();
    firstMints[1].push_back(mint);
    duplicateMints[2].push_back(mint);
    sparkState->AddBlock(&firstIndex);
    sparkState->AddBlock(&duplicateIndex);
    BOOST_REQUIRE_EQUAL(sparkState->GetLatestCoinID(), 2);

    sparkState->RemoveBlock(&duplicateIndex);
    BOOST_CHECK(
        sparkState->GetMintedCoinHeightAndId(mint) ==
        std::make_pair(firstIndex.nHeight, 1));
    BOOST_CHECK_EQUAL(sparkState->GetLatestCoinID(), 1);
    BOOST_CHECK(!sparkState->GetCoinGroupInfo(2, group));
    sparkState->RemoveBlock(&firstIndex);
    BOOST_CHECK_EQUAL(sparkState->GetTotalCoins(), 0U);

    const spark::Coin sameBlockMint =
        CreateCoin(spark::COIN_TYPE_MINT, 2 * COIN);
    CBlock sameBlock;
    PopulateSparkTxInfo(sameBlock, {sameBlockMint, sameBlockMint}, {});
    CBlockIndex sameBlockIndex;
    sameBlockIndex.pprev = chainActive.Tip();
    sameBlockIndex.nHeight = chainActive.Height() + 1;
    sparkState->AddMintsToStateAndBlockIndex(&sameBlockIndex, &sameBlock);

    BOOST_REQUIRE_EQUAL(sparkState->GetTotalCoins(), 1U);
    sparkState->RemoveBlock(&sameBlockIndex);
    BOOST_CHECK_EQUAL(sparkState->GetTotalCoins(), 0U);
}

BOOST_AUTO_TEST_CASE(add_remove_block)
{
    GenerateBlocks(501);

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
    index3->ensurePrivacyData().spentLTags = block3.sparkTxInfo->spentLTags;

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
    index4->ensurePrivacyData().spentLTags = block4.sparkTxInfo->spentLTags;

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

BOOST_AUTO_TEST_CASE(remove_block_preserves_legacy_duplicate_mint)
{
    GenerateBlocks(500);

    std::vector<CMutableTransaction> txs;
    const auto mint = GenerateMints({1 * COIN}, txs)[0];
    const auto coin = pwalletMain->sparkWallet->getCoinFromMeta(mint);

    const auto checkDuplicate = [&](size_t maxCoinInGroup, int duplicateGroupId) {
        spark::CSparkState state(maxCoinInGroup, 1);

        CBlock firstBlock;
        PopulateSparkTxInfo(firstBlock, {coin}, {});
        CBlockIndex firstIndex;
        firstIndex.pprev = chainActive.Tip();
        firstIndex.nHeight = chainActive.Height() + 1;
        state.AddMintsToStateAndBlockIndex(&firstIndex, &firstBlock);

        CBlock duplicateBlock;
        PopulateSparkTxInfo(duplicateBlock, {coin}, {});
        CBlockIndex duplicateIndex;
        duplicateIndex.pprev = &firstIndex;
        duplicateIndex.nHeight = firstIndex.nHeight + 1;
        state.AddMintsToStateAndBlockIndex(&duplicateIndex, &duplicateBlock);

        BOOST_REQUIRE_EQUAL(state.GetTotalCoins(), 1U);
        BOOST_REQUIRE_EQUAL(
            duplicateIndex.privacyData().sparkMintedCoins
                .at(duplicateGroupId).size(),
            1U);

        state.RemoveBlock(&duplicateIndex);
        BOOST_CHECK(
            state.GetMintedCoinHeightAndId(coin) ==
            std::make_pair(firstIndex.nHeight, 1));

        state.RemoveBlock(&firstIndex);
        BOOST_CHECK_EQUAL(state.GetTotalCoins(), 0U);
    };

    // Exercise duplicates in both the same group and a later group.
    checkDuplicate(10, 1);
    checkDuplicate(1, 2);
}

BOOST_AUTO_TEST_CASE(get_coin_group)
{
    GenerateBlocks(500);

    std::vector<CAmount> amounts(12, COIN);
    std::vector<CMutableTransaction> txs;

    auto mints = GenerateMints(amounts, txs);
    std::vector<spark::Coin> coins;
    std::vector<CBlockIndex*> indexes;
    std::vector<CBlock> blocks;

    for (size_t i = 0; i != mints.size(); i += 2) {
        auto index = GenerateBlock({txs[i], txs[i + 1]});

        auto block = GetCBlock(index);
        coins.push_back(pwalletMain->sparkWallet->getCoinFromMeta(mints[i + 1]));
        coins.push_back(pwalletMain->sparkWallet->getCoinFromMeta(mints[i]));

        PopulateSparkTxInfo(
             block,
             {
                pwalletMain->sparkWallet->getCoinFromMeta(mints[i]),
                pwalletMain->sparkWallet->getCoinFromMeta(mints[i + 1])
             },
             {});

        indexes.push_back(index);
        blocks.push_back(block);

        GenerateBlock({});
    }

    size_t maxSize = 6;
    size_t startCoin = 2;
    auto sparkState = new spark::CSparkState(maxSize, startCoin);

    auto addMintsToState = [&](CBlockIndex* index, CBlock const& block) {
        if (index->hasPrivacyData()) index->ensurePrivacyData().sparkMintedCoins.clear();
        sparkState->AddMintsToStateAndBlockIndex(index, &block);
    };

    auto verifyMints = [&](size_t i, size_t j, std::vector<spark::Coin> const& coinSet) {
        std::vector<spark::Coin> expected(coins.begin() + i, coins.begin() + j);
        std::reverse(expected.begin(), expected.end());

        BOOST_CHECK(expected == coinSet);
    };

    auto verifyGroup = [&](int expectedId, size_t expectedCoins, CBlockIndex* expectedFirst, CBlockIndex* expectedLast, int testId = 0) -> void {
        if (!testId) {
            testId = sparkState->GetLatestCoinID();
        }

        spark::CSparkState::SparkCoinGroupInfo group;

        BOOST_CHECK(sparkState->GetCoinGroupInfo(testId, group));
        if (expectedId > 0) { // verify last Id
            BOOST_CHECK_EQUAL(expectedId, testId);
        }

        BOOST_CHECK_EQUAL(expectedCoins, group.nCoins);
        BOOST_CHECK_EQUAL(expectedFirst, group.firstBlock);
        BOOST_CHECK_EQUAL(expectedLast, group.lastBlock);
    };


    addMintsToState(indexes[0], blocks[0]);
    addMintsToState(indexes[1], blocks[1]);
    addMintsToState(indexes[2], blocks[2]);

    verifyGroup(1, 6, indexes[0], indexes[2]);

    uint256 blockHashOut1;
    std::vector<spark::Coin> coinOut1;
    std::vector<unsigned char> setHash;

    BOOST_CHECK_EQUAL(6, sparkState->GetCoinSetForSpend(
        &chainActive,
        indexes[2]->nHeight,
        1,
        blockHashOut1,
        coinOut1,
        setHash));

    verifyMints(0, 6, coinOut1);
    BOOST_CHECK(indexes[2]->GetBlockHash() == blockHashOut1);

    // 8 coins, 1(6), 2(4)
    addMintsToState(indexes[3], blocks[3]);
    verifyGroup(2, 4, indexes[2], indexes[3]);
    verifyGroup(1, 6, indexes[0], indexes[2], 1);

    uint256 blockHashOut2;
    std::vector<spark::Coin> coinOut2;
    BOOST_CHECK_EQUAL(4, sparkState->GetCoinSetForSpend(
        &chainActive,
        indexes[3]->nHeight + 1,
        2,
        blockHashOut2,
        coinOut2,
        setHash));

    verifyMints(4, 8, coinOut2);
    BOOST_CHECK(indexes[3]->GetBlockHash() == blockHashOut2);

    // 10 coins, 1(6), 2(6)
    addMintsToState(indexes[4], blocks[4]);

    verifyGroup(2, 6, indexes[2], indexes[4]);
    verifyGroup(1, 6, indexes[0], indexes[2], 1);

    uint256 blockHashOut3;
    std::vector<spark::Coin> coinOut3;
    BOOST_CHECK_EQUAL(6, sparkState->GetCoinSetForSpend(
        &chainActive,
        indexes[4]->nHeight,
        2,
        blockHashOut3,
        coinOut3,
        setHash));

    verifyMints(4, 10, coinOut3);
    BOOST_CHECK(indexes[4]->GetBlockHash() == blockHashOut3);

    // 12 coins, 1(6), 2(6), 3(4)
    addMintsToState(indexes[5], blocks[5]);

    verifyGroup(3, 4, indexes[4], indexes[5]);
    verifyGroup(2, 6, indexes[2], indexes[4], 2);
    verifyGroup(1, 6, indexes[0], indexes[2], 1);

    uint256 blockHashOut4;
    std::vector<spark::Coin> coinOut4;
    BOOST_CHECK_EQUAL(4, sparkState->GetCoinSetForSpend(
        &chainActive,
        indexes[5]->nHeight,
        3,
        blockHashOut4,
        coinOut4,
        setHash));
        verifyMints(8, 12, coinOut4);

    // Get first group
    uint256 blockHashOut5;
    std::vector<spark::Coin> coinOut5;
    BOOST_CHECK_EQUAL(6, sparkState->GetCoinSetForSpend(
        &chainActive,
        indexes[5]->nHeight,
        1,
        blockHashOut5,
        coinOut5,
        setHash));

    verifyMints(0, 6, coinOut5);
    BOOST_CHECK(indexes[2]->GetBlockHash() == blockHashOut5);

    // Get first group with low max height
    uint256 blockHashOut6;
    std::vector<spark::Coin>  coinOut6;
    BOOST_CHECK_EQUAL(2, sparkState->GetCoinSetForSpend(
        &chainActive,
        indexes[0]->nHeight,
        1,
        blockHashOut6,
        coinOut6,
        setHash));

    verifyMints(0, 2, coinOut6);
    BOOST_CHECK(indexes[0]->GetBlockHash() == blockHashOut6);

    sparkState->RemoveBlock(indexes[5]);
    verifyGroup(2, 6, indexes[2], indexes[4]);
    verifyGroup(1, 6, indexes[0], indexes[2], 1);

    sparkState->Reset();
}

// Blocks carrying no privacy transactions must not allocate CBlockIndexPrivacyData.
// The block index keeps every entry alive for the lifetime of the process, so a
// stray unconditional ensurePrivacyData() on the connect path costs hundreds of
// megabytes over a full chain.
//
// The chain is generated past nSparkStartBlock and into the evo spork range so
// that the spark and spork connect paths are actually exercised; below those
// heights only the sigma/lelantus paths run and the check is nearly vacuous.
// nSparkNamesStartBlock is far too high to reach in a unit test, so the spark
// name path is not covered here.
BOOST_AUTO_TEST_CASE(no_privacy_data_for_empty_blocks)
{
    const Consensus::Params &consensus = ::Params().GetConsensus();

    // one block past the start of the evo spork range, which is the last of the
    // protocol activations this test can reach
    const int targetHeight = consensus.nEvoSporkStartBlock + 1;
    BOOST_REQUIRE(targetHeight > consensus.nSparkStartBlock);
    BOOST_REQUIRE(targetHeight < consensus.nEvoSporkStopBlock);

    std::vector<int> allocatedAt;
    while (chainActive.Height() < targetHeight) {
        CBlockIndex *index = GenerateBlock({});
        BOOST_REQUIRE(index != nullptr);
        if (index->hasPrivacyData())
            allocatedAt.push_back(index->nHeight);
    }

    // report the offending heights rather than just a count, so a regression
    // points straight at the activation that started allocating
    BOOST_CHECK_MESSAGE(allocatedAt.empty(),
        "privacy data allocated for " << allocatedAt.size() << " empty block(s), first at height "
        << (allocatedAt.empty() ? 0 : allocatedAt.front()));

    sparkState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()
