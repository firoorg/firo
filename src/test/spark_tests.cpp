#include "../chainparams.h"
#include "../batchproof_container.h"
#include "../consensus/consensus.h"
#include "../script/standard.h"
#include "../validation.h"
#include "../wallet/coincontrol.h"
#include "../wallet/walletexcept.h"
#include "../wallet/wallet.h"
#include "../net.h"
#include "../miner.h"
#include "../policy/policy.h"

#include "test_bitcoin.h"
#include "fixtures.h"
#include <iostream>
#include <boost/test/unit_test.hpp>

namespace spark {

    // Generate a random char vector from a random scalar
    static std::vector<unsigned char> random_char_vector() {
        Scalar temp;
        temp.randomize();
        std::vector<unsigned char> result;
        result.resize(SCALAR_ENCODING);
        temp.serialize(result.data());
        return result;
    }


class SparkTests : public SparkTestingSetup
{
public:
    SparkTests() :
          SparkTestingSetup(),
          sparkState(CSparkState::GetState()),
          consensus(::Params().GetConsensus()) {
    }

    ~SparkTests() {
          sparkState->Reset();
    }

    void ExtractSpend(CTransaction const &tx,
                      std::vector<spark::Coin>& coins,
                      std::vector<GroupElement>& lTags) {
        if (tx.vin[0].scriptSig.IsSparkSpend()) {
            coins.clear();
            coins =  spark::GetSparkMintCoins(tx);
            lTags.clear();
            lTags =  spark::GetSparkUsedTags(tx);
        }
    }

    CBlock GetCBlock(CBlockIndex const *blockIdx) {
        CBlock block;
        if (!ReadBlockFromDisk(block, blockIdx, ::Params().GetConsensus())) {
            throw std::invalid_argument("No block index data");
        }

        return block;
    }

    CTransaction GenerateHistoricalMultiInputSpend(
        const std::vector<CSparkMintMeta>& selected,
        CAmount transparentAmount,
        SpendTransactionVersion version = SpendTransactionVersion::V1)
    {
        BOOST_REQUIRE(!selected.empty());

        const auto* params = spark::Params::get_default();
        const SpendKey spendKey = pwalletMain->sparkWallet->generateSpendKey(params);
        const FullViewKey fullViewKey(spendKey);

        CMutableTransaction tx;
        CScript spendScript;
        spendScript << OP_SPARKSPEND;
        tx.vin.emplace_back(
            COutPoint(), spendScript, std::numeric_limits<uint32_t>::max());
        tx.vout.emplace_back(transparentAmount, script);
        tx.nVersion = 3;
        tx.nType = version == SpendTransactionVersion::V2
            ? TRANSACTION_SPARK_V2
            : TRANSACTION_SPARK;
        tx.vExtraPayload.clear();
        const uint256 metadataHash = tx.GetHash();

        std::vector<InputCoinData> inputs;
        std::map<uint64_t, uint256> blockHashes;
        std::unordered_map<uint64_t, CoverSetData> coverSetData;
        std::unordered_map<uint64_t, std::vector<Coin>> coverSets;
        CAmount totalInput = 0;

        for (const auto& meta : selected) {
            uint64_t groupId = meta.nId;
            CSparkState::SparkCoinGroupInfo nextGroup;
            if (cmp::greater(sparkState->GetLatestCoinID(), groupId) &&
                sparkState->GetCoinGroupInfo(groupId + 1, nextGroup) &&
                nextGroup.firstBlock->nHeight <= meta.nHeight) {
                ++groupId;
            }

            if (!coverSetData.count(groupId)) {
                uint256 blockHash;
                std::vector<Coin> coverSet;
                std::vector<unsigned char> setHash;
                BOOST_REQUIRE(sparkState->GetCoinSetForSpend(
                    &chainActive,
                    chainActive.Height() - (ZC_MINT_CONFIRMATIONS - 1),
                    groupId,
                    blockHash,
                    coverSet,
                    setHash) >= 2);

                CoverSetData data;
                data.cover_set_size = coverSet.size();
                data.cover_set_representation = setHash;
                data.cover_set_representation.insert(
                    data.cover_set_representation.end(),
                    metadataHash.begin(),
                    metadataHash.end());
                coverSetData[groupId] = std::move(data);
                coverSets[groupId] = std::move(coverSet);
                blockHashes[groupId] = blockHash;
            }

            Coin coin = pwalletMain->sparkWallet->getCoinFromMeta(meta);
            std::size_t index = 0;
            while (index < coverSets.at(groupId).size() &&
                   coverSets.at(groupId)[index] != coin) {
                ++index;
            }
            BOOST_REQUIRE(index < coverSets.at(groupId).size());

            IdentifiedCoinData identified;
            identified.i = meta.i;
            identified.d = meta.d;
            identified.v = meta.v;
            identified.k = meta.k;
            identified.memo = meta.memo;
            const RecoveredCoinData recovered =
                coin.recover(fullViewKey, identified);

            InputCoinData input;
            input.cover_set_id = groupId;
            input.index = index;
            input.s = recovered.s;
            input.T = recovered.T;
            input.v = meta.v;
            input.k = meta.k;
            inputs.push_back(std::move(input));
            totalInput += meta.v;
        }

        const CAmount fee = CENT;
        BOOST_REQUIRE(totalInput > transparentAmount + fee);
        OutputCoinData change;
        change.address = pwalletMain->sparkWallet->getChangeAddress();
        change.v = totalInput - transparentAmount - fee;
        change.memo = "";

        SpendTransaction spend(
            params,
            fullViewKey,
            spendKey,
            inputs,
            coverSetData,
            coverSets,
            fee,
            transparentAmount,
            {change},
            version,
            uint256(),
            blockHashes);

        CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
        payload << spend;
        tx.vExtraPayload.assign(payload.begin(), payload.end());

        for (const auto& outCoin : spend.getOutCoins()) {
            CDataStream encoded(SER_NETWORK, PROTOCOL_VERSION);
            encoded << outCoin;
            CScript mintScript;
            mintScript << OP_SPARKSMINT;
            mintScript.insert(mintScript.end(), encoded.begin(), encoded.end());
            tx.vout.emplace_back(0, mintScript);
        }

        return CTransaction(tx);
    }



public:
     CSparkState *sparkState;
     Consensus::Params const &consensus;

};

// Restore both Spark activation heights by assignment. Calling
// UpdateRegtestSparkSingleInputHeight(INT_MAX) throws when Chaum V2 is still
// the regtest default (700), and a throw from a test destructor terminates.
struct RestoreSparkActivationHeights {
    Consensus::Params& consensus;
    int singleInput;
    int v2;

    RestoreSparkActivationHeights()
        : consensus(const_cast<Consensus::Params&>(::Params().GetConsensus()))
        , singleInput(consensus.nSparkSingleInputStartBlock)
        , v2(consensus.nSparkChaumV2StartBlock)
    {
    }

    ~RestoreSparkActivationHeights()
    {
        consensus.nSparkSingleInputStartBlock = singleInput;
        consensus.nSparkChaumV2StartBlock = v2;
    }
};

BOOST_FIXTURE_TEST_SUITE(spark_tests, SparkTests)

BOOST_AUTO_TEST_CASE(schnorr_proof)
{
    auto params = Params::get_default();

    MintTransaction mintTransaction(params);
    BOOST_CHECK(mintTransaction.verify());
}

BOOST_AUTO_TEST_CASE(is_spark_allowed)
{
    auto start = ::Params().GetConsensus().nSparkStartBlock;
    BOOST_CHECK(!IsSparkAllowed(0));
    BOOST_CHECK(!IsSparkAllowed(start - 1));
    BOOST_CHECK(IsSparkAllowed(start));
    BOOST_CHECK(IsSparkAllowed(start + 1));
}

BOOST_AUTO_TEST_CASE(parse_spark_mintscript)
{
    auto params = Params::get_default();

    // Generate keys
    const SpendKey spend_key(params);
    const FullViewKey full_view_key(spend_key);
    const IncomingViewKey incoming_view_key(full_view_key);

    const uint64_t i = 12345;
    const uint64_t v = 1;
    const std::string memo = "test memo";

    // Generate address
    const Address address(incoming_view_key, i);

    MintedCoinData mintedCoin;
    mintedCoin.address = address;
    mintedCoin.v = v;
    mintedCoin.memo = memo;

    std::vector<MintedCoinData> outputs;
    outputs.push_back(mintedCoin);

    spark::MintTransaction sparkMint(params, outputs, random_char_vector());
    std::vector<CDataStream> serializedCoins = sparkMint.getMintedCoinsSerialized();

    CScript script;
    script << OP_SPARKMINT;
    script.insert(script.end(), serializedCoins[0].begin(), serializedCoins[0].end());

    // coin parse test
    spark::Coin parsedCoin(params);
    ParseSparkMintCoin(script, parsedCoin);

    std::vector<Coin> coins;
    sparkMint.getCoins(coins);

    BOOST_CHECK(parsedCoin == coins[0]);

    // transaction parse test

    std::vector<CScript> scripts;
    scripts.push_back(script);

    MintTransaction mintTransaction(params);
    ParseSparkMintTransaction(scripts, mintTransaction);

    BOOST_CHECK(mintTransaction.verify());

    scripts[0].resize(script.size() - 1);
    BOOST_CHECK_THROW(ParseSparkMintTransaction(scripts, mintTransaction), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(parse_spark_smint)
{
    auto params = Params::get_default();

    // Generate keys
    const SpendKey spend_key(params);
    const FullViewKey full_view_key(spend_key);
    const IncomingViewKey incoming_view_key(full_view_key);

    const uint64_t i = 12345;
    const uint64_t v = 1;
    const std::string memo = "test memo";

    // Generate address
    const Address address(incoming_view_key, i);

    spark::Coin coin(params, 0, (Scalar().randomize()), address, v, memo, random_char_vector());

    CScript script(OP_SPARKSMINT);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << coin;
    script.insert(script.end(), serialized.begin(), serialized.end());

    spark::Coin parsedCoin(params);
    ParseSparkMintCoin(script, parsedCoin);

    BOOST_CHECK_NO_THROW(coin.identify(incoming_view_key));

    BOOST_CHECK(coin == parsedCoin);

    parsedCoin.S.randomize();
    BOOST_CHECK_THROW(parsedCoin.identify(incoming_view_key), std::runtime_error);

    spark::Coin parsedCoin2(params);
    ParseSparkMintCoin(script, parsedCoin2);

    BOOST_CHECK(coin == parsedCoin2);

    // parse invalid
    script.resize(script.size() - 1);
    BOOST_CHECK_THROW(ParseSparkMintCoin(script, coin), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(get_outpoint)
{
    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(500);

    std::vector<CAmount> amounts{2, 10};
    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints(amounts, txs);

    BOOST_CHECK_EQUAL(mints.size(), amounts.size());

    auto mint = mints[0];
    auto nonCommitted = mints[1];
    auto tx = txs[0];
    size_t mintIdx = 0;

    for (; mintIdx < tx.vout.size(); mintIdx++) {
        if (tx.vout[mintIdx].scriptPubKey.IsSparkMint()) {
            break;
        }
    }

    auto prevHeight = chainActive.Tip()->nHeight;
    mempool.clear();
    auto blockIdx = GenerateBlock({txs[0]});

    BOOST_CHECK_EQUAL(prevHeight + 1, chainActive.Tip()->nHeight);

    CBlock block;
    BOOST_CHECK(ReadBlockFromDisk(block, blockIdx, ::Params().GetConsensus()));

    // verify
    COutPoint expectedOut(tx.GetHash(), mintIdx);

    spark::Coin coin = pwalletMain->sparkWallet->getCoinFromMeta(mint);

    // GetOutPointFromBlock
    COutPoint out;
    BOOST_CHECK(GetOutPointFromBlock(out, coin, block));
    BOOST_CHECK(expectedOut == out);

    spark::Coin nonCommittedCoin = pwalletMain->sparkWallet->getCoinFromMeta(nonCommitted);

    BOOST_CHECK(!GetOutPointFromBlock(out, nonCommittedCoin, block));

    // GetOutPoint
    //  by coin
    out = COutPoint();
    BOOST_CHECK(GetOutPoint(out, coin));
    BOOST_CHECK(expectedOut == out);
    BOOST_CHECK(!GetOutPoint(out, nonCommittedCoin));

    // by coin hash
    out = COutPoint();
    uint256 coin_hash = primitives::GetSparkCoinHash(coin);
    BOOST_CHECK(GetOutPoint(out, coin_hash));
    BOOST_CHECK(expectedOut == out);

    uint256 non_commited_coin_hash = primitives::GetSparkCoinHash(nonCommittedCoin);
    BOOST_CHECK(!GetOutPoint(out, non_commited_coin_hash));

    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(build_spark_state)
{
    pwalletMain->SetBroadcastTransactions(true);

    GenerateBlocks(500);
    // generate mints
    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints({1 * COIN, 2 * COIN, 3 * COIN, 4 * COIN}, txs);
    mempool.clear();
    GenerateBlock({txs[0], txs[1]});
    auto blockIdx1 = chainActive.Tip();
    auto block1 = GetCBlock(blockIdx1);

    GenerateBlock({txs[2], txs[3]});
    auto blockIdx2 = chainActive.Tip();
    auto block2 = GetCBlock(blockIdx2);

    BOOST_CHECK(BuildSparkStateFromIndex(&chainActive));
    BOOST_CHECK(sparkState->HasCoin(pwalletMain->sparkWallet->getCoinFromMeta(mints[0])));
    BOOST_CHECK(sparkState->HasCoin(pwalletMain->sparkWallet->getCoinFromMeta(mints[1])));
    BOOST_CHECK(sparkState->HasCoin(pwalletMain->sparkWallet->getCoinFromMeta(mints[2])));
    BOOST_CHECK(sparkState->HasCoin(pwalletMain->sparkWallet->getCoinFromMeta(mints[3])));

    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(connect_and_disconnect_block)
{
    // util function
    auto reconnect = [](CBlock const &block) {
        LOCK(cs_main);

        std::shared_ptr<CBlock const> sharedBlock =
                std::make_shared<CBlock const>(block);

        CValidationState state;
        ActivateBestChain(state, ::Params(), sharedBlock);
    };

    pwalletMain->SetBroadcastTransactions(true);
    GenerateBlocks(500);

    std::vector<CMutableTransaction> mintTxs;
    auto mints = GenerateMints({3 * COIN, 2 * COIN}, mintTxs);
    std::vector<CMutableTransaction> mintTxs2;
    auto mints2 = GenerateMints({3 * COIN }, mintTxs2);

    struct {
        // expected state.
        std::vector<spark::Coin> coins;
        std::vector<GroupElement> lTags;

        // first group
        CBlockIndex *first = nullptr;
        CBlockIndex *last = nullptr;

        int lastId = 0;

        // real state
        CSparkState *state;

        void Verify() const {
            auto const &spends = state->GetSpends();
            BOOST_CHECK_EQUAL(lTags.size(), spends.size());
            for (auto const &lTag : lTags) {
                BOOST_CHECK_MESSAGE(spends.count(lTag), "lTag is not found on state");
            }

            auto const &mints = state->GetMints();
            BOOST_CHECK_EQUAL(coins.size(), mints.size());
            for (auto const &c : coins)
                BOOST_CHECK_MESSAGE(mints.count(c), "public is not found on state");

            auto retrievedId = state->GetLatestCoinID();

            CSparkState::SparkCoinGroupInfo group;
            state->GetCoinGroupInfo(retrievedId, group);
            BOOST_CHECK_EQUAL(lastId, retrievedId);
            BOOST_CHECK_EQUAL(first, group.firstBlock);
            BOOST_CHECK_EQUAL(last, group.lastBlock);
            BOOST_CHECK_EQUAL(coins.size(), group.nCoins);
        }
    } checker;

    checker.state = sparkState;

    // Cache empty checker
    auto emptyChecker = checker;

    mempool.clear();
    // Generate some txs which contain mints
    auto blockIdx1 = GenerateBlock({mintTxs[0], mintTxs[1]});
    BOOST_CHECK(blockIdx1);
    auto block1 = GetCBlock(blockIdx1);

    checker.coins.push_back(pwalletMain->sparkWallet->getCoinFromMeta(mints[0]));
    checker.coins.push_back(pwalletMain->sparkWallet->getCoinFromMeta(mints[1]));
    checker.first = blockIdx1;
    checker.last = blockIdx1;
    checker.lastId = 1;
    checker.Verify();

    // Generate empty blocks should not affect state
    GenerateBlocks(10);
    checker.Verify();

    // Add spend tx

    // Create two txs which contains same serial.
    CCoinControl coinControl;

    {
        auto tx = mintTxs[0];
        auto it = std::find_if(tx.vout.begin(), tx.vout.end(), [](CTxOut const &out) -> bool {
            return out.scriptPubKey.IsSparkMint();
        });
        BOOST_CHECK(it != tx.vout.end());

        coinControl.Select(COutPoint(tx.GetHash(), std::distance(tx.vout.begin(), it)));
    }

    auto sTx1 = GenerateSparkSpend({1 * COIN}, {}, &coinControl);

    // wait while another thread updates mint status in wallet, and then continue
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    // Update isused status
    {
        CSparkMintMeta meta = pwalletMain->sparkWallet->getMintMeta(mints[0].k);

        BOOST_CHECK(meta != CSparkMintMeta());
        BOOST_CHECK(meta.isUsed);

        meta.isUsed = false;
        pwalletMain->sparkWallet->updateMintInMemory(meta);
        meta = CSparkMintMeta();
        meta = pwalletMain->sparkWallet->getMintMeta(mints[0].k);
        BOOST_CHECK(!meta.isUsed);
    }

    std::size_t old_size = mempool.size();
    // Construct a duplicate without committing it. SpendAndStoreSpark now
    // rejects the mempool conflict before returning, while this test needs the
    // transaction below to exercise block-level rejection.
    CAmount duplicateFee = 0;
    CWalletTx duplicateWalletTx =
        pwalletMain->CreateSparkSpendTransaction(
            {{script, COIN, false}}, {}, duplicateFee, &coinControl);
    BOOST_REQUIRE(duplicateWalletTx.tx);
    CTransaction dupTx1(*duplicateWalletTx.tx);

    // check that it is not accepted into mempool
    BOOST_CHECK(old_size == mempool.size());

    std::vector<spark::Coin> dupNewCoins1;
    std::vector<GroupElement> dupTags1;
    ExtractSpend(dupTx1, dupNewCoins1, dupTags1);

    std::vector<spark::Coin> newCoins1;
    std::vector<GroupElement> tags1;
    ExtractSpend(sTx1, newCoins1, tags1);
    BOOST_CHECK_EQUAL(1, newCoins1.size());
    BOOST_CHECK_EQUAL(1, tags1.size());
    BOOST_CHECK(dupTags1[0] == tags1[0]);

    mempool.clear();
    auto blockIdx2 = GenerateBlock({sTx1});
    BOOST_CHECK(blockIdx2);

    auto block2 = GetCBlock(blockIdx2);

    auto cacheChecker = checker;
    checker.coins.push_back(newCoins1.front());
    checker.lTags.push_back(tags1.front());
    checker.last = blockIdx2;

    checker.Verify();

    // state should be rolled back
    BOOST_CHECK(DisconnectBlocks(1));
    BOOST_CHECK_EQUAL(chainActive.Tip()->nHeight, blockIdx2->nHeight - 1);
    cacheChecker.Verify();

    // reconnect
    reconnect(block2);
    checker.Verify();

    // add more block contain both mint and serial
    auto sTx2 = GenerateSparkSpend({1 * COIN}, {}, nullptr);

    std::vector<spark::Coin> newCoins2;
    std::vector<GroupElement> tags2;
    ExtractSpend(sTx2, newCoins2, tags2);
    BOOST_CHECK_EQUAL(1, newCoins2.size());
    BOOST_CHECK_EQUAL(1, tags2.size());

    BOOST_CHECK(mempool.size() == 1);
    mempool.clear();
    std::vector<CMutableTransaction> blockTX;
    auto blockIdx3 = GenerateBlock({mintTxs2[0], sTx2});
    BOOST_CHECK(blockIdx3);
    auto block3 = GetCBlock(blockIdx3);

    checker.coins.insert(checker.coins.end(), newCoins2.begin(), newCoins2.end());
    checker.coins.push_back(pwalletMain->sparkWallet->getCoinFromMeta(mints2[0]));
    checker.lTags.push_back(tags2[0]);
    checker.last = blockIdx3;

    checker.Verify();

    // Clear state and rebuild
    sparkState->Reset();
    emptyChecker.Verify();

    BuildSparkStateFromIndex(&chainActive);
    checker.Verify();

    // Disconnect all and reconnect
    std::vector<CBlock> blocks;
    while (chainActive.Tip() != chainActive.Genesis()) {
        blocks.push_back(GetCBlock(chainActive.Tip()));
        DisconnectBlocks(1);
    }

    emptyChecker.Verify();

    for (auto const &block : blocks) {
        reconnect(block);
    }

    checker.Verify();

    // double spend
    auto currentBlock = chainActive.Tip()->nHeight;
    BOOST_CHECK(!GenerateBlock({dupTx1}));
    BOOST_CHECK_EQUAL(currentBlock, chainActive.Tip()->nHeight);
    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(checktransaction)
{
    GenerateBlocks(500);

    // mints
    std::vector<CMutableTransaction> txs;
    GenerateMints({110 * COIN}, txs);
    auto &tx = txs[0];

    CValidationState state;
    CSparkTxInfo info;
    BOOST_CHECK(CheckSparkTransaction(
            txs[0], state, tx.GetHash(), false, chainActive.Height(), true, true, &info));

    std::vector<spark::Coin> expectedCoins = spark::GetSparkMintCoins(tx);
    BOOST_CHECK(expectedCoins == info.mints);

    // spend
    txs.clear();
    pwalletMain->SetBroadcastTransactions(true);
    auto mints = GenerateMints({10 * COIN, 1 * COIN}, txs);
    mempool.clear();

    auto currentBlock = chainActive.Tip()->nHeight;
    GenerateBlock(txs);
    BOOST_CHECK_EQUAL(currentBlock, chainActive.Tip()->nHeight -1);

    GenerateBlocks(10);

    auto outputAmount = 1 * COIN;
    FIRO_UNUSED auto mintAmount = 2 * CENT - CENT; // a cent as fee
    CAmount fee;
    CWalletTx wtx = pwalletMain->SpendAndStoreSpark({{script, outputAmount, false}}, {}, fee);

    CMutableTransaction spendTx(wtx);
    auto spend = ParseSparkSpend(spendTx);

    // test get join split amounts
    BOOST_CHECK_EQUAL(1, GetSpendInputs(spendTx));

    info = CSparkTxInfo();

    BOOST_CHECK(CheckSparkTransaction(
            spendTx, state, spendTx.GetHash(), false, chainActive.Height(), false, true, &info));

    auto &lTags = spend.getUsedLTags();
    auto &ids = spend.getCoinGroupIds();

    for (size_t i = 0; i != lTags.size(); i++) {
        bool hasLTag = false;
        BOOST_CHECK_MESSAGE(hasLTag = (info.spentLTags.count(lTags[i]) > 0), "No linking tag as expected");
        if (hasLTag) {
            BOOST_CHECK_MESSAGE(cmp::equal(ids[i], info.spentLTags[lTags[i]]), "linking tag group id is invalid");
        }
    }

    info = CSparkTxInfo();
    BOOST_CHECK(CheckSparkTransaction(
            spendTx, state, spendTx.GetHash(), false, chainActive.Height(), false, true, &info));

    info.spTransactions.clear();
    BOOST_CHECK(!CheckSparkTransaction(
            spendTx, state, spendTx.GetHash(), false, chainActive.Height(), false, true, &info));

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(spark_single_input_mempool_policy)
{
    GenerateBlocks(200);

    std::vector<CMutableTransaction> mintTransactions;
    const auto createdMints =
        GenerateMints({5 * COIN, 5 * COIN, 10 * COIN}, mintTransactions);
    mempool.clear();
    GenerateBlock(mintTransactions);
    GenerateBlocks(10);

    std::vector<CSparkMintMeta> selectedMints;
    for (const auto& mint : createdMints) {
        if (mint.v == 5 * COIN) {
            selectedMints.push_back(
                pwalletMain->sparkWallet->getMintMeta(mint.k));
        }
    }
    BOOST_REQUIRE_EQUAL(selectedMints.size(), 2U);
    const CTransaction multiInputSpend(
        GenerateHistoricalMultiInputSpend(selectedMints, 9 * COIN));
    const SpendTransaction parsed = ParseSparkSpend(multiInputSpend);
    BOOST_REQUIRE_EQUAL(parsed.getUsedLTags().size(), 2U);
    mempool.clear();

    // Until consensus activation, historical/block validation retains the
    // deployed verifier so existing blocks remain reindexable.
    CValidationState blockState;
    CSparkTxInfo blockInfo;
    BOOST_REQUIRE(CheckSparkTransaction(
        multiInputSpend,
        blockState,
        multiInputSpend.GetHash(),
        false,
        chainActive.Height(),
        false,
        true,
        &blockInfo));

    GenerateBlocks(185);

    // Upgraded nodes stop relaying multi-input spends immediately,
    // without assigning peer misbehavior points.
    CValidationState mempoolState;
    BOOST_CHECK(!CheckSparkTransaction(
        multiInputSpend,
        mempoolState,
        multiInputSpend.GetHash(),
        false,
        INT_MAX,
        false,
        true,
        nullptr));
    int mempoolDoS = -1;
    BOOST_REQUIRE(mempoolState.IsInvalid(mempoolDoS));
    BOOST_CHECK_EQUAL(mempoolDoS, 0);

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(spark_single_input_consensus_activation)
{
    RestoreSparkActivationHeights resetActivationHeights;

    GenerateBlocks(500);

    std::vector<CMutableTransaction> mintTransactions;
    const auto createdMints =
        GenerateMints({5 * COIN, 5 * COIN, 10 * COIN}, mintTransactions);
    mempool.clear();
    GenerateBlock(mintTransactions);
    GenerateBlocks(10);

    std::vector<CSparkMintMeta> selectedMints;
    for (const auto& mint : createdMints) {
        if (mint.v == 5 * COIN) {
            selectedMints.push_back(
                pwalletMain->sparkWallet->getMintMeta(mint.k));
        }
    }
    BOOST_REQUIRE_EQUAL(selectedMints.size(), 2U);
    const CTransaction multiInputSpend(
        GenerateHistoricalMultiInputSpend(selectedMints, 9 * COIN));
    const SpendTransaction parsed = ParseSparkSpend(multiInputSpend);
    BOOST_REQUIRE_EQUAL(parsed.getUsedLTags().size(), 2U);
    mempool.clear();

    const int activationHeight = chainActive.Height() + 1;
    UpdateRegtestSparkSingleInputHeight(activationHeight);

    const CTransaction singleInputSpend(
        GenerateSparkSpend({4 * COIN}, {}, nullptr));
    BOOST_REQUIRE_EQUAL(
        ParseSparkSpend(singleInputSpend).getUsedLTags().size(), 1U);
    mempool.clear();

    CValidationState historicalState;
    CSparkTxInfo historicalInfo;
    BOOST_REQUIRE(CheckSparkTransaction(
        multiInputSpend,
        historicalState,
        multiInputSpend.GetHash(),
        false,
        activationHeight - 1,
        false,
        true,
        &historicalInfo));

    CValidationState activeState;
    CSparkTxInfo activeInfo;
    BOOST_CHECK(!CheckSparkTransaction(
        multiInputSpend,
        activeState,
        multiInputSpend.GetHash(),
        false,
        activationHeight,
        false,
        true,
        &activeInfo));
    int activeDoS = 0;
    BOOST_REQUIRE(activeState.IsInvalid(activeDoS));
    BOOST_CHECK_EQUAL(activeDoS, 100);

    // Consensus keeps the single-input rule effective if an in-memory test
    // configuration bypasses the startup ordering check.
    Consensus::Params& mutableConsensus =
        const_cast<Consensus::Params&>(::Params().GetConsensus());
    const int originalV2Height = mutableConsensus.nSparkChaumV2StartBlock;
    mutableConsensus.nSparkSingleInputStartBlock = activationHeight + 1;
    mutableConsensus.nSparkChaumV2StartBlock = activationHeight;
    CValidationState defensiveState;
    CSparkTxInfo defensiveInfo;
    BOOST_CHECK(!CheckSparkTransaction(
        multiInputSpend,
        defensiveState,
        multiInputSpend.GetHash(),
        false,
        activationHeight,
        false,
        true,
        &defensiveInfo));
    BOOST_REQUIRE(defensiveState.IsInvalid(activeDoS));
    BOOST_CHECK_EQUAL(activeDoS, 100);
    mutableConsensus.nSparkSingleInputStartBlock = activationHeight;
    mutableConsensus.nSparkChaumV2StartBlock = originalV2Height;

    CValidationState historicalSingleState;
    CSparkTxInfo historicalSingleInfo;
    BOOST_REQUIRE(CheckSparkTransaction(
        singleInputSpend,
        historicalSingleState,
        singleInputSpend.GetHash(),
        false,
        activationHeight - 1,
        false,
        true,
        &historicalSingleInfo));

    CValidationState activeSingleState;
    CSparkTxInfo activeSingleInfo;
    BOOST_CHECK(CheckSparkTransaction(
        singleInputSpend,
        activeSingleState,
        singleInputSpend.GetHash(),
        false,
        activationHeight,
        false,
        true,
        &activeSingleInfo));

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(spark_single_input_wallet_requires_one_coin_immediately)
{
    GenerateBlocks(500);

    std::vector<CMutableTransaction> mintTransactions;
    GenerateMints({5 * COIN, 5 * COIN}, mintTransactions);
    mempool.clear();
    GenerateBlock(mintTransactions);
    GenerateBlocks(10);

    const auto hasSingleCoinMessage = [](const InsufficientFunds& error) {
        return std::string(error.what()).find(
            "No single available Spark coin can fund this transaction") !=
            std::string::npos;
    };
    try {
        GenerateSparkSpend({9 * COIN}, {}, nullptr);
        BOOST_FAIL("Expected InsufficientFunds for multi-coin V1 spend");
    } catch (const InsufficientFunds& error) {
        BOOST_CHECK(hasSingleCoinMessage(error));
    }

    const CTransaction singleInputSpend(
        GenerateSparkSpend({4 * COIN}, {}, nullptr));
    BOOST_CHECK_EQUAL(
        ParseSparkSpend(singleInputSpend).getUsedLTags().size(), 1U);

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(spark_v2_activation_and_wallet_selection)
{
    Consensus::Params& mutableConsensus =
        const_cast<Consensus::Params&>(::Params().GetConsensus());
    const int originalSparkNamesStartBlock =
        mutableConsensus.nSparkNamesStartBlock;
    struct ResetActivationHeights {
        Consensus::Params& consensus;
        int sparkNamesStartBlock;
        RestoreSparkActivationHeights sparkHeights;
        ~ResetActivationHeights()
        {
            BatchProofContainer::get_instance()->fCollectProofs = false;
            BatchProofContainer::get_instance()->init();
            consensus.nSparkNamesStartBlock = sparkNamesStartBlock;
        }
    } resetActivationHeights{
        mutableConsensus, originalSparkNamesStartBlock};

    GenerateBlocks(500);
    std::vector<CMutableTransaction> mintTransactions;
    const auto createdMints =
        GenerateMints({5 * COIN, 5 * COIN}, mintTransactions);
    mempool.clear();
    GenerateBlock(mintTransactions);
    GenerateBlocks(10);

    std::vector<CSparkMintMeta> fiveCoinMints;
    for (const auto& mint : createdMints) {
        if (mint.v == 5 * COIN) {
            fiveCoinMints.push_back(
                pwalletMain->sparkWallet->getMintMeta(mint.k));
        }
    }
    BOOST_REQUIRE_EQUAL(fiveCoinMints.size(), 2U);

    // Construct both formats before changing activation so their acceptance
    // can be tested at the exact boundary.
    const CTransaction v1Single(GenerateHistoricalMultiInputSpend(
        {fiveCoinMints[0]}, 4 * COIN, SpendTransactionVersion::V1));
    const CTransaction v2Multi(GenerateHistoricalMultiInputSpend(
        fiveCoinMints, 9 * COIN, SpendTransactionVersion::V2));
    BOOST_REQUIRE(v1Single.IsSparkSpendV1());
    BOOST_REQUIRE(v2Multi.IsSparkSpendV2());
    BOOST_REQUIRE(
        ParseSparkSpend(v2Multi).getVersion() == SpendTransactionVersion::V2);

    CMutableTransaction v2PayloadAsV1(v2Multi);
    v2PayloadAsV1.nType = TRANSACTION_SPARK;
    const CTransaction retaggedV2(v2PayloadAsV1);
    BOOST_REQUIRE(retaggedV2.IsSparkSpendV1());
    CMutableTransaction v1PayloadAsV2(v1Single);
    v1PayloadAsV2.nType = TRANSACTION_SPARK_V2;
    BOOST_CHECK_THROW(ParseSparkSpend(v1PayloadAsV2), std::exception);
    CMutableTransaction trailingV2(v2Multi);
    trailingV2.vExtraPayload.push_back(0);
    BOOST_CHECK_THROW(ParseSparkSpend(trailingV2), std::exception);

    CMutableTransaction oversizedFee(v2Multi);
    CDataStream feePosition(
        oversizedFee.vExtraPayload, SER_NETWORK, PROTOCOL_VERSION);
    uint8_t wireVersion;
    feePosition >> wireVersion;
    const uint64_t feeInputCount = ReadCompactSize(feePosition);
    FIRO_UNUSED const uint64_t feeOutputCount =
        ReadCompactSize(feePosition);
    for (uint64_t i = 0; i < feeInputCount; ++i) {
        uint64_t coverSetId;
        feePosition >> coverSetId;
    }
    const uint64_t blockHashCount = ReadCompactSize(feePosition);
    for (uint64_t i = 0; i < blockHashCount; ++i) {
        uint64_t coverSetId;
        uint256 blockHash;
        feePosition >> coverSetId >> blockHash;
    }
    const std::size_t feeOffset =
        oversizedFee.vExtraPayload.size() - feePosition.size();
    BOOST_REQUIRE_LE(feeOffset + sizeof(uint64_t),
        oversizedFee.vExtraPayload.size());
    std::fill_n(
        oversizedFee.vExtraPayload.begin() + feeOffset,
        sizeof(uint64_t),
        0xff);
    BOOST_CHECK_THROW(GetSparkSpendFee(oversizedFee), std::invalid_argument);
    mempool.clear();

    const int preActivationHeight = chainActive.Height();
    const int activationHeight = preActivationHeight + 2;
    UpdateRegtestSparkActivationHeights(
        &activationHeight, &activationHeight);
    // Live networks activated Spark Names before the V2 spend format. Exercise
    // that ordering instead of regtest's otherwise later names height.
    mutableConsensus.nSparkNamesStartBlock = 1;

    CValidationState retaggedV2State;
    CSparkTxInfo retaggedV2Info;
    BOOST_CHECK(!CheckSparkTransaction(
        retaggedV2,
        retaggedV2State,
        retaggedV2.GetHash(),
        false,
        activationHeight,
        false,
        true,
        &retaggedV2Info));

    CValidationState prematureContextualState;
    BOOST_CHECK(!IsSparkSpendFormatAllowed(
        v2Multi, activationHeight - 1));
    BOOST_CHECK(!ContextualCheckTransaction(
        v2Multi,
        prematureContextualState,
        ::Params().GetConsensus(),
        chainActive.Tip()));

    CValidationState prematureState;
    CSparkTxInfo prematureInfo;
    BOOST_CHECK(!CheckSparkTransaction(
        v2Multi,
        prematureState,
        v2Multi.GetHash(),
        false,
        activationHeight - 1,
        false,
        true,
        &prematureInfo));

    CValidationState prematureMempoolState;
    BOOST_CHECK(!CheckSparkTransaction(
        v2Multi,
        prematureMempoolState,
        v2Multi.GetHash(),
        false,
        INT_MAX,
        false,
        true,
        nullptr));
    int prematureMempoolDoS = -1;
    BOOST_REQUIRE(prematureMempoolState.IsInvalid(
        prematureMempoolDoS));
    BOOST_CHECK_EQUAL(prematureMempoolDoS, 0);

    CMutableTransaction malformedPrematureV2(v2Multi);
    malformedPrematureV2.vExtraPayload.clear();
    CValidationState malformedPrematureMempoolState;
    BOOST_CHECK(!CheckSparkTransaction(
        malformedPrematureV2,
        malformedPrematureMempoolState,
        malformedPrematureV2.GetHash(),
        false,
        INT_MAX,
        false,
        true,
        nullptr));
    int malformedPrematureMempoolDoS = -1;
    BOOST_REQUIRE(malformedPrematureMempoolState.IsInvalid(
        malformedPrematureMempoolDoS));
    BOOST_CHECK_EQUAL(malformedPrematureMempoolDoS, 0);

    BOOST_CHECK(!GenerateBlock({CMutableTransaction(v2Multi)}));
    BOOST_CHECK_EQUAL(chainActive.Height(), preActivationHeight);

    BOOST_REQUIRE(GenerateBlock({}));
    BOOST_REQUIRE_EQUAL(chainActive.Height(), activationHeight - 1);

    CValidationState activeContextualState;
    BOOST_CHECK(IsSparkSpendFormatAllowed(
        v2Multi, activationHeight));
    BOOST_CHECK(ContextualCheckTransaction(
        v2Multi,
        activeContextualState,
        ::Params().GetConsensus(),
        chainActive.Tip()));

    CValidationState activeV2State;
    CSparkTxInfo activeV2Info;
    BOOST_REQUIRE(CheckSparkTransaction(
        v2Multi,
        activeV2State,
        v2Multi.GetHash(),
        false,
        activationHeight,
        false,
        true,
        &activeV2Info));

    BatchProofContainer* batch = BatchProofContainer::get_instance();
    batch->init();
    batch->fCollectProofs = true;
    CValidationState batchedV2State;
    CSparkTxInfo batchedV2Info;
    BOOST_REQUIRE(CheckSparkTransaction(
        v2Multi,
        batchedV2State,
        v2Multi.GetHash(),
        false,
        activationHeight,
        false,
        true,
        &batchedV2Info));
    batch->finalize();
    BOOST_CHECK_NO_THROW(batch->verify());

    CValidationState activeV1State;
    CSparkTxInfo activeV1Info;
    BOOST_CHECK(CheckSparkTransaction(
        v1Single,
        activeV1State,
        v1Single.GetHash(),
        false,
        activationHeight,
        false,
        true,
        &activeV1Info));

    // After activation the wallet may select multiple coins again and must
    // emit only the explicitly versioned transaction type and payload.
    const CTransaction walletV2(GenerateSparkSpend({9 * COIN}, {}, nullptr));
    BOOST_CHECK(walletV2.IsSparkSpendV2());
    const SpendTransaction parsedWalletV2 = ParseSparkSpend(walletV2);
    BOOST_CHECK(parsedWalletV2.getVersion() == SpendTransactionVersion::V2);
    BOOST_CHECK_EQUAL(parsedWalletV2.getUsedLTags().size(), 2U);

    CRecipient coherenceRecipient;
    coherenceRecipient.scriptPubKey = script;
    coherenceRecipient.nAmount = COIN;
    CAmount coherenceFee = 0;
    int mismatchedNextBlockHeight;
    {
        LOCK(cs_main);
        mismatchedNextBlockHeight = chainActive.Height() + 2;
    }
    BOOST_CHECK_THROW(
        pwalletMain->sparkWallet->CreateSparkSpendTransaction(
            {coherenceRecipient},
            {},
            coherenceFee,
            nullptr,
            0,
            uint256(),
            mismatchedNextBlockHeight),
        std::runtime_error);

    // Wallet selection must enforce the same input bound as the V2 parser so
    // an oversized selection fails before expensive proof construction.
    std::list<CSparkMintMeta> boundedSelection(MAX_CHAUM_V2_INPUTS);
    for (auto& coin : boundedSelection) {
        coin.v = COIN;
    }
    const auto boundedResult =
        pwalletMain->sparkWallet->SelectSparkCoins(
            static_cast<CAmount>(boundedSelection.size()) * COIN,
            true,
            boundedSelection,
            0,
            1,
            nullptr,
            true,
            0);
    BOOST_CHECK_EQUAL(
        boundedResult.second.size(), MAX_CHAUM_V2_INPUTS);
    BOOST_CHECK_THROW(
        pwalletMain->sparkWallet->SelectSparkCoins(
            COIN,
            true,
            boundedSelection,
            0,
            1,
            nullptr,
            true,
            std::numeric_limits<std::size_t>::max()),
        std::invalid_argument);

    std::list<CSparkMintMeta> oversizedSelection = boundedSelection;
    oversizedSelection.push_back(CSparkMintMeta());
    oversizedSelection.back().v = COIN;
    BOOST_CHECK_THROW(
        pwalletMain->sparkWallet->SelectSparkCoins(
            static_cast<CAmount>(oversizedSelection.size()) * COIN,
            true,
            oversizedSelection,
            0,
            1,
            nullptr,
            true,
            0),
        std::invalid_argument);

    CRecipient maximumRecipient;
    maximumRecipient.scriptPubKey = script;
    maximumRecipient.nAmount = MAX_MONEY;
    CAmount rejectedFee = 0;
    BOOST_CHECK_THROW(
        pwalletMain->sparkWallet->CreateSparkSpendTransaction(
            {maximumRecipient, maximumRecipient}, {}, rejectedFee),
        std::runtime_error);
    const CFeeRate originalPayTxFee = payTxFee;
    payTxFee = CFeeRate(CAmount{1});
    std::list<CSparkMintMeta> maximumBalance(1);
    maximumBalance.front().v = MAX_MONEY;
    BOOST_CHECK_THROW(
        pwalletMain->sparkWallet->SelectSparkCoins(
            MAX_MONEY,
            false,
            maximumBalance,
            0,
            1,
            nullptr,
            true,
            0),
        std::invalid_argument);
    payTxFee = originalPayTxFee;

    OutputCoinData oversizedPrivateRecipient;
    oversizedPrivateRecipient.v = std::numeric_limits<uint64_t>::max();
    BOOST_CHECK_THROW(
        pwalletMain->sparkWallet->CreateSparkSpendTransaction(
            {}, {{oversizedPrivateRecipient, false}}, rejectedFee),
        std::runtime_error);

    // V2 private output scripts and their placement are consensus-canonical.
    // Otherwise third parties can change the txid without changing any proof
    // statement, tag, output coin, fee, or transparent value.
    mempool.clear();
    CMutableTransaction tailedPrivateOutput(walletV2);
    auto privateOutput = std::find_if(
        tailedPrivateOutput.vout.begin(), tailedPrivateOutput.vout.end(),
        [](const CTxOut& output) { return output.scriptPubKey.IsSparkSMint(); });
    BOOST_REQUIRE(privateOutput != tailedPrivateOutput.vout.end());
    privateOutput->scriptPubKey.push_back(0);
    CValidationState tailedState;
    CSparkTxInfo tailedInfo;
    BOOST_CHECK(!CheckSparkTransaction(
        tailedPrivateOutput,
        tailedState,
        tailedPrivateOutput.GetHash(),
        false,
        activationHeight,
        false,
        true,
        &tailedInfo));

    CMutableTransaction reorderedOutputs(walletV2);
    const auto reorderedPrivate = std::find_if(
        reorderedOutputs.vout.begin(), reorderedOutputs.vout.end(),
        [](const CTxOut& output) { return output.scriptPubKey.IsSparkSMint(); });
    BOOST_REQUIRE(reorderedPrivate != reorderedOutputs.vout.end());
    BOOST_REQUIRE(reorderedPrivate != reorderedOutputs.vout.begin());
    std::rotate(
        reorderedOutputs.vout.begin(),
        reorderedPrivate,
        std::next(reorderedPrivate));
    CValidationState reorderedState;
    CSparkTxInfo reorderedInfo;
    BOOST_CHECK(!CheckSparkTransaction(
        reorderedOutputs,
        reorderedState,
        reorderedOutputs.GetHash(),
        false,
        activationHeight,
        false,
        true,
        &reorderedInfo));

    CBlockIndex* activationIndex =
        GenerateBlock({CMutableTransaction(v2Multi)});
    BOOST_REQUIRE(activationIndex);
    BOOST_REQUIRE_EQUAL(chainActive.Height(), activationHeight);
    const CBlock activationBlock = GetCBlock(activationIndex);

    BOOST_REQUIRE(DisconnectBlocks(2));
    BOOST_REQUIRE_EQUAL(chainActive.Height(), activationHeight - 2);
    BOOST_REQUIRE(mempool.exists(v2Multi.GetHash()));
    BOOST_REQUIRE(IsFinalTx(
        v2Multi, chainActive.Height() + 1, GetAdjustedTime()));

    // A stale V2 transaction must be excluded from both miner selection
    // paths before V2 activation. A large priority delta forces the legacy
    // priority path independently of the package-level activation check.
    mempool.PrioritiseTransaction(
        v2Multi.GetHash(), v2Multi.GetHash().ToString(), 1e15, 0);
    std::unique_ptr<CBlockTemplate> preActivationTemplate;
    BOOST_CHECK_NO_THROW(preActivationTemplate =
        BlockAssembler(::Params()).CreateNewBlock(script));
    BOOST_REQUIRE(preActivationTemplate);
    BOOST_CHECK(std::none_of(
        preActivationTemplate->block.vtx.begin(), preActivationTemplate->block.vtx.end(),
        [&v2Multi](const CTransactionRef& tx) {
            return tx->GetHash() == v2Multi.GetHash();
        }));
    mempool.ClearPrioritisation(v2Multi.GetHash());

    std::unique_ptr<CBlockTemplate> preActivationPackageTemplate;
    BOOST_CHECK_NO_THROW(preActivationPackageTemplate =
        BlockAssembler(::Params()).CreateNewBlock(script));
    BOOST_REQUIRE(preActivationPackageTemplate);
    BOOST_CHECK(std::none_of(
        preActivationPackageTemplate->block.vtx.begin(),
        preActivationPackageTemplate->block.vtx.end(),
        [&v2Multi](const CTransactionRef& tx) {
            return tx->GetHash() == v2Multi.GetHash();
        }));

    {
        LOCK(cs_main);
        mempool.removeForReorg(
            pcoinsTip,
            chainActive.Height() + 1,
            STANDARD_LOCKTIME_VERIFY_FLAGS);
    }
    BOOST_CHECK(!mempool.exists(v2Multi.GetHash()));
    {
        LOCK(cs_main);
        CValidationState reconnectState;
        BOOST_REQUIRE(ActivateBestChain(
            reconnectState,
            ::Params(),
            std::make_shared<const CBlock>(activationBlock)));
    }
    BOOST_CHECK_EQUAL(chainActive.Height(), activationHeight);

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(spark_v2_private_fee_reporting_and_coin_control)
{
    struct RestoreBroadcastSetting {
        CWallet* wallet;
        bool enabled;
        ~RestoreBroadcastSetting()
        {
            wallet->SetBroadcastTransactions(enabled);
        }
    } restoreBroadcast{pwalletMain, pwalletMain->GetBroadcastTransactions()};
    pwalletMain->SetBroadcastTransactions(true);

    struct ResetActivationHeights {
        RestoreSparkActivationHeights sparkHeights;
    } resetActivationHeights;

    GenerateBlocks(500);
    std::vector<CMutableTransaction> mintTransactions;
    GenerateMints({5 * COIN, 5 * COIN}, mintTransactions);
    mempool.clear();
    BOOST_REQUIRE(GenerateBlock(mintTransactions));
    GenerateBlocks(10);

    const int activationHeight = chainActive.Height() + 1;
    UpdateRegtestSparkActivationHeights(
        &activationHeight, &activationHeight);

    // Per-send fee controls must govern both selection and the final size
    // check. The wallet must also report the exact post-fee private recipient
    // amount; the private output cannot be recovered later from public output
    // values when the GUI builds its confirmation.
    CCoinControl minimumFeeControl;
    minimumFeeControl.nMinimumTotalFee = maxTxFee / 2;
    BOOST_CHECK_EQUAL(
        CWallet::GetMinimumFee(1000, &minimumFeeControl, mempool),
        minimumFeeControl.nMinimumTotalFee);

    CCoinControl overrideFeeControl;
    overrideFeeControl.nMinimumTotalFee = maxTxFee / 2;
    overrideFeeControl.fOverrideFeeRate = true;
    overrideFeeControl.nFeeRate = CFeeRate(100000);

    OutputCoinData privateRecipient;
    {
        LOCK(pwalletMain->cs_wallet);
        privateRecipient.address =
            pwalletMain->sparkWallet->generateNewAddress();
    }
    privateRecipient.v = 2 * COIN;
    privateRecipient.memo = "fee-reporting";
    CAmount privateFee = 0;
    std::vector<CAmount> reportedRecipientAmounts;
    CWalletTx privateSpend =
        pwalletMain->CreateSparkSpendTransaction(
            {},
            {{privateRecipient, true}},
            privateFee,
            &overrideFeeControl,
            activationHeight,
            &reportedRecipientAmounts);
    BOOST_REQUIRE(privateSpend.tx);
    BOOST_REQUIRE(privateSpend.tx->IsSparkSpendV2());
    BOOST_CHECK_EQUAL(
        privateFee,
        overrideFeeControl.nFeeRate.GetFee(3403));
    BOOST_REQUIRE_EQUAL(reportedRecipientAmounts.size(), 1U);
    BOOST_CHECK_EQUAL(
        reportedRecipientAmounts.front(),
        static_cast<CAmount>(privateRecipient.v) - privateFee);

    const auto privateOutput = std::find_if(
        privateSpend.tx->vout.begin(),
        privateSpend.tx->vout.end(),
        [](const CTxOut& output) {
            return output.scriptPubKey.IsSparkSMint();
        });
    BOOST_REQUIRE(privateOutput != privateSpend.tx->vout.end());
    CSparkOutputTx uncommittedOutput;
    BOOST_CHECK(!pwalletMain->GetSparkOutputTx(
        privateOutput->scriptPubKey, uncommittedOutput));

    // A private-only transaction puts a Spark output at vout.begin(). This
    // also exercises metadata hashing without relying on invalidated vector
    // iterators.
    CValidationState privateSpendState;
    CSparkTxInfo privateSpendInfo;
    BOOST_CHECK(CheckSparkTransaction(
        *privateSpend.tx,
        privateSpendState,
        privateSpend.GetHash(),
        false,
        activationHeight,
        false,
        true,
        &privateSpendInfo));

    CValidationState commitState;
    CReserveKey reserveKey(pwalletMain);
    BOOST_REQUIRE(pwalletMain->CommitTransaction(
        privateSpend,
        reserveKey,
        g_connman.get(),
        commitState,
        true));
    CSparkOutputTx committedOutput;
    BOOST_REQUIRE(pwalletMain->GetSparkOutputTx(
        privateOutput->scriptPubKey, committedOutput));
    BOOST_CHECK_EQUAL(committedOutput.memo, privateRecipient.memo);
    BOOST_CHECK_EQUAL(
        committedOutput.amount,
        reportedRecipientAmounts.front());

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(spark_spend_commit_honors_rejection_and_broadcast_setting)
{
    struct RestoreBroadcastSetting {
        CWallet* wallet;
        bool enabled;
        ~RestoreBroadcastSetting()
        {
            wallet->SetBroadcastTransactions(enabled);
        }
    } restoreBroadcast{pwalletMain, pwalletMain->GetBroadcastTransactions()};

    GenerateBlocks(500);
    std::vector<CMutableTransaction> mintTransactions;
    const auto mints =
        GenerateMints({5 * COIN, 5 * COIN}, mintTransactions);
    mempool.clear();
    BOOST_REQUIRE(GenerateBlock(mintTransactions));
    GenerateBlocks(10);

    COutPoint conflictingOutpoint;
    BOOST_REQUIRE(GetOutPoint(
        conflictingOutpoint,
        pwalletMain->sparkWallet->getCoinFromMeta(mints[0])));
    CCoinControl conflictingControl;
    conflictingControl.fAllowOtherInputs = false;
    conflictingControl.fRequireAllInputs = true;
    conflictingControl.Select(conflictingOutpoint);
    pwalletMain->SetBroadcastTransactions(true);
    CAmount fee = 0;
    const CWalletTx accepted = pwalletMain->SpendAndStoreSpark(
        {{script, COIN, false}}, {}, fee, &conflictingControl);
    BOOST_REQUIRE(mempool.exists(accepted.GetHash()));

    for (int attempt = 0;
         attempt < 500 &&
             !pwalletMain->sparkWallet->getMintMeta(mints[0].k).isUsed;
         ++attempt) {
        MilliSleep(10);
    }
    BOOST_REQUIRE(
        pwalletMain->sparkWallet->getMintMeta(mints[0].k).isUsed);

    const std::vector<GroupElement> usedTags =
        ParseSparkSpend(*accepted.tx).getUsedLTags();
    BOOST_REQUIRE_EQUAL(usedTags.size(), 1U);
    pwalletMain->sparkWallet->setCoinUnused(usedTags.front());

    const std::size_t walletSizeBeforeRejection =
        pwalletMain->mapWallet.size();
    BOOST_CHECK_THROW(
        pwalletMain->SpendAndStoreSpark(
            {{script, COIN, false}}, {}, fee, &conflictingControl),
        std::runtime_error);
    BOOST_CHECK_EQUAL(
        pwalletMain->mapWallet.size(), walletSizeBeforeRejection);
    BOOST_CHECK(mempool.exists(accepted.GetHash()));

    COutPoint offlineOutpoint;
    BOOST_REQUIRE(GetOutPoint(
        offlineOutpoint,
        pwalletMain->sparkWallet->getCoinFromMeta(mints[1])));
    CCoinControl offlineControl;
    offlineControl.fAllowOtherInputs = false;
    offlineControl.fRequireAllInputs = true;
    offlineControl.Select(offlineOutpoint);
    pwalletMain->SetBroadcastTransactions(false);
    const std::size_t walletSizeBeforeOfflineSpend =
        pwalletMain->mapWallet.size();
    const CWalletTx offlineSpend = pwalletMain->SpendAndStoreSpark(
        {{script, COIN, false}}, {}, fee, &offlineControl);
    BOOST_CHECK_EQUAL(
        pwalletMain->mapWallet.size(), walletSizeBeforeOfflineSpend + 1);
    BOOST_CHECK(pwalletMain->GetWalletTx(offlineSpend.GetHash()));
    BOOST_CHECK(!mempool.exists(offlineSpend.GetHash()));

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(spark_single_input_historical_batch_verification)
{
    BatchProofContainer* batch = BatchProofContainer::get_instance();
    struct ResetBatchAndActivation {
        BatchProofContainer* batch;
        RestoreSparkActivationHeights heights;
        ~ResetBatchAndActivation()
        {
            batch->fCollectProofs = false;
            batch->init();
        }
    } reset{batch};

    GenerateBlocks(500);
    std::vector<CMutableTransaction> mintTransactions;
    const auto createdMints =
        GenerateMints({5 * COIN, 5 * COIN}, mintTransactions);
    mempool.clear();
    GenerateBlock(mintTransactions);
    GenerateBlocks(10);

    std::vector<CSparkMintMeta> selectedMints;
    for (const auto& mint : createdMints) {
        selectedMints.push_back(
            pwalletMain->sparkWallet->getMintMeta(mint.k));
    }
    const CTransaction multiInputSpend(
        GenerateHistoricalMultiInputSpend(selectedMints, 9 * COIN));

    batch->init();
    batch->fCollectProofs = true;
    CValidationState historicalState;
    CSparkTxInfo historicalInfo;
    BOOST_REQUIRE(CheckSparkTransaction(
        multiInputSpend,
        historicalState,
        multiInputSpend.GetHash(),
        false,
        chainActive.Height(),
        false,
        true,
        &historicalInfo));
    batch->finalize();
    BOOST_CHECK_NO_THROW(batch->verify());

    UpdateRegtestSparkSingleInputHeight(chainActive.Height());
    batch->init();
    batch->fCollectProofs = true;
    CValidationState activeState;
    CSparkTxInfo activeInfo;
    BOOST_CHECK(!CheckSparkTransaction(
        multiInputSpend,
        activeState,
        multiInputSpend.GetHash(),
        false,
        chainActive.Height(),
        false,
        true,
        &activeInfo));
    int activeDoS = 0;
    BOOST_REQUIRE(activeState.IsInvalid(activeDoS));
    BOOST_CHECK_EQUAL(activeDoS, 100);
}

BOOST_AUTO_TEST_CASE(batched_spark_proofs_are_verified_inside_connect_block)
{
    BatchProofContainer* batch = BatchProofContainer::get_instance();
    struct ResetBatch {
        BatchProofContainer* batch;
        ~ResetBatch()
        {
            batch->fCollectProofs = false;
            batch->init();
        }
    } reset{batch};

    GenerateBlocks(500);
    std::vector<CMutableTransaction> mintTransactions;
    GenerateMints({5 * COIN, 1 * COIN}, mintTransactions);
    mempool.clear();
    BOOST_REQUIRE(GenerateBlock(mintTransactions));
    GenerateBlocks(10);

    CMutableTransaction invalidSpend(
        GenerateSparkSpend({4 * COIN}, {}, nullptr));
    BOOST_REQUIRE(!invalidSpend.vout.empty());
    ++invalidSpend.vout.front().nValue;
    mempool.clear();

    CBlock candidate = CreateBlock({invalidSpend}, script);
    uint256 candidateHash = candidate.GetHash();
    CBlockIndex candidateIndex(candidate);
    candidateIndex.phashBlock = &candidateHash;
    candidateIndex.pprev = chainActive.Tip();
    candidateIndex.nHeight = chainActive.Height() + 1;
    // Use a recent block time so ConnectBlock verifies proofs inline instead
    // of deferring them (master IBD batching path).
    candidateIndex.nTime = GetSystemTimeInSeconds();

    CValidationState state;
    CCoinsViewCache view(pcoinsTip);
    {
        LOCK(cs_main);
        BOOST_CHECK(!ConnectBlock(
            candidate, state, &candidateIndex, view, ::Params(), true));
    }

    // VerifyDB must avoid tip-state mutation without skipping the proof.
    CValidationState verifyState;
    CCoinsViewCache verifyView(pcoinsTip);
    {
        LOCK(cs_main);
        BOOST_CHECK(!ConnectBlock(
            candidate,
            verifyState,
            &candidateIndex,
            verifyView,
            ::Params(),
            true,
            true));
    }

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(abandoned_connect_block_clears_batched_spark_proofs)
{
    BatchProofContainer* batch = BatchProofContainer::get_instance();
    struct ResetBatch {
        BatchProofContainer* batch;
        ~ResetBatch()
        {
            batch->fCollectProofs = false;
            batch->init();
        }
    } reset{batch};

    GenerateBlocks(500);
    std::vector<CMutableTransaction> mintTransactions;
    GenerateMints({5 * COIN, 1 * COIN}, mintTransactions);
    mempool.clear();
    BOOST_REQUIRE(GenerateBlock(mintTransactions));
    GenerateBlocks(10);

    CMutableTransaction invalidSpend(
        GenerateSparkSpend({4 * COIN}, {}, nullptr));
    BOOST_REQUIRE(!invalidSpend.vout.empty());
    ++invalidSpend.vout.front().nValue;

    CMutableTransaction missingInput;
    missingInput.vin.emplace_back(COutPoint(uint256S("01"), 0));
    missingInput.vout.emplace_back(1, script);
    mempool.clear();

    CBlock candidate = CreateBlock({invalidSpend, missingInput}, script);
    uint256 candidateHash = candidate.GetHash();
    CBlockIndex candidateIndex(candidate);
    candidateIndex.phashBlock = &candidateHash;
    candidateIndex.pprev = chainActive.Tip();
    candidateIndex.nHeight = chainActive.Height() + 1;
    // Old enough to enable deferred batching while ConnectBlock still fails
    // on the missing transparent input before finalize.
    candidateIndex.nTime = GetSystemTimeInSeconds() - 86401;

    CValidationState state;
    CCoinsViewCache view(pcoinsTip);
    {
        LOCK(cs_main);
        BOOST_CHECK(!ConnectBlock(
            candidate, state, &candidateIndex, view, ::Params(), true));
    }

    // Master deferred batching does not abort() on ConnectBlock failure; the
    // next ConnectBlock init() (or an explicit init here) drops temps.
    batch->init();
    batch->fCollectProofs = false;
    BOOST_CHECK_NO_THROW(batch->verify());

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(verifydb_level_four_reconnects_spark_spend_and_mints)
{
    BatchProofContainer::get_instance()->fCollectProofs = false;
    BatchProofContainer::get_instance()->init();

    GenerateBlocks(500);
    std::vector<CMutableTransaction> mintTransactions;
    GenerateMints({5 * COIN, 1 * COIN}, mintTransactions);
    mempool.clear();
    BOOST_REQUIRE(GenerateBlock(mintTransactions));
    GenerateBlocks(10);

    CMutableTransaction spend(GenerateSparkSpend({4 * COIN}, {}, nullptr));
    mempool.clear();
    BOOST_REQUIRE(GenerateBlock({spend}));

    CVerifyDB verifier;
    BOOST_CHECK(verifier.VerifyDB(::Params(), pcoinsTip, 4, 12));

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(verifydb_rejects_invalid_standalone_spark_mint)
{
    BatchProofContainer::get_instance()->fCollectProofs = false;
    BatchProofContainer::get_instance()->init();

    GenerateBlocks(500);

    std::vector<CMutableTransaction> mintTransactions;
    GenerateMints({5 * COIN}, mintTransactions);
    BOOST_REQUIRE_EQUAL(mintTransactions.size(), 1U);
    mempool.clear();

    CMutableTransaction invalidMint(mintTransactions.front());
    auto mintOutput = std::find_if(
        invalidMint.vout.begin(),
        invalidMint.vout.end(),
        [](const CTxOut& output) {
            return output.scriptPubKey.IsSparkMint();
        });
    BOOST_REQUIRE(mintOutput != invalidMint.vout.end());
    BOOST_REQUIRE(mintOutput->scriptPubKey.size() > 1U);
    mintOutput->scriptPubKey.back() ^= 1;

    const CTransaction invalidTransaction(invalidMint);
    CValidationState state;
    CSparkTxInfo info;
    BOOST_CHECK(!CheckSparkTransaction(
        invalidTransaction,
        state,
        invalidTransaction.GetHash(),
        true,
        chainActive.Height() + 1,
        false,
        true,
        &info));
}

BOOST_AUTO_TEST_CASE(verifydb_rejects_same_block_spark_double_spend)
{
    BatchProofContainer::get_instance()->fCollectProofs = false;
    BatchProofContainer::get_instance()->init();

    GenerateBlocks(500);
    std::vector<CMutableTransaction> mintTransactions;
    const auto mints = GenerateMints({5 * COIN, 1 * COIN}, mintTransactions);
    mempool.clear();
    BOOST_REQUIRE(GenerateBlock(mintTransactions));
    GenerateBlocks(10);

    CCoinControl coinControl;
    const auto mintOutput = std::find_if(
        mintTransactions[0].vout.begin(),
        mintTransactions[0].vout.end(),
        [](const CTxOut& output) { return output.scriptPubKey.IsSparkMint(); });
    BOOST_REQUIRE(mintOutput != mintTransactions[0].vout.end());
    coinControl.Select(COutPoint(
        mintTransactions[0].GetHash(),
        std::distance(mintTransactions[0].vout.begin(), mintOutput)));

    const CMutableTransaction firstSpend(
        GenerateSparkSpend({1 * COIN}, {}, &coinControl));
    CSparkMintMeta mintMeta =
        pwalletMain->sparkWallet->getMintMeta(mints[0].k);
    BOOST_REQUIRE(mintMeta != CSparkMintMeta());
    mintMeta.isUsed = false;
    pwalletMain->sparkWallet->updateMintInMemory(mintMeta);
    const CMutableTransaction duplicateSpend(
        GenerateSparkSpend({1 * COIN}, {}, &coinControl));
    mempool.clear();

    BOOST_REQUIRE(firstSpend.GetHash() != duplicateSpend.GetHash());
    BOOST_REQUIRE(
        ParseSparkSpend(firstSpend).getUsedLTags() ==
        ParseSparkSpend(duplicateSpend).getUsedLTags());

    CBlock candidate = CreateBlock({firstSpend, duplicateSpend}, script);
    uint256 candidateHash = candidate.GetHash();
    CBlockIndex candidateIndex(candidate);
    candidateIndex.phashBlock = &candidateHash;
    candidateIndex.pprev = chainActive.Tip();
    candidateIndex.nHeight = chainActive.Height() + 1;

    CValidationState state;
    CCoinsViewCache view(pcoinsTip);
    {
        LOCK(cs_main);
        BOOST_CHECK(!ConnectBlock(
            candidate,
            state,
            &candidateIndex,
            view,
            ::Params(),
            true,
            true));
    }

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(verifydb_rejects_cross_block_spark_double_spend)
{
    BatchProofContainer::get_instance()->fCollectProofs = false;
    BatchProofContainer::get_instance()->init();

    GenerateBlocks(500);
    std::vector<CMutableTransaction> mintTransactions;
    const auto mints = GenerateMints({5 * COIN, 1 * COIN}, mintTransactions);
    mempool.clear();
    BOOST_REQUIRE(GenerateBlock(mintTransactions));
    GenerateBlocks(10);

    CCoinControl coinControl;
    const auto mintOutput = std::find_if(
        mintTransactions[0].vout.begin(),
        mintTransactions[0].vout.end(),
        [](const CTxOut& output) { return output.scriptPubKey.IsSparkMint(); });
    BOOST_REQUIRE(mintOutput != mintTransactions[0].vout.end());
    coinControl.Select(COutPoint(
        mintTransactions[0].GetHash(),
        std::distance(mintTransactions[0].vout.begin(), mintOutput)));

    const CTransaction firstSpend(
        GenerateSparkSpend({1 * COIN}, {}, &coinControl));
    CSparkMintMeta mintMeta =
        pwalletMain->sparkWallet->getMintMeta(mints[0].k);
    BOOST_REQUIRE(mintMeta != CSparkMintMeta());
    mintMeta.isUsed = false;
    pwalletMain->sparkWallet->updateMintInMemory(mintMeta);
    const CTransaction duplicateSpend(
        GenerateSparkSpend({1 * COIN}, {}, &coinControl));
    mempool.clear();

    BOOST_REQUIRE(
        ParseSparkSpend(firstSpend).getUsedLTags() ==
        ParseSparkSpend(duplicateSpend).getUsedLTags());

    CSparkVerifyDBContext verifyContext(chainActive.Tip());
    CSparkTxInfo firstInfo;
    CValidationState firstState;
    BOOST_REQUIRE(CheckSparkTransaction(
        firstSpend,
        firstState,
        firstSpend.GetHash(),
        true,
        chainActive.Height() + 1,
        false,
        true,
        &firstInfo));

    CBlockIndex firstSpendIndex;
    firstSpendIndex.pprev = chainActive.Tip();
    firstSpendIndex.nHeight = chainActive.Height() + 1;
    firstSpendIndex.spentLTags = firstInfo.spentLTags;
    verifyContext.AddBlock(&firstSpendIndex);

    CSparkTxInfo duplicateInfo;
    CValidationState duplicateState;
    BOOST_CHECK(!CheckSparkTransaction(
        duplicateSpend,
        duplicateState,
        duplicateSpend.GetHash(),
        true,
        chainActive.Height() + 2,
        false,
        true,
        &duplicateInfo));

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(spark_single_input_block_boundary_and_reorg)
{
    RestoreSparkActivationHeights resetActivationHeights;

    GenerateBlocks(500);
    std::vector<CMutableTransaction> mintTransactions;
    const auto createdMints = GenerateMints(
        {5 * COIN, 5 * COIN, 5 * COIN, 5 * COIN, 10 * COIN},
        mintTransactions);
    mempool.clear();
    GenerateBlock(mintTransactions);
    GenerateBlocks(10);

    std::vector<CSparkMintMeta> fiveCoinMints;
    for (const auto& mint : createdMints) {
        if (mint.v == 5 * COIN) {
            fiveCoinMints.push_back(
                pwalletMain->sparkWallet->getMintMeta(mint.k));
        }
    }
    BOOST_REQUIRE_EQUAL(fiveCoinMints.size(), 4U);

    const CTransaction historicalMultiInput =
        GenerateHistoricalMultiInputSpend(
            {fiveCoinMints[0], fiveCoinMints[1]}, 9 * COIN);
    const CTransaction activeMultiInput =
        GenerateHistoricalMultiInputSpend(
            {fiveCoinMints[2], fiveCoinMints[3]}, 9 * COIN);
    const CTransaction activeSingleInput(
        GenerateSparkSpend({4 * COIN}, {}, nullptr));
    mempool.clear();

    const int baseHeight = chainActive.Height();
    const int activationHeight = baseHeight + 2;
    UpdateRegtestSparkSingleInputHeight(activationHeight);

    BOOST_CHECK(IsSparkSpendFormatAllowed(
        historicalMultiInput, activationHeight - 1));
    BOOST_CHECK(!IsSparkSpendFormatAllowed(
        historicalMultiInput, activationHeight));
    BOOST_CHECK(IsSparkSpendFormatAllowed(
        activeSingleInput, activationHeight));

    TestMemPoolEntryHelper mempoolEntry;
    mempool.addUnchecked(
        historicalMultiInput.GetHash(),
        mempoolEntry.Height(baseHeight).FromTx(historicalMultiInput));
    BOOST_REQUIRE(mempool.exists(historicalMultiInput.GetHash()));
    {
        LOCK(cs_main);
        mempool.removeForReorg(
            pcoinsTip, activationHeight - 1, LOCKTIME_VERIFY_SEQUENCE);
    }
    BOOST_CHECK(mempool.exists(historicalMultiInput.GetHash()));
    {
        LOCK(cs_main);
        mempool.removeForReorg(
            pcoinsTip, activationHeight, LOCKTIME_VERIFY_SEQUENCE);
    }
    BOOST_CHECK(!mempool.exists(historicalMultiInput.GetHash()));

    CBlockIndex* historicalIndex =
        GenerateBlock({CMutableTransaction(historicalMultiInput)});
    BOOST_REQUIRE(historicalIndex);
    BOOST_REQUIRE_EQUAL(chainActive.Height(), activationHeight - 1);
    const CBlock historicalBlock = GetCBlock(historicalIndex);

    BOOST_CHECK(!GenerateBlock({CMutableTransaction(activeMultiInput)}));
    BOOST_CHECK_EQUAL(chainActive.Height(), activationHeight - 1);

    CBlockIndex* activationIndex =
        GenerateBlock({CMutableTransaction(activeSingleInput)});
    BOOST_REQUIRE(activationIndex);
    BOOST_REQUIRE_EQUAL(chainActive.Height(), activationHeight);
    const CBlock activationBlock = GetCBlock(activationIndex);

    BOOST_REQUIRE(DisconnectBlocks(2));
    BOOST_REQUIRE_EQUAL(chainActive.Height(), baseHeight);

    const auto reconnect = [](const CBlock& block) {
        LOCK(cs_main);
        CValidationState state;
        const auto shared = std::make_shared<const CBlock>(block);
        BOOST_REQUIRE(ActivateBestChain(state, ::Params(), shared));
    };

    // Supplying the first disconnected block lets ActivateBestChain reconnect
    // the known two-block branch across the boundary in one activation step.
    reconnect(historicalBlock);
    BOOST_CHECK_EQUAL(chainActive.Height(), activationHeight);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == activationBlock.GetHash());
}

BOOST_AUTO_TEST_CASE(spark_proof_cache_is_invalidated_on_cover_set_reorg)
{
    ClearSparkSpendProofCache();
    GenerateBlocks(500);

    std::vector<CMutableTransaction> firstMintTransactions;
    GenerateMints({5 * COIN}, firstMintTransactions);
    mempool.clear();
    CBlockIndex* firstMintIndex = GenerateBlock(firstMintTransactions);
    BOOST_REQUIRE(firstMintIndex);
    GenerateBlocks(10);

    std::vector<CMutableTransaction> secondMintTransactions;
    GenerateMints({5 * COIN}, secondMintTransactions);
    mempool.clear();
    CBlockIndex* secondMintIndex = GenerateBlock(secondMintTransactions);
    BOOST_REQUIRE(secondMintIndex);
    GenerateBlocks(10);

    const CTransaction spend = GenerateSparkSpend({4 * COIN}, {}, nullptr);
    SpendTransaction parsed = ParseSparkSpend(spend);
    const auto references = parsed.getBlockHashes();
    BOOST_REQUIRE_EQUAL(references.size(), 1U);
    BOOST_REQUIRE(references.begin()->second == secondMintIndex->GetBlockHash());

    // Mempool validation populates the proof cache for the two-coin cover set.
    CValidationState mempoolState;
    BOOST_REQUIRE(CheckSparkTransaction(
        spend,
        mempoolState,
        spend.GetHash(),
        false,
        INT_MAX,
        false,
        true,
        nullptr));
    BOOST_CHECK_EQUAL(GetSparkSpendProofCacheSize(), 1U);

    CMutableTransaction invalidSpend(spend);
    BOOST_REQUIRE(!invalidSpend.vout.empty());
    ++invalidSpend.vout.front().nValue;
    CValidationState invalidState;
    BOOST_CHECK(!CheckSparkTransaction(
        CTransaction(invalidSpend),
        invalidState,
        invalidSpend.GetHash(),
        false,
        INT_MAX,
        false,
        true,
        nullptr));
    // Failures are cached too (same as master), under a different txid.
    BOOST_CHECK_EQUAL(GetSparkSpendProofCacheSize(), 2U);

    // Remove the referenced cover-set block while leaving the first mint and
    // group active. Validation must recompute the result for the new context.
    const int disconnectCount =
        chainActive.Height() - secondMintIndex->nHeight + 1;
    BOOST_REQUIRE_GT(disconnectCount, 0);
    BOOST_REQUIRE(DisconnectBlocks(disconnectCount));
    BOOST_REQUIRE(chainActive.Height() >= firstMintIndex->nHeight);
    BOOST_CHECK_EQUAL(GetSparkSpendProofCacheSize(), 0U);

    CValidationState reorgState;
    CSparkTxInfo reorgInfo;
    BOOST_CHECK(!CheckSparkTransaction(
        spend,
        reorgState,
        spend.GetHash(),
        false,
        chainActive.Height() + 1,
        false,
        true,
        &reorgInfo));

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(spark_unknown_cover_set_reference_is_not_mempool_admissible)
{
    RestoreSparkActivationHeights resetActivationHeights;

    GenerateBlocks(500);

    std::vector<CMutableTransaction> mintTransactions;
    GenerateMints({5 * COIN, 1 * COIN}, mintTransactions);
    mempool.clear();
    BOOST_REQUIRE(GenerateBlock(mintTransactions));
    GenerateBlocks(10);

    const CTransaction spend = GenerateSparkSpend({4 * COIN}, {}, nullptr);
    SpendTransaction parsed = ParseSparkSpend(spend);
    auto references = parsed.getBlockHashes();
    BOOST_REQUIRE_EQUAL(references.size(), 1U);
    references.begin()->second = uint256S("01");
    parsed.setBlockHashes(references);

    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << parsed;
    CMutableTransaction unknownReference(spend);
    unknownReference.vExtraPayload.assign(payload.begin(), payload.end());

    CValidationState state;
    BOOST_CHECK(!CheckSparkTransaction(
        CTransaction(unknownReference),
        state,
        unknownReference.GetHash(),
        false,
        INT_MAX,
        false,
        true,
        nullptr));
    int dos = -1;
    BOOST_REQUIRE(state.IsInvalid(dos));
    BOOST_CHECK_EQUAL(dos, 0);

    auto unavailableReferences = parsed.getBlockHashes();
    BOOST_REQUIRE_EQUAL(unavailableReferences.size(), 1U);
    const uint256 referenceHash = unavailableReferences.begin()->second;
    unavailableReferences.clear();
    unavailableReferences.emplace(
        static_cast<uint64_t>(sparkState->GetLatestCoinID()) + 1,
        referenceHash);
    parsed.setBlockHashes(unavailableReferences);
    CDataStream unavailablePayload(SER_NETWORK, PROTOCOL_VERSION);
    unavailablePayload << parsed;
    CMutableTransaction unavailableGroup(spend);
    unavailableGroup.vExtraPayload.assign(
        unavailablePayload.begin(), unavailablePayload.end());

    CValidationState unavailableState;
    BOOST_CHECK(!CheckSparkTransaction(
        CTransaction(unavailableGroup),
        unavailableState,
        unavailableGroup.GetHash(),
        false,
        INT_MAX,
        false,
        true,
        nullptr));
    BOOST_REQUIRE(unavailableState.IsInvalid(dos));
    BOOST_CHECK_EQUAL(dos, 0);

    unavailableReferences.clear();
    unavailableReferences.emplace(
        static_cast<uint64_t>(std::numeric_limits<int>::max()) + 1,
        referenceHash);
    parsed.setBlockHashes(unavailableReferences);
    CDataStream outOfRangePayload(SER_NETWORK, PROTOCOL_VERSION);
    outOfRangePayload << parsed;
    CMutableTransaction outOfRangeGroup(spend);
    outOfRangeGroup.vExtraPayload.assign(
        outOfRangePayload.begin(), outOfRangePayload.end());

    CValidationState outOfRangeState;
    BOOST_CHECK(!CheckSparkTransaction(
        CTransaction(outOfRangeGroup),
        outOfRangeState,
        outOfRangeGroup.GetHash(),
        false,
        INT_MAX,
        false,
        true,
        nullptr));
    BOOST_REQUIRE(outOfRangeState.IsInvalid(dos));
    BOOST_CHECK_EQUAL(dos, 0);

    const int activationHeight = chainActive.Height() + 1;
    UpdateRegtestSparkSingleInputHeight(activationHeight);

    BatchProofContainer* batch = BatchProofContainer::get_instance();
    batch->init();
    batch->fCollectProofs = true;
    CValidationState batchedOutOfRangeState;
    CSparkTxInfo batchedOutOfRangeInfo;
    BOOST_CHECK(!CheckSparkTransaction(
        CTransaction(outOfRangeGroup),
        batchedOutOfRangeState,
        outOfRangeGroup.GetHash(),
        false,
        activationHeight,
        false,
        true,
        &batchedOutOfRangeInfo));
    BOOST_REQUIRE(batchedOutOfRangeState.IsInvalid(dos));
    BOOST_CHECK_EQUAL(dos, 100);
    batch->finalize();
    BOOST_CHECK_NO_THROW(batch->verify());

    CValidationState historicalState;
    CSparkTxInfo historicalInfo;
    BOOST_CHECK(CheckSparkTransaction(
        CTransaction(unknownReference),
        historicalState,
        unknownReference.GetHash(),
        false,
        activationHeight - 1,
        false,
        true,
        &historicalInfo));

    CValidationState activeState;
    CSparkTxInfo activeInfo;
    BOOST_CHECK(!CheckSparkTransaction(
        CTransaction(unknownReference),
        activeState,
        unknownReference.GetHash(),
        false,
        activationHeight,
        false,
        true,
        &activeInfo));
    BOOST_REQUIRE(activeState.IsInvalid(dos));
    BOOST_CHECK_EQUAL(dos, 100);

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(spark_activation_order_is_validated)
{
    Consensus::Params& consensus =
        const_cast<Consensus::Params&>(::Params().GetConsensus());
    const int originalSingleInput = consensus.nSparkSingleInputStartBlock;
    const int originalV2 = consensus.nSparkChaumV2StartBlock;
    struct RestoreActivationHeights {
        Consensus::Params& consensus;
        int singleInput;
        int v2;
        ~RestoreActivationHeights()
        {
            consensus.nSparkSingleInputStartBlock = singleInput;
            consensus.nSparkChaumV2StartBlock = v2;
        }
    } restore{consensus, originalSingleInput, originalV2};

    BOOST_CHECK_THROW(
        UpdateRegtestSparkChaumV2Height(100), std::runtime_error);
    BOOST_CHECK_EQUAL(consensus.nSparkChaumV2StartBlock, originalV2);

    UpdateRegtestSparkSingleInputHeight(100);
    UpdateRegtestSparkChaumV2Height(100);
    BOOST_CHECK_NO_THROW(ValidateSparkActivationHeights(consensus));

    // Raising both past the previous V2 height must succeed when applied
    // together (CLI parses both before validating the final pair).
    const int jointSingle = 800;
    const int jointV2 = 900;
    UpdateRegtestSparkActivationHeights(&jointSingle, &jointV2);
    BOOST_CHECK_EQUAL(consensus.nSparkSingleInputStartBlock, 800);
    BOOST_CHECK_EQUAL(consensus.nSparkChaumV2StartBlock, 900);

    // An invalid joint update rolls both heights back.
    const int badSingle = 950;
    const int badV2 = 900;
    BOOST_CHECK_THROW(
        UpdateRegtestSparkActivationHeights(&badSingle, &badV2),
        std::runtime_error);
    BOOST_CHECK_EQUAL(consensus.nSparkSingleInputStartBlock, 800);
    BOOST_CHECK_EQUAL(consensus.nSparkChaumV2StartBlock, 900);

    consensus.nSparkSingleInputStartBlock = 101;
    BOOST_CHECK_THROW(
        ValidateSparkActivationHeights(consensus), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(coingroup)
{
    GenerateBlocks(500);

    // util function
    auto reconnect = [](CBlock const &block) {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        LOCK(mempool.cs);

        std::shared_ptr<CBlock const> sharedBlock =
                std::make_shared<CBlock const>(block);

        CValidationState state;
        ActivateBestChain(state, ::Params(), sharedBlock);
    };

    struct {
        // expected state.
        std::vector<spark::Coin> coins;

        // first group
        CBlockIndex *first = nullptr;
        CBlockIndex *last = nullptr;

        int lastId = 0;
        size_t lastGroupCoins = 0;

        // real state
        CSparkState *state;

        void Verify(std::string stateName = "") const {
            auto const &mints = state->GetMints();
            BOOST_CHECK_EQUAL(coins.size(), mints.size());
            for (auto const &c : coins) {
                BOOST_CHECK_MESSAGE(mints.count(c), "Coin is not found on state : " + stateName);
            }

            auto retrievedId = state->GetLatestCoinID();

            CSparkState::SparkCoinGroupInfo group;
            state->GetCoinGroupInfo(retrievedId, group);

            BOOST_CHECK_EQUAL(lastId, retrievedId);
            BOOST_CHECK_EQUAL(first, group.firstBlock);
            BOOST_CHECK_EQUAL(last, group.lastBlock);
            BOOST_CHECK_EQUAL(lastGroupCoins, group.nCoins);
        }
    } checker;
    checker.state = sparkState;

    sparkState->~CSparkState();
    new (sparkState) CSparkState(65, 16);
    sparkState->Reset();

    pwalletMain->SetBroadcastTransactions(true);
    // logic
    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints(std::vector<CAmount>(10, 1), txs);

    auto txRange = [&](size_t start, size_t end) -> std::vector<CMutableTransaction> {
        std::vector<CMutableTransaction> rangeTxs;
        for (auto i = start; i < end && i < txs.size(); i++) {
            rangeTxs.push_back(txs[i]);
        }

        return rangeTxs;
    };

    auto emptyChecker = checker;
    emptyChecker.Verify();

    // add one block
    mempool.clear();
    auto idx1 = GenerateBlock(txRange(0, 1));
    auto block1 = GetCBlock(idx1);
    checker.coins.push_back(pwalletMain->sparkWallet->getCoinFromMeta(mints[0]));
    checker.lastId = 1;
    checker.first = idx1;
    checker.last = idx1;
    checker.lastGroupCoins = 1;
    checker.Verify();

    // add more
    auto idx2 = GenerateBlock(txRange(1, 10));
    auto block2 = GetCBlock(idx2);
    for (size_t i = 0; i < (mints.size() - 1); ++i)
        checker.coins.push_back(pwalletMain->sparkWallet->getCoinFromMeta(mints[i]));

    checker.last = idx2;
    checker.lastGroupCoins = 10;
    checker.Verify();

    auto cacheIdx2Checker = checker;


    // add more to fill group
    txs.clear();
    mints = GenerateMints(std::vector<CAmount>(55, 1), txs);
    mempool.clear();
    auto idx3 = GenerateBlock(txRange(0, 22));
    auto block3 = GetCBlock(idx3);
    auto idx4 = GenerateBlock(txRange(22, 55));
    auto block4 = GetCBlock(idx4);
    for (size_t i = 0; i < mints.size(); ++i)
        checker.coins.push_back(pwalletMain->sparkWallet->getCoinFromMeta(mints[i]));
     checker.last = idx4;
     checker.lastGroupCoins = 65;
     checker.Verify();

    auto cacheIdx3Checker = checker;
    txs.clear();
    mints = GenerateMints(std::vector<CAmount>(1, 1), txs);
    mempool.clear();

    // add one more to create new group
    auto idx5 = GenerateBlock(txRange(0, 1));
    auto block5 = GetCBlock(idx5);
    checker.coins.push_back(pwalletMain->sparkWallet->getCoinFromMeta(mints[mints.size()-1]));
    checker.lastId = 2;
    checker.lastGroupCoins = 34;
    checker.first = idx4;
    checker.last = idx5;
    checker.Verify();

    // remove last block check coingroup
    DisconnectBlocks(1);
    cacheIdx3Checker.Verify();

    // remove one more block
    DisconnectBlocks(2);
    cacheIdx2Checker.Verify();

    // reconnect them all and check state
    reconnect(block3);
    reconnect(block4);
    reconnect(block5);
    checker.Verify();

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(wallet_lookup_indexes)
{
    auto params = Params::get_default();
    CSparkWallet* wallet = pwalletMain->sparkWallet.get();
    CWalletDB walletdb(pwalletMain->strWalletFile);

    // Build a meta for a coin generated from foreign keys: trial decryption
    // with the wallet's view key can never identify it, so any positive
    // answer below must come from the lookup indexes, not the EC fallback.
    const SpendKey spendKey(params);
    const FullViewKey fullViewKey(spendKey);
    const IncomingViewKey incomingViewKey(fullViewKey);
    const Address address(incomingViewKey, 1);

    CSparkMintMeta meta;
    meta.nHeight = 1;
    meta.nId = 1;
    meta.isUsed = false;
    meta.txid = uint256();
    meta.i = 1;
    meta.d = address.get_d();
    meta.v = 7 * COIN;
    meta.k.randomize();
    meta.memo = "lookup test";
    meta.serial_context = random_char_vector();
    meta.type = COIN_TYPE_MINT;
    meta.coin = Coin(params, meta.type, meta.k, address, meta.v, meta.memo, meta.serial_context);

    const uint256 lTagHash = uint256S("0x1");

    // Unknown coin: both the coin index and identification miss
    BOOST_CHECK(!wallet->isMine(meta.coin));
    BOOST_CHECK(wallet->getMintMeta(meta.k) == CSparkMintMeta());
    BOOST_CHECK(wallet->validateLookupIndexes());

    wallet->addOrUpdateMint(meta, lTagHash, walletdb);
    BOOST_CHECK(wallet->validateLookupIndexes());

    // Coin index hits
    BOOST_CHECK(wallet->isMine(meta.coin));
    BOOST_CHECK_EQUAL(wallet->getMyCoinV(meta.coin), CAmount(meta.v));
    CAmount amount(0);
    BOOST_CHECK(wallet->getMintAmount(meta.coin, amount));
    BOOST_CHECK_EQUAL(amount, CAmount(meta.v));
    CSparkMintMeta byCoin;
    BOOST_CHECK(wallet->getMintMeta(meta.coin, byCoin));
    BOOST_CHECK(byCoin == meta);

    // Nonce index hits
    BOOST_CHECK(wallet->getMintMeta(meta.k) == meta);
    BOOST_CHECK_EQUAL(wallet->getMintMeta(meta.k).v, meta.v);
    BOOST_CHECK(wallet->getMintMeta(meta.k).serial_context == meta.serial_context);
    Scalar otherNonce;
    otherNonce.randomize();
    BOOST_CHECK(wallet->getMintMeta(otherNonce) == CSparkMintMeta());

    // Same coin under a different serial context must not hit: coin equality
    // does not cover the serial context, but identification depends on it
    Coin altered = meta.coin;
    altered.setSerialContext(random_char_vector());
    BOOST_CHECK(!wallet->isMine(altered));

    // Indexes follow an in-memory update
    CSparkMintMeta updated = meta;
    updated.isUsed = true;
    wallet->updateMintInMemory(updated);
    BOOST_CHECK(wallet->getMintMeta(meta.k).isUsed);
    BOOST_CHECK(wallet->isMine(meta.coin));
    BOOST_CHECK(wallet->validateLookupIndexes());

    // Indexes drop the entry on erase
    wallet->eraseMint(lTagHash, walletdb);
    BOOST_CHECK(!wallet->isMine(meta.coin));
    BOOST_CHECK(wallet->getMintMeta(meta.k) == CSparkMintMeta());
    BOOST_CHECK(!wallet->getMintAmount(meta.coin, amount));
    BOOST_CHECK(wallet->validateLookupIndexes());

    // Re-add, then clearAllMints empties the indexes
    wallet->addOrUpdateMint(meta, lTagHash, walletdb);
    BOOST_CHECK(wallet->isMine(meta.coin));
    wallet->clearAllMints(walletdb);
    BOOST_CHECK(!wallet->isMine(meta.coin));
    BOOST_CHECK(wallet->getMintMeta(meta.k) == CSparkMintMeta());
    BOOST_CHECK(wallet->validateLookupIndexes());
}

BOOST_AUTO_TEST_CASE(wallet_cache_verification)
{
    auto params = Params::get_default();
    CSparkWallet* wallet = pwalletMain->sparkWallet.get();
    CWalletDB walletdb(pwalletMain->strWalletFile);

    // A record whose coin was built from the wallet's own keys, so
    // identification confirms it
    const uint64_t goodI = 5;
    const Address goodAddress = wallet->getAddress(int32_t(goodI));
    CSparkMintMeta good;
    good.nHeight = 1;
    good.nId = 1;
    good.isUsed = false;
    good.txid = uint256();
    good.i = goodI;
    good.d = goodAddress.get_d();
    good.v = 3 * COIN;
    good.k.randomize();
    good.memo = "good";
    good.serial_context = random_char_vector();
    good.type = COIN_TYPE_MINT;
    good.coin = Coin(params, good.type, good.k, goodAddress, good.v, good.memo, good.serial_context);
    const uint256 goodTag = uint256S("0x10");

    // A record whose coin was built from foreign keys, standing in for a
    // corrupt or tampered wallet record that identification rejects
    const SpendKey foreignSpend(params);
    const FullViewKey foreignFull(foreignSpend);
    const IncomingViewKey foreignView(foreignFull);
    const Address foreignAddress(foreignView, 1);
    CSparkMintMeta bad;
    bad.nHeight = 1;
    bad.nId = 1;
    bad.isUsed = false;
    bad.txid = uint256();
    bad.i = 1;
    bad.d = foreignAddress.get_d();
    bad.v = 9 * COIN;
    bad.k.randomize();
    bad.memo = "bad";
    bad.serial_context = random_char_vector();
    bad.type = COIN_TYPE_MINT;
    bad.coin = Coin(params, bad.type, bad.k, foreignAddress, bad.v, bad.memo, bad.serial_context);
    const uint256 badTag = uint256S("0x20");

    wallet->addOrUpdateMint(good, goodTag, walletdb);
    wallet->addOrUpdateMint(bad, badTag, walletdb);
    BOOST_CHECK(wallet->isMine(good.coin));
    BOOST_CHECK(wallet->isMine(bad.coin));
    BOOST_CHECK(wallet->validateLookupIndexes());

    // The sweep confirms the good record and evicts only the bad one
    BOOST_CHECK_EQUAL(wallet->verifyCachedCoins(), 1u);
    BOOST_CHECK(wallet->isMine(good.coin));
    BOOST_CHECK(wallet->getMintMeta(good.k) == good);
    BOOST_CHECK(!wallet->isMine(bad.coin));
    BOOST_CHECK(wallet->getMintMeta(bad.k) == CSparkMintMeta());

    // Only the fast path was evicted; the record itself remains
    BOOST_CHECK(wallet->getMintMeta(badTag) == bad);

    // A second sweep has nothing left to evict
    BOOST_CHECK_EQUAL(wallet->verifyCachedCoins(), 0u);

    wallet->clearAllMints(walletdb);
    BOOST_CHECK(wallet->validateLookupIndexes());
}

} // end of namespace spark

BOOST_AUTO_TEST_SUITE_END()
