#include "../chainparams.h"
#include "../batchproof_container.h"
#include "../pow.h"
#include "../script/standard.h"
#include "../validation.h"
#include "../validationinterface.h"
#include "../wallet/coincontrol.h"
#include "../wallet/walletexcept.h"
#include "../wallet/wallet.h"
#include "../net.h"

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
        CAmount transparentAmount)
    {
        BOOST_REQUIRE(selected.size() > 1U);

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
        tx.nType = TRANSACTION_SPARK;
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
            {change});
        spend.setBlockHashes(blockHashes);

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
    // Create duplicated serial tx and test this at the bottom
    auto dupTx1 = GenerateSparkSpend({1 * COIN}, {}, &coinControl);

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

BOOST_AUTO_TEST_CASE(spark_coin_type_policy_and_consensus_activation)
{
    struct ResetActivationHeight {
        ~ResetActivationHeight()
        {
            UpdateRegtestSparkCoinTypeFixHeight(INT_MAX);
        }
    } resetActivationHeight;

    const auto makeTransaction = [](opcodetype opcode, char coinType) {
        const auto* params = Params::get_default();
        const SpendKey spendKey(params);
        const FullViewKey fullViewKey(spendKey);
        const IncomingViewKey incomingViewKey(fullViewKey);
        const Address address(incomingViewKey, 12345);
        Scalar k;
        k.randomize();
        const uint64_t value = 1;
        const Coin coin(
            params,
            coinType,
            k,
            address,
            value,
            "coin-type-test",
            random_char_vector());
        CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
        serialized << coin;

        CScript outputScript;
        outputScript << opcode;
        outputScript.insert(
            outputScript.end(), serialized.begin(), serialized.end());

        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint(uint256S("0x1"), 0));
        tx.vout.emplace_back(0, outputScript);
        return tx;
    };

    const CMutableTransaction mismatchedMint =
        makeTransaction(OP_SPARKMINT, COIN_TYPE_SPEND);
    const CMutableTransaction mismatchedSMint =
        makeTransaction(OP_SPARKSMINT, COIN_TYPE_MINT);

    // Relay policy rejects both mismatches immediately, before Spark coin
    // deserialization, without assigning peer misbehavior points.
    CValidationState mintPolicyState;
    bool mintMissingInputs = true;
    {
        LOCK(cs_main);
        BOOST_CHECK(!AcceptToMemoryPool(
            mempool,
            mintPolicyState,
            MakeTransactionRef(mismatchedMint),
            false,
            &mintMissingInputs));
    }
    int mintPolicyDoS = -1;
    BOOST_REQUIRE(mintPolicyState.IsInvalid(mintPolicyDoS));
    BOOST_CHECK_EQUAL(mintPolicyDoS, 0);
    BOOST_CHECK_EQUAL(mintPolicyState.GetRejectCode(), REJECT_NONSTANDARD);
    BOOST_CHECK_EQUAL(mintPolicyState.GetRejectReason(), "bad-spark-coin-type");
    BOOST_CHECK(!mintMissingInputs);

    CValidationState smintPolicyState;
    bool smintMissingInputs = true;
    {
        LOCK(cs_main);
        BOOST_CHECK(!AcceptToMemoryPool(
            mempool,
            smintPolicyState,
            MakeTransactionRef(mismatchedSMint),
            false,
            &smintMissingInputs));
    }
    int smintPolicyDoS = -1;
    BOOST_REQUIRE(smintPolicyState.IsInvalid(smintPolicyDoS));
    BOOST_CHECK_EQUAL(smintPolicyDoS, 0);
    BOOST_CHECK_EQUAL(smintPolicyState.GetRejectCode(), REJECT_NONSTANDARD);
    BOOST_CHECK_EQUAL(smintPolicyState.GetRejectReason(), "bad-spark-coin-type");
    BOOST_CHECK(!smintMissingInputs);

    const int activationHeight = chainActive.Height() + 1;
    UpdateRegtestSparkCoinTypeFixHeight(activationHeight);

    // INT_MAX is reserved for non-consensus callers. Keep that contract
    // distinct from the height-gated block rule even when the tip is active.
    UpdateRegtestSparkCoinTypeFixHeight(chainActive.Height());
    CValidationState sentinelHeightState;
    BOOST_CHECK(CheckTransaction(
        CTransaction(mismatchedSMint),
        sentinelHeightState,
        true,
        mismatchedSMint.GetHash(),
        false,
        INT_MAX));
    UpdateRegtestSparkCoinTypeFixHeight(activationHeight);

    struct BlockCheckResult : public CValidationInterface {
        BlockCheckResult()
        {
            RegisterValidationInterface(this);
        }

        ~BlockCheckResult()
        {
            UnregisterValidationInterface(this);
        }

        int calls = 0;
        int dos = -1;
        std::string reason;

    protected:
        void BlockChecked(const CBlock&, const CValidationState& state) override
        {
            ++calls;
            state.IsInvalid(dos);
            reason = state.GetRejectReason();
        }
    };

    const auto mineRegtestBlock = [this](CBlock& block) {
        block.nNonce = 0;
        block.cachedPoWHash.SetNull();
        block.fChecked = false;
        while (!CheckProofOfWork(block.GetHash(), block.nBits, consensus)) {
            ++block.nNonce;
        }
    };

    CScript truncatedMintScript;
    truncatedMintScript << OP_SPARKMINT;
    truncatedMintScript.push_back(
        static_cast<unsigned char>(COIN_TYPE_SPEND));
    CMutableTransaction truncatedMint;
    truncatedMint.vin.emplace_back(COutPoint(uint256S("0x3"), 0));
    truncatedMint.vout.emplace_back(0, truncatedMintScript);

    // Reject an uncontextualized block header before its transactions can
    // enter legacy Spark parsing with a fabricated height of zero.
    CBlock unknownParentBlock = CreateBlock({truncatedMint}, script);
    unknownParentBlock.hashPrevBlock = uint256S(
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    mineRegtestBlock(unknownParentBlock);
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(
            mapBlockIndex.count(unknownParentBlock.hashPrevBlock), 0U);
    }
    {
        bool unknownParentNewBlock = false;
        BlockCheckResult unknownParentResult;
        BOOST_CHECK(!ProcessNewBlock(
            ::Params(),
            std::make_shared<const CBlock>(unknownParentBlock),
            false,
            &unknownParentNewBlock));
        BOOST_CHECK(!unknownParentNewBlock);
        BOOST_CHECK_EQUAL(unknownParentResult.calls, 1);
        BOOST_CHECK_EQUAL(unknownParentResult.dos, 10);
        BOOST_CHECK_EQUAL(unknownParentResult.reason, "bad-prevblk");
    }

    // Contextual header checks must also precede body validation when the
    // parent is known. The alternative target is valid in isolation but is
    // not the target required for this child.
    CBlock wrongDifficultyBlock = CreateBlock({truncatedMint}, script);
    wrongDifficultyBlock.nBits = 0x2070ffff;
    mineRegtestBlock(wrongDifficultyBlock);
    {
        bool wrongDifficultyNewBlock = false;
        BlockCheckResult wrongDifficultyResult;
        BOOST_CHECK(!ProcessNewBlock(
            ::Params(),
            std::make_shared<const CBlock>(wrongDifficultyBlock),
            false,
            &wrongDifficultyNewBlock));
        BOOST_CHECK(!wrongDifficultyNewBlock);
        BOOST_CHECK_EQUAL(wrongDifficultyResult.calls, 1);
        BOOST_CHECK_EQUAL(wrongDifficultyResult.dos, 100);
        BOOST_CHECK_EQUAL(wrongDifficultyResult.reason, "bad-diffbits");
    }

    // Once the header is contextualized at the activation height, the body
    // still receives the raw coin-type check and the index records the failure.
    CBlock activeMismatchBlock = CreateBlock({truncatedMint}, script);
    {
        bool activeMismatchNewBlock = false;
        BlockCheckResult activeMismatchResult;
        BOOST_CHECK(!ProcessNewBlock(
            ::Params(),
            std::make_shared<const CBlock>(activeMismatchBlock),
            false,
            &activeMismatchNewBlock));
        BOOST_CHECK(activeMismatchNewBlock);
        BOOST_CHECK_EQUAL(activeMismatchResult.calls, 1);
        BOOST_CHECK_EQUAL(activeMismatchResult.dos, 100);
        BOOST_CHECK_EQUAL(
            activeMismatchResult.reason, "bad-spark-coin-type");

        LOCK(cs_main);
        const auto activeMismatchIndex =
            mapBlockIndex.find(activeMismatchBlock.GetHash());
        BOOST_REQUIRE(activeMismatchIndex != mapBlockIndex.end());
        BOOST_CHECK(
            activeMismatchIndex->second->nStatus & BLOCK_FAILED_VALID);
    }

    // A context-valid historical fork with no more work is ignored before
    // its preactivation body is checked. This preserves historical consensus
    // behavior without exposing the legacy parser to unsolicited stale data.
    CBlock staleBlock = CreateBlock({truncatedMint}, script);
    {
        LOCK(cs_main);
        staleBlock.hashPrevBlock =
            chainActive[chainActive.Height() - 1]->GetBlockHash();
    }
    mineRegtestBlock(staleBlock);
    {
        bool staleNewBlock = true;
        BlockCheckResult staleResult;
        BOOST_CHECK(ProcessNewBlock(
            ::Params(),
            std::make_shared<const CBlock>(staleBlock),
            false,
            &staleNewBlock));
        BOOST_CHECK(!staleNewBlock);
        BOOST_CHECK_EQUAL(staleResult.calls, 0);

        LOCK(cs_main);
        const auto staleIndex = mapBlockIndex.find(staleBlock.GetHash());
        BOOST_REQUIRE(staleIndex != mapBlockIndex.end());
        BOOST_CHECK_EQUAL(
            staleIndex->second->nStatus & BLOCK_HAVE_DATA, 0U);
        BOOST_CHECK_EQUAL(
            staleIndex->second->nStatus & BLOCK_FAILED_MASK, 0U);
    }

    // A mismatched SMint output in an otherwise ordinary transaction is safe
    // to use for the preactivation boundary because legacy validation does not
    // deserialize it as a Spark transaction.
    CValidationState historicalState;
    BOOST_REQUIRE(CheckTransaction(
        CTransaction(mismatchedSMint),
        historicalState,
        true,
        mismatchedSMint.GetHash(),
        false,
        activationHeight - 1));

    CValidationState activeState;
    BOOST_CHECK(!CheckTransaction(
        CTransaction(mismatchedSMint),
        activeState,
        true,
        mismatchedSMint.GetHash(),
        false,
        activationHeight));
    int activeDoS = -1;
    BOOST_REQUIRE(activeState.IsInvalid(activeDoS));
    BOOST_CHECK_EQUAL(activeDoS, 100);
    BOOST_CHECK_EQUAL(activeState.GetRejectCode(), REJECT_INVALID);
    BOOST_CHECK_EQUAL(activeState.GetRejectReason(), "bad-spark-coin-type");

    CValidationState postActivationState;
    BOOST_CHECK(!CheckTransaction(
        CTransaction(mismatchedSMint),
        postActivationState,
        true,
        mismatchedSMint.GetHash(),
        false,
        activationHeight + 1));
    BOOST_CHECK_EQUAL(postActivationState.GetRejectReason(), "bad-spark-coin-type");

    // The mint mismatch is tested only after activation. Running it through
    // legacy validation would deliberately execute the bug this change gates.
    CValidationState mintActiveState;
    BOOST_CHECK(!CheckTransaction(
        CTransaction(mismatchedMint),
        mintActiveState,
        true,
        mismatchedMint.GetHash(),
        false,
        activationHeight));
    BOOST_CHECK_EQUAL(mintActiveState.GetRejectReason(), "bad-spark-coin-type");

    CValidationState verifyDbState;
    BOOST_CHECK(!CheckTransaction(
        CTransaction(mismatchedSMint),
        verifyDbState,
        true,
        mismatchedSMint.GetHash(),
        true,
        activationHeight));
    BOOST_CHECK_EQUAL(verifyDbState.GetRejectReason(), "bad-spark-coin-type");

    const CMutableTransaction consistentSMint =
        makeTransaction(OP_SPARKSMINT, COIN_TYPE_SPEND);
    CValidationState consistentState;
    BOOST_CHECK(CheckTransaction(
        CTransaction(consistentSMint),
        consistentState,
        true,
        consistentSMint.GetHash(),
        false,
        activationHeight));

    const auto* params = Params::get_default();
    const SpendKey spendKey(params);
    const FullViewKey fullViewKey(spendKey);
    const IncomingViewKey incomingViewKey(fullViewKey);
    MintedCoinData validCoin;
    validCoin.address = Address(incomingViewKey, 54321);
    validCoin.v = 1;
    validCoin.memo = "valid-coin-type";
    MintTransaction validMint(
        params, {validCoin}, random_char_vector());
    const std::vector<CDataStream> serializedMints =
        validMint.getMintedCoinsSerialized();
    BOOST_REQUIRE_EQUAL(serializedMints.size(), 1U);
    CScript validMintScript;
    validMintScript << OP_SPARKMINT;
    validMintScript.insert(
        validMintScript.end(),
        serializedMints.front().begin(),
        serializedMints.front().end());
    CMutableTransaction validMintTransaction;
    validMintTransaction.vin.emplace_back(
        COutPoint(uint256S("0x2"), 0));
    validMintTransaction.vout.emplace_back(1, validMintScript);

    CValidationState validMintState;
    BOOST_CHECK(CheckTransaction(
        CTransaction(validMintTransaction),
        validMintState,
        true,
        validMintTransaction.GetHash(),
        false,
        activationHeight));

    const CBlock validMintBlock =
        CreateBlock({validMintTransaction}, script);
    CValidationState validMintBlockState;
    BOOST_CHECK(CheckBlock(
        validMintBlock,
        validMintBlockState,
        consensus,
        false,
        true,
        activationHeight,
        false));

    const CBlock boundaryBlock = CreateBlock({mismatchedSMint}, script);
    CValidationState historicalBlockState;
    BOOST_REQUIRE(CheckBlock(
        boundaryBlock,
        historicalBlockState,
        consensus,
        false,
        true,
        activationHeight - 1,
        false));

    CValidationState activeBlockState;
    BOOST_CHECK(!CheckBlock(
        boundaryBlock,
        activeBlockState,
        consensus,
        false,
        true,
        activationHeight,
        false));
    int activeBlockDoS = -1;
    BOOST_REQUIRE(activeBlockState.IsInvalid(activeBlockDoS));
    BOOST_CHECK_EQUAL(activeBlockDoS, 100);
    BOOST_CHECK_EQUAL(activeBlockState.GetRejectReason(), "bad-spark-coin-type");

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
    struct ResetActivationHeight {
        ~ResetActivationHeight()
        {
            UpdateRegtestSparkSingleInputHeight(INT_MAX);
        }
    } resetActivationHeight;

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

    const auto hasSingleCoinMessage = [](const SparkFundsFragmented& error) {
        return std::string(error.what()).find(
            "No single available Spark coin can fund this transaction") !=
            std::string::npos;
    };
    BOOST_CHECK_EXCEPTION(
        GenerateSparkSpend({9 * COIN}, {}, nullptr),
        SparkFundsFragmented,
        hasSingleCoinMessage);

    const CTransaction singleInputSpend(
        GenerateSparkSpend({4 * COIN}, {}, nullptr));
    BOOST_CHECK_EQUAL(
        ParseSparkSpend(singleInputSpend).getUsedLTags().size(), 1U);

    mempool.clear();
    sparkState->Reset();
}

BOOST_AUTO_TEST_CASE(spark_single_input_historical_batch_verification)
{
    BatchProofContainer* batch = BatchProofContainer::get_instance();
    struct ResetBatchAndActivation {
        BatchProofContainer* batch;
        ~ResetBatchAndActivation()
        {
            batch->fCollectProofs = false;
            batch->init();
            UpdateRegtestSparkSingleInputHeight(INT_MAX);
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

BOOST_AUTO_TEST_CASE(spark_single_input_block_boundary_and_reorg)
{
    struct ResetActivationHeight {
        ~ResetActivationHeight()
        {
            UpdateRegtestSparkSingleInputHeight(INT_MAX);
        }
    } resetActivationHeight;

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

    // Remove the referenced cover-set block while leaving the first mint and
    // group active. Validation must recompute the result for the new context.
    const int disconnectCount =
        chainActive.Height() - secondMintIndex->nHeight + 1;
    BOOST_REQUIRE_GT(disconnectCount, 0);
    BOOST_REQUIRE(DisconnectBlocks(disconnectCount));
    BOOST_REQUIRE(chainActive.Height() >= firstMintIndex->nHeight);

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
