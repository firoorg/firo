#include "../chainparams.h"
#include "../script/standard.h"
#include "../validation.h"
#include "../wallet/coincontrol.h"
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
    GenerateBlocks(1100);

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

    GenerateBlocks(1100);
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
    GenerateBlocks(1100);

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
    GenerateBlocks(1100);

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
            BOOST_CHECK_MESSAGE(ids[i] == info.spentLTags[lTags[i]], "linking tag group id is invalid");
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

BOOST_AUTO_TEST_CASE(coingroup)
{
    GenerateBlocks(1100);

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

} // end of namespace spark

BOOST_AUTO_TEST_SUITE_END()