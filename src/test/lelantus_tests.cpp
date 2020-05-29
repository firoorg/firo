#include "../chainparams.h"
#include "../lelantus.h"
#include "../validation.h"
#include "../wallet/wallet.h"

#include "test_bitcoin.h"
#include "fixtures.h"

#include <boost/test/unit_test.hpp>

namespace lelantus {

struct MintScriptGenerator {
    PrivateCoin coin;

    CScript Get() {
        CScript script;

        script.push_back(OP_LELANTUSMINT);

        std::vector<unsigned char> serializedProof;
        GenerateMintSchnorrProof(coin, serializedProof);

        auto vch = coin.getPublicCoin().getValue().getvch();
        script.insert(script.end(), vch.begin(), vch.end());
        script.insert(script.end(), serializedProof.begin(), serializedProof.end());

        return script;
    }
};

struct JoinSplitScriptGenerator {
    Params const *params;
    std::vector<std::pair<PrivateCoin, uint32_t>> coins;
    std::map<uint32_t, std::vector<PublicCoin>> anons;
    CAmount vout;
    std::vector<PrivateCoin> coinsOut;
    CAmount fee;
    std::vector<uint256> groupBlockHashes;
    uint256 txHash;

    std::pair<CScript, JoinSplit> Get() {
        // auto p = params ? params : Params::get_default();
        auto p = Params::get_default();

        CScript script;

        JoinSplit joinSplit(p, coins, anons, vout, coinsOut, fee, groupBlockHashes, txHash);
        joinSplit.setVersion(LELANTUS_TX_VERSION_4);

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << joinSplit;

        script << OP_LELANTUSJOINSPLIT;
        script.insert(script.end(), ss.begin(), ss.end());

        return {script, joinSplit};
    }
};

class LelantusTests : public LelantusTestingSetup {
public:
    LelantusTests() :
        LelantusTestingSetup(),
        lelantusState(CLelantusState::GetState()),
        consensus(::Params().GetConsensus()) {
    }

    ~LelantusTests() {
        lelantusState->Reset();
    }

public:

    std::vector<PublicCoin> ExtractCoins(std::vector<PrivateCoin> const &coins) {
        std::vector<PublicCoin> pubs;
        pubs.reserve(coins.size());

        for (auto &c : coins) {
            pubs.push_back(c.getPublicCoin());
        }

        return pubs;
    }

    std::pair<MintScriptGenerator, CTxOut> GenerateMintScript(CAmount value) const {
        MintScriptGenerator script{PrivateCoin(params, value)};

        return {script, CTxOut(value, script.Get())};
    }

    CBlock GetCBlock(CBlockIndex const *blockIdx) {
        CBlock block;
        if (!ReadBlockFromDisk(block, blockIdx, ::Params().GetConsensus())) {
            throw std::invalid_argument("No block index data");
        }

        return block;
    }

    void PopulateLelantusTxInfo(
        CBlock &block,
        std::vector<std::pair<secp_primitives::GroupElement, int64_t>> const &mints,
        std::vector<std::pair<Scalar, int>> const &serials) {
        block.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();
        block.lelantusTxInfo->mints.insert(block.lelantusTxInfo->mints.end(), mints.begin(), mints.end());

        for (auto const &s : serials) {
            block.lelantusTxInfo->spentSerials.emplace(s);
        }

        block.lelantusTxInfo->Complete();
    }

public:
    CLelantusState *lelantusState;
    Consensus::Params const &consensus;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_tests, LelantusTests)

BOOST_AUTO_TEST_CASE(schnorr_proof)
{
    auto params = Params::get_default();

    PrivateCoin coin(params, 1);

    std::vector<unsigned char> serializedSchnorrProof;
    GenerateMintSchnorrProof(coin, serializedSchnorrProof);

    auto commitment = coin.getPublicCoin();
    SchnorrProof<Scalar, GroupElement> proof;
    proof.deserialize(serializedSchnorrProof.data());

    BOOST_CHECK(VerifyMintSchnorrProof(1, commitment.getValue(), proof));
}

BOOST_AUTO_TEST_CASE(is_lelantus_allowed)
{
    auto start = ::Params().GetConsensus().nLelantusStartBlock;
    BOOST_CHECK(!IsLelantusAllowed(0));
    BOOST_CHECK(!IsLelantusAllowed(start - 1));
    BOOST_CHECK(IsLelantusAllowed(start));
    BOOST_CHECK(IsLelantusAllowed(start + 1));
}

BOOST_AUTO_TEST_CASE(parse_lelantus_mintscript)
{
    // payload: op_code + pubcoin + schnorrproof
    PrivateCoin priv(params, 1);
    auto &pub = priv.getPublicCoin();

    std::vector<unsigned char> proofSerialized;

    GenerateMintSchnorrProof(priv, proofSerialized);

    CScript script(OP_LELANTUSMINT);

    auto vch = pub.getValue().getvch();
    script.insert(script.end(), vch.begin(), vch.end());
    script.insert(script.end(), proofSerialized.begin(), proofSerialized.end());

    // verify
    secp_primitives::GroupElement parsedCoin;
    ParseLelantusMintScript(script, parsedCoin);

    BOOST_CHECK(pub.getValue() == parsedCoin);

    SchnorrProof<Scalar, GroupElement> proof;
    ParseLelantusMintScript(script, parsedCoin, proof);

    BOOST_CHECK(pub.getValue() == parsedCoin);
    BOOST_CHECK(VerifyMintSchnorrProof(1, parsedCoin, proof));

    std::vector<unsigned char> parsedProof;
    parsedProof.resize(proof.memoryRequired());
    proof.serialize(parsedProof.data());

    BOOST_CHECK(proofSerialized == parsedProof);

    GroupElement parsedCoin2;
    ParseLelantusMintScript(script, parsedCoin2);

    BOOST_CHECK(pub.getValue() == parsedCoin2);

    script.resize(script.size() - 1);
    BOOST_CHECK_THROW(ParseLelantusMintScript(script, parsedCoin, proof), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(parse_lelantus_jmint)
{
    GroupElement val;
    val.randomize();

    CScript script(OP_LELANTUSJMINT);

    auto vch = val.getvch();
    script.insert(script.end(), vch.begin(), vch.end());

    std::vector<unsigned char> encrypted;
    encrypted.resize(16);

    std::fill(encrypted.begin(), encrypted.end(), 0xff);
    script.insert(script.end(), encrypted.begin(), encrypted.end());

    // parse and verify
    GroupElement outCoin;
    std::vector<unsigned char> outEnc;
    ParseLelantusJMintScript(script, outCoin, outEnc);

    BOOST_CHECK(val == outCoin);
    BOOST_CHECK(encrypted == outEnc);

    GroupElement outCoin2;
    ParseLelantusMintScript(script, outCoin2);

    BOOST_CHECK(val == outCoin2);

    // parse invalid
    script.resize(script.size() - 1);
    BOOST_CHECK_THROW(ParseLelantusJMintScript(script, outCoin, outEnc), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(get_outpoint)
{
    GenerateBlocks(110);

    // generate mints
    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints({2, 10}, txs);
    auto mint = mints[0];
    auto nonCommitted = mints[1];
    auto tx = txs[0];
    size_t mintIdx = 0;
    for (; mintIdx < tx.vout.size(); mintIdx++) {
        if (tx.vout[mintIdx].scriptPubKey.IsLelantusMint()) {
            break;
        }
    }

    GenerateBlock({txs[0]});

    auto blockIdx = chainActive.Tip();
    CBlock block;
    BOOST_CHECK(ReadBlockFromDisk(block, blockIdx, ::Params().GetConsensus()));

    block.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();
    block.lelantusTxInfo->mints.emplace_back(mint.GetPubcoinValue(), mint.GetAmount());

    lelantusState->AddMintsToStateAndBlockIndex(blockIdx, &block);
    lelantusState->AddBlock(blockIdx);

    // verify
    COutPoint expectedOut(tx.GetHash(), mintIdx);

    // GetOutPointFromBlock
    COutPoint out;
    BOOST_CHECK(GetOutPointFromBlock(out, mint.GetPubcoinValue(), block));
    BOOST_CHECK(expectedOut == out);

    BOOST_CHECK(!GetOutPointFromBlock(out, nonCommitted.GetPubcoinValue(), block));

    // GetOutPoint
    // by pubcoin
    out = COutPoint();
    BOOST_CHECK(GetOutPoint(out, PublicCoin(mint.GetPubcoinValue())));
    BOOST_CHECK(expectedOut == out);

    BOOST_CHECK(!GetOutPoint(out, PublicCoin(nonCommitted.GetPubcoinValue())));

    // by pubcoin value
    out = COutPoint();
    BOOST_CHECK(GetOutPoint(out, mint.GetPubcoinValue()));
    BOOST_CHECK(expectedOut == out);

    BOOST_CHECK(!GetOutPoint(out, nonCommitted.GetPubcoinValue()));

    // by pubcoin hash
    out = COutPoint();
    BOOST_CHECK(GetOutPoint(out, mint.GetPubCoinHash()));
    BOOST_CHECK(expectedOut == out);

    BOOST_CHECK(!GetOutPoint(out, nonCommitted.GetPubCoinHash()));
}

BOOST_AUTO_TEST_CASE(build_lelantus_state)
{
    GenerateBlocks(110);

    // generate mints
    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints({1 * COIN, 2 * COIN, 10 * COIN, 100 * COIN}, txs);

    GenerateBlock({txs[0], txs[1]});
    auto blockIdx1 = chainActive.Tip();
    auto block1 = GetCBlock(blockIdx1);

    GenerateBlock({txs[2], txs[3]});
    auto blockIdx2 = chainActive.Tip();
    auto block2 = GetCBlock(blockIdx2);

    block1.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();
    block2.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();

    block1.lelantusTxInfo->mints.emplace_back(mints[0].GetPubcoinValue(), mints[0].GetAmount());
    block1.lelantusTxInfo->mints.emplace_back(mints[1].GetPubcoinValue(), mints[1].GetAmount());
    block2.lelantusTxInfo->mints.emplace_back(mints[2].GetPubcoinValue(), mints[2].GetAmount());
    block2.lelantusTxInfo->mints.emplace_back(mints[3].GetPubcoinValue(), mints[3].GetAmount());

    lelantusState->AddMintsToStateAndBlockIndex(blockIdx1, &block1);
    lelantusState->AddMintsToStateAndBlockIndex(blockIdx2, &block2);

    BOOST_CHECK(BuildLelantusStateFromIndex(&chainActive));
    BOOST_CHECK(lelantusState->HasCoin(mints[0].GetPubcoinValue()));
    BOOST_CHECK(lelantusState->HasCoin(mints[1].GetPubcoinValue()));
    BOOST_CHECK(lelantusState->HasCoin(mints[2].GetPubcoinValue()));
    BOOST_CHECK(lelantusState->HasCoin(mints[3].GetPubcoinValue()));
}

BOOST_AUTO_TEST_CASE(connect_and_disconnect_block)
{
    auto params = Params::get_default();

    std::vector<CMutableTransaction> txs;
    std::vector<PrivateCoin> mints = {
        PrivateCoin(params, 1), PrivateCoin(params, 1), PrivateCoin(params, 1)
    };
    Scalar serial1, serial2, serial3;
    serial1.randomize();
    serial2.randomize();
    serial3.randomize();

    // verify functions
    auto verifyMintsAndSerials = [&] (bool m1In, bool m2In, bool m3In, bool s1In, bool s2In, bool s3In) {
        BOOST_CHECK_EQUAL(m1In, lelantusState->HasCoin(mints[0].getPublicCoin()));
        BOOST_CHECK_EQUAL(s1In, lelantusState->IsUsedCoinSerial(serial1));

        BOOST_CHECK_EQUAL(m2In, lelantusState->HasCoin(mints[1].getPublicCoin()));
        BOOST_CHECK_EQUAL(s2In, lelantusState->IsUsedCoinSerial(serial2));

        BOOST_CHECK_EQUAL(m3In, lelantusState->HasCoin(mints[2].getPublicCoin()));
        BOOST_CHECK_EQUAL(s3In, lelantusState->IsUsedCoinSerial(serial3));
    };

    auto verifyLastGroup = [&] (int id, CBlockIndex *first, CBlockIndex *last, size_t count) {
        auto retrievedId = lelantusState->GetLatestCoinID();

        CLelantusState::LelantusCoinGroupInfo group;
        lelantusState->GetCoinGroupInfo(retrievedId, group);

        BOOST_CHECK_EQUAL(id, retrievedId);
        BOOST_CHECK_EQUAL(first, group.firstBlock);
        BOOST_CHECK_EQUAL(last, group.lastBlock);
        BOOST_CHECK_EQUAL(count, group.nCoins);
    };

    auto blockIdx1 = GenerateBlock({});
    auto block1 = GetCBlock(blockIdx1);
    PopulateLelantusTxInfo(block1, {
        {mints[0].getPublicCoin().getValue(), mints[0].getV()},
        {mints[1].getPublicCoin().getValue(), mints[1].getV()}
    }, {});

    // add and verify state
    CValidationState state;
    BOOST_CHECK(ConnectBlockLelantus(state, ::Params(), blockIdx1, &block1, false));

    verifyMintsAndSerials(1, 1, 0, 0, 0, 0);
    verifyLastGroup(1, blockIdx1, blockIdx1, 2);

    // Generate block between 1 and 2
    auto noMintBlockIdx = GenerateBlock({});
    auto noMintBlock = GetCBlock(noMintBlockIdx);
    PopulateLelantusTxInfo(noMintBlock, {}, {});

    BOOST_CHECK(ConnectBlockLelantus(state, ::Params(), noMintBlockIdx, &noMintBlock, false));

    verifyMintsAndSerials(1, 1, 0, 0, 0, 0);
    verifyLastGroup(1, blockIdx1, blockIdx1, 2);

    // add block 2 with a serial
    auto blockIdx2 = GenerateBlock({});
    auto block2 = GetCBlock(blockIdx2);
    PopulateLelantusTxInfo(block2, {}, {{serial1, 1}});

    BOOST_CHECK(ConnectBlockLelantus(state, ::Params(), blockIdx2, &block2, false));

    verifyMintsAndSerials(1, 1, 0, 1, 0, 0);
    verifyLastGroup(1, blockIdx1, blockIdx1, 2);

    // add block 3 which contains both mint and serial
    auto blockIdx3 = GenerateBlock({});
    auto block3 = GetCBlock(blockIdx3);
    PopulateLelantusTxInfo(block3, {{mints[2].getPublicCoin().getValue(), mints[2].getV()}}, {{serial2, 1}});

    BOOST_CHECK(ConnectBlockLelantus(state, ::Params(), blockIdx3, &block3, false));

    verifyMintsAndSerials(1, 1, 1, 1, 1, 0);
    verifyLastGroup(1, blockIdx1, blockIdx3, 3);

    // remove block 3
    DisconnectTipLelantus(block3, blockIdx3);

    verifyMintsAndSerials(1, 1, 0, 1, 0, 0);
    verifyLastGroup(1, blockIdx1, blockIdx1, 2);

    // reconnect
    BOOST_CHECK(ConnectBlockLelantus(state, ::Params(), blockIdx3, &block3, false));

    verifyMintsAndSerials(1, 1, 1, 1, 1, 0);
    verifyLastGroup(1, blockIdx1, blockIdx3, 3);

    // add more block without any mint or serial
    noMintBlockIdx = GenerateBlock({});
    noMintBlock = GetCBlock(noMintBlockIdx);
    PopulateLelantusTxInfo(noMintBlock, {}, {});

    BOOST_CHECK(ConnectBlockLelantus(state, ::Params(), noMintBlockIdx, &noMintBlock, false));

    verifyMintsAndSerials(1, 1, 1, 1, 1, 0);
    verifyLastGroup(1, blockIdx1, blockIdx3, 3);

    // add a serial
    auto blockIdx4 = GenerateBlock({});
    auto block4 = GetCBlock(blockIdx4);
    PopulateLelantusTxInfo(block4, {}, {{serial3, 1}});

    BOOST_CHECK(ConnectBlockLelantus(state, ::Params(), blockIdx4, &block4, false));

    verifyMintsAndSerials(1, 1, 1, 1, 1, 1);
    verifyLastGroup(1, blockIdx1, blockIdx3, 3);

    // add a block with duplicated a serial should fail
    auto invalidBlockIdx3 = GenerateBlock({});
    auto invalidBlock3 = GetCBlock(invalidBlockIdx3);
    PopulateLelantusTxInfo(invalidBlock3, {}, {{serial3, 1}});
    BOOST_CHECK(!ConnectBlockLelantus(state, ::Params(), invalidBlockIdx3, &invalidBlock3, false));

    verifyMintsAndSerials(1, 1, 1, 1, 1, 1);
    verifyLastGroup(1, blockIdx1, blockIdx3, 3);

    // purge state to recreate
    DisconnectTipLelantus(block4, blockIdx4);

    verifyMintsAndSerials(1, 1, 1, 1, 1, 0);
    verifyLastGroup(1, blockIdx1, blockIdx3, 3);

    DisconnectTipLelantus(block3, blockIdx3);

    verifyMintsAndSerials(1, 1, 0, 1, 0, 0);
    verifyLastGroup(1, blockIdx1, blockIdx1, 2);

    DisconnectTipLelantus(noMintBlock, noMintBlockIdx);

    verifyMintsAndSerials(1, 1, 0, 1, 0, 0);
    verifyLastGroup(1, blockIdx1, blockIdx1, 2);

    DisconnectTipLelantus(block2, blockIdx2);

    verifyMintsAndSerials(1, 1, 0, 0, 0, 0);
    verifyLastGroup(1, blockIdx1, blockIdx1, 2);

    DisconnectTipLelantus(block1, blockIdx1);

    verifyMintsAndSerials(0, 0, 0, 0, 0, 0);

    // verify no group
    CLelantusState::LelantusCoinGroupInfo group;
    BOOST_CHECK(!lelantusState->GetCoinGroupInfo(1, group));

    // regenerate state using BuildLelantusStateFromIndex
    BOOST_CHECK(BuildLelantusStateFromIndex(&chainActive));

    verifyMintsAndSerials(1, 1, 1, 1, 1, 1);
    verifyLastGroup(1, blockIdx1, blockIdx3, 3);
}

BOOST_AUTO_TEST_CASE(checktransaction)
{
    GenerateBlocks(1000);

    // mints
    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints({1 * CENT}, txs);
    auto &tx = txs[0];

    CValidationState state;
    CLelantusTxInfo info;
    BOOST_CHECK(CheckLelantusTransaction(
        txs[0], state, tx.GetHash(), true, chainActive.Height(), true, true, &info));

    std::vector<std::pair<PublicCoin, uint64_t>> expectedCoins = {{mints[0].GetPubcoinValue(), 1 * CENT}};
    BOOST_CHECK(expectedCoins == info.mints);

    // join split
    txs.clear();
    mints = GenerateMints({10 * CENT, 11 * CENT, 100 * CENT}, txs, true);
    GenerateBlock(txs);
    GenerateBlocks(10);

    auto outputAmount = 8 * CENT;
    auto mintAmount = 2 * CENT - CENT; // a cent as fee

    CWalletTx wtx;
    pwalletMain->JoinSplitLelantus(
        {{script, outputAmount, false}},
        {mintAmount},
        wtx);

    CMutableTransaction joinsplitTx(wtx);
    auto joinsplit = ParseLelantusJoinSplit(joinsplitTx.vin[0]);

    // test get join split amounts
    BOOST_CHECK_EQUAL(1, GetSpendInputs(joinsplitTx));
    BOOST_CHECK_EQUAL(1, GetSpendInputs(joinsplitTx, joinsplitTx.vin[0]));

    info = CLelantusTxInfo();
    BOOST_CHECK(CheckLelantusTransaction(
        joinsplitTx, state, joinsplitTx.GetHash(), false, chainActive.Height(), false, true, &info));

    auto &serials = joinsplit->getCoinSerialNumbers();
    auto &ids = joinsplit->getCoinGroupIds();

    for (size_t i = 0; i != serials.size(); i++) {
        bool hasSerial = false;
        BOOST_CHECK_MESSAGE(hasSerial = (info.spentSerials.count(serials[i]) > 0), "No serial as expected");
        if (hasSerial) {
            BOOST_CHECK_MESSAGE(ids[i] == info.spentSerials[serials[i]], "Serials group id is invalid");
        }
    }

    info = CLelantusTxInfo();
    BOOST_CHECK(CheckLelantusTransaction(
        joinsplitTx, state, joinsplitTx.GetHash(), false, INT_MAX, false, true, &info));

    // test surge dection.
    while (!lelantusState->IsSurgeConditionDetected()) {
        Scalar s;
        s.randomize();

        lelantusState->AddSpend(s, 1);
    }

    BOOST_CHECK(!CheckLelantusTransaction(
        joinsplitTx, state, joinsplitTx.GetHash(), false, INT_MAX, false, true, &info));
}

BOOST_AUTO_TEST_CASE(spend_limitation_per_tx)
{
    PrivateCoin coinOut(params, 0);
    JoinSplitScriptGenerator invalidG, validG;
    invalidG.fee = 0;
    invalidG.vout = 0;
    invalidG.coinsOut = {coinOut};
    invalidG.groupBlockHashes = {ArithToUint256(0)};
    invalidG.txHash = ArithToUint256(0);

    validG.fee = 0;
    validG.vout = 0;
    validG.coinsOut = {coinOut};
    validG.groupBlockHashes = {ArithToUint256(0)};
    validG.txHash = ArithToUint256(0);

    for (size_t i = 0; i != consensus.nMaxLelantusInputPerTransaction + 1; i++) {
        PrivateCoin coin(params, 0);
        invalidG.coins.emplace_back(coin, 1);
        invalidG.anons[1].push_back(coin.getPublicCoin());

        if (i != 0) { // skip first
            validG.coins.emplace_back(coin, 1);
            validG.anons[1].push_back(coin.getPublicCoin());
        }
    }

    CMutableTransaction invalidTx, validTx;
    invalidTx.vin.resize(1);
    invalidTx.vin[0].scriptSig = invalidG.Get().first;

    validTx.vin.resize(1);
    validTx.vin[0].scriptSig = validG.Get().first;

    CBlock invalidBlock, validBlock;
    invalidBlock.vtx.push_back(MakeTransactionRef(invalidTx));
    validBlock.vtx.push_back(MakeTransactionRef(validTx));

    CValidationState state;
    BOOST_CHECK(!CheckLelantusBlock(state, invalidBlock));
    BOOST_CHECK(CheckLelantusBlock(state, validBlock));
}

BOOST_AUTO_TEST_CASE(spend_limitation_per_block)
{
    CBlock block;
    size_t spends = 0;

    for (size_t i = 0; spends <= consensus.nMaxLelantusInputPerBlock; i++) {
        PrivateCoin coinOut(params, 0);
        JoinSplitScriptGenerator g;
        g.fee = 0;
        g.vout = 0;
        g.coinsOut = {coinOut};
        for (size_t i = 0; i != consensus.nMaxLelantusInputPerTransaction; i++) {
            PrivateCoin coin(params, 0);
            g.coins.emplace_back(coin, 1);
            g.anons[1].push_back(coin.getPublicCoin());

            spends++;
        }

        g.groupBlockHashes = {ArithToUint256(i)};
        g.txHash = ArithToUint256(i);

        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].scriptSig = g.Get().first;


        block.vtx.push_back(MakeTransactionRef(tx));
    }

    CValidationState state;
    BOOST_CHECK(!CheckLelantusBlock(state, block));

    block.vtx.pop_back();
    BOOST_CHECK(CheckLelantusBlock(state, block));
}

BOOST_AUTO_TEST_CASE(parse_joinsplit)
{
    std::vector<CMutableTransaction> txs;
    std::vector<PrivateCoin> coins;
    GenerateMints({1 * COIN, 10 * COIN, 1 * COIN, 1 * COIN}, txs, coins, true, false);

    JoinSplitScriptGenerator g;
    g.params = params;
    g.coins = {{coins[0], 1}, {coins[1], 1}, {coins[2], 2}};
    for (auto id : {1, 2}) {
        for (size_t i = 0; i != 10; i++) {
            GroupElement e;
            e.randomize();

            g.anons[id].emplace_back(e);
        }
    }

    g.anons[1][0] = coins[0].getPublicCoin();
    g.anons[1][1] = coins[1].getPublicCoin();
    g.anons[2][0] = coins[2].getPublicCoin();

    g.vout = 11 * COIN - CENT;
    g.coinsOut.push_back(coins[3]);
    g.fee = CENT;
    g.groupBlockHashes = {ArithToUint256(1), ArithToUint256(2)};
    g.txHash = ArithToUint256(3);

    auto gs = g.Get();
    CTxIn inp(COutPoint(), gs.first);

    auto result = ParseLelantusJoinSplit(inp);

    BOOST_CHECK(gs.second.getCoinSerialNumbers() == result->getCoinSerialNumbers());
    BOOST_CHECK(gs.second.getFee() == result->getFee());
    BOOST_CHECK(gs.second.getCoinGroupIds() == result->getCoinGroupIds());
    BOOST_CHECK(gs.second.getIdAndBlockHashes() == result->getIdAndBlockHashes());
    BOOST_CHECK(gs.second.getVersion() == result->getVersion());
    BOOST_CHECK(gs.second.HasValidSerials() == result->HasValidSerials());

    BOOST_CHECK(gs.second.Verify(g.anons, ExtractCoins(g.coinsOut), g.vout, g.txHash));
    BOOST_CHECK(result->Verify(g.anons, ExtractCoins(g.coinsOut), g.vout, g.txHash));
}

BOOST_AUTO_TEST_SUITE_END()

};