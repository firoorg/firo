#include "../lelantus.h"
#include "../validation.h"
#include "../wallet/wallet.h"

#include "test_bitcoin.h"
#include "fixtures.h"

#include <boost/test/unit_test.hpp>

namespace lelantus {

struct MintScript {
public:
    CScript script;
    PrivateCoin coin;

public:
    void GenerateScript() {
        script.push_back(OP_LELANTUSMINT);

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << coin.getPublicCoin();

        std::vector<unsigned char> serializedProof;
        GenerateMintSchnorrProof(coin, serializedProof);

        script.insert(script.end(), ss.begin(), ss.end());
        script.insert(script.end(), serializedProof.begin(), serializedProof.end());
    }
};

class LelantusTests : public LelantusTestingSetup {
public:
    LelantusTests() :
        LelantusTestingSetup(),
        lelantusState(CLelantusState::GetState()) {
    }

public:

    std::pair<MintScript, CTxOut> GenerateMintScript(CAmount value) const {
        MintScript script{CScript(), PrivateCoin(params, value)};
        script.GenerateScript();

        return {script, CTxOut(value, script.script)};
    }

public:
    CLelantusState *lelantusState;
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

BOOST_AUTO_TEST_CASE(is_available_to_mint)
{
    auto lowest = 5 * CENT;
    BOOST_CHECK(!IsAvailableToMint(0));
    BOOST_CHECK(!IsAvailableToMint(lowest - 1));
    BOOST_CHECK(IsAvailableToMint(lowest));
    BOOST_CHECK(IsAvailableToMint(lowest + 1));
}

BOOST_AUTO_TEST_CASE(parse_lelantus_mintscript)
{
    // payload: op_code + pubcoin + schnorrproof
    PrivateCoin priv(params, 1);
    auto &pub = priv.getPublicCoin();

    std::vector<unsigned char> proofSerialized;

    GenerateMintSchnorrProof(priv, proofSerialized);

    CScript script;
    script.push_back(OP_LELANTUSMINT);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << pub;

    script.insert(script.end(), ss.begin(), ss.end());
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

    PublicCoin coin(val);

    CScript script;
    script.push_back(OP_LELANTUSJMINT);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << coin;
    script.insert(script.end(), ss.begin(), ss.end());

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

// TODO(can not):
// - ParseLelantusJoinSplit
// - GetSpendAmount
// - CheckLelantusBlock

// TODO(can):
// - CheckLelantusTransaction
// - DisconnectTipLelantus
// - ConnectBlockLelantus

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
    block.lelantusTxInfo->mints.emplace_back(mint.GetPubcoinValue());

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

    CBlock block1, block2;

    GenerateBlock({txs[0], txs[1]});
    auto blockIdx1 = chainActive.Tip();

    GenerateBlock({txs[2], txs[3]});
    auto blockIdx2 = chainActive.Tip();

    BOOST_CHECK(ReadBlockFromDisk(block1, blockIdx1, ::Params().GetConsensus()));
    BOOST_CHECK(ReadBlockFromDisk(block2, blockIdx2, ::Params().GetConsensus()));

    block1.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();
    block2.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();

    block1.lelantusTxInfo->mints.emplace_back(mints[0].GetPubcoinValue());
    block1.lelantusTxInfo->mints.emplace_back(mints[1].GetPubcoinValue());
    block2.lelantusTxInfo->mints.emplace_back(mints[2].GetPubcoinValue());
    block2.lelantusTxInfo->mints.emplace_back(mints[3].GetPubcoinValue());

    lelantusState->AddMintsToStateAndBlockIndex(blockIdx1, &block1);
    lelantusState->AddMintsToStateAndBlockIndex(blockIdx2, &block2);

    BOOST_CHECK(BuildLelantusStateFromIndex(&chainActive));
    BOOST_CHECK(lelantusState->HasCoin(mints[0].GetPubcoinValue()));
    BOOST_CHECK(lelantusState->HasCoin(mints[1].GetPubcoinValue()));
    BOOST_CHECK(lelantusState->HasCoin(mints[2].GetPubcoinValue()));
    BOOST_CHECK(lelantusState->HasCoin(mints[3].GetPubcoinValue()));
}

BOOST_AUTO_TEST_SUITE_END()

};