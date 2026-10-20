#include "util.h"

#include "clientversion.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "random.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h"
#include "validation.h"
#include "validationinterface.h"
#include "test/test_bitcoin.h"
#include "script/standard.h"
#include <consensus/merkle.h>

#include <boost/test/unit_test.hpp>
#include <boost/signals2/connection.hpp>

struct ProgpowTestingSetup : public TestChain100Setup
{
    CKey m_coinbaseKey;
    CScript coinbaseScript;
    Consensus::Params &mutableParams;
    Consensus::Params originalParams;

    class ProgpowValidationInterface : public CValidationInterface {
    public:
        std::string errorCode;

    protected:
        virtual void BlockChecked(const CBlock&, const CValidationState& state) override {
            errorCode = state.GetRejectReason();
        }
    };

    ProgpowTestingSetup() : TestChain100Setup(), mutableParams(const_cast<Consensus::Params&>(Params().GetConsensus()))
    {
        originalParams = mutableParams;
        mutableParams.nPPSwitchTime = INT_MAX;
        m_coinbaseKey.MakeNewKey(true);
        coinbaseScript = GetScriptForDestination(m_coinbaseKey.GetPubKey().GetID());
    }

    ~ProgpowTestingSetup() {
        mutableParams = originalParams;
        SetMockTime(0);
        ethash::ethash_clamp_memory_usage(INT_MAX, INT_MAX);
    }

    bool VerifyBlockCheckStatus(const CBlock &block, const std::string &correctError, bool shouldPassPowCheck=true) {
        ProgpowValidationInterface validationInterface;

        RegisterValidationInterface(&validationInterface);
        CBlock newBlock = block;
        // brute force correct nOnce64 value
        CValidationState state;
        const Consensus::Params &params = Params().GetConsensus();
        while (CheckBlockHeader(newBlock, state, params, true) != shouldPassPowCheck)
            newBlock.nNonce64++;
        ProcessNewBlock(Params(), std::make_shared<CBlock>(newBlock), false, nullptr);
        UnregisterValidationInterface(&validationInterface);

        return correctError == validationInterface.errorCode;
    }
};


BOOST_FIXTURE_TEST_SUITE(progpow_tests, ProgpowTestingSetup)

BOOST_AUTO_TEST_CASE(transition)
{
    mutableParams.nPPSwitchTime = INT_MAX;

    CBlock regularBlock = CreateAndProcessBlock({}, m_coinbaseKey);
    BOOST_ASSERT(!regularBlock.IsProgPow());

    mutableParams.nPPSwitchTime = (uint32_t)(chainActive.Tip()->GetMedianTimePast()+10);
    SetMockTime(mutableParams.nPPSwitchTime+1);

    int oldHeight = chainActive.Height();
    CBlock ppBlock = CreateAndProcessBlock({}, m_coinbaseKey);
    BOOST_ASSERT(chainActive.Height() == oldHeight+1);
    BOOST_ASSERT(ppBlock.IsProgPow());

    CBlockHeader header = regularBlock.GetBlockHeader();
    header.hashPrevBlock = ppBlock.GetHash();
    header.nTime = mutableParams.nPPSwitchTime - 1;
    header.nBits = GetNextWorkRequired(chainActive.Tip(), &header, mutableParams);
    while (!CheckProofOfWork(header.GetHash(), header.nBits, mutableParams))
        ++header.nNonce;

    CValidationState state;
    BOOST_CHECK(!ProcessNewBlockHeaders({header}, state, Params()));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-blk-progpow-state");
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(mapBlockIndex.count(header.GetHash()), 0);
    }
    const auto switchTime = mutableParams.nPPSwitchTime;
    mutableParams.nPPSwitchTime = INT_MAX; // Simulate a header indexed under the old rule.
    CValidationState indexedState;
    const bool indexed = ProcessNewBlockHeaders({header}, indexedState, Params());
    mutableParams.nPPSwitchTime = switchTime;
    BOOST_REQUIRE(indexed);
    CValidationState knownState;
    BOOST_CHECK(!ProcessNewBlockHeaders({header}, knownState, Params()));
    BOOST_CHECK_EQUAL(knownState.GetRejectReason(), "bad-blk-progpow-state");

    // Try to add regular block after PP one. Should throw an exception
    SetMockTime(mutableParams.nPPSwitchTime-1);
    try {
        CreateBlock({}, m_coinbaseKey);
        BOOST_ASSERT(false);
    }
    catch (std::runtime_error &err) {
        BOOST_ASSERT(std::string(err.what()).find("bad-blk-progpow-state") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(corruption)
{
    mutableParams.nPPSwitchTime = (uint32_t)(chainActive.Tip()->GetMedianTimePast()+10);
    SetMockTime(mutableParams.nPPSwitchTime+1);

    CBlock block = CreateBlock({}, m_coinbaseKey);
    BOOST_ASSERT(block.IsProgPow());

    CBlock modifiedBlock = block;

    // modifications made to the block should lead to rejection

    // try to modify transaction for block
    CMutableTransaction coinbaseTx = *block.vtx[0];
    CScript script;
    script << OP_TRUE;
    coinbaseTx.vout[0].scriptPubKey = script;
    modifiedBlock.vtx[0] = std::make_shared<CTransaction>(coinbaseTx);
    modifiedBlock.hashMerkleRoot = BlockMerkleRoot(modifiedBlock);
    BOOST_ASSERT(VerifyBlockCheckStatus(modifiedBlock, "invalid-mixhash"));

    // try to modify field in header
    modifiedBlock = block;
    modifiedBlock.nTime++;
    BOOST_ASSERT(VerifyBlockCheckStatus(modifiedBlock, "invalid-mixhash"));

    // try to modify nHeight
    modifiedBlock = block;
    modifiedBlock.nHeight++;
    BOOST_ASSERT(VerifyBlockCheckStatus(modifiedBlock, "bad-blk-progpow"));

    // try to modify nNonce64 so the block wouldn't pass PoW check
    modifiedBlock = block;
    BOOST_ASSERT(VerifyBlockCheckStatus(modifiedBlock, "high-hash", false));

    // try to modify mix_hash
    modifiedBlock = block;
    modifiedBlock.mix_hash = uint256S("e2c490c5bf0c3810cb8216997653d937b2822c1da37868b7e5f3c1a380c8a80a"); // SHA256("Firo")
    BOOST_ASSERT(VerifyBlockCheckStatus(modifiedBlock, "invalid-mixhash"));

    // verify that unmodified block passes all the checks
    BOOST_ASSERT(VerifyBlockCheckStatus(block, ""));
}

BOOST_AUTO_TEST_CASE(header_height_mismatch)
{
    mutableParams.nPPSwitchTime = (uint32_t)(chainActive.Tip()->GetMedianTimePast()+10);
    SetMockTime(mutableParams.nPPSwitchTime+1);

    CBlock block = CreateBlock({}, m_coinbaseKey);
    BOOST_REQUIRE(block.IsProgPow());
    block.nHeight = 0;

    while (!CheckProofOfWork(block.GetProgPowHashLight(), block.nBits, mutableParams))
        ++block.nNonce64;

    CValidationState state;
    std::vector<CBlockHeader> headers{block};
    BOOST_CHECK(!ProcessNewBlockHeaders(headers, state, Params()));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-blk-progpow");

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(mapBlockIndex.count(block.GetHash()), 0);
}

BOOST_AUTO_TEST_CASE(mtp_anchor)
{
    CBlockIndex* originalTip = chainActive.Tip();
    CBlock block = CreateBlock({}, m_coinbaseKey);
    mutableParams.nMTPAnchorHeight = originalTip->nHeight + 2;
    mutableParams.hashMTPAnchor = uint256S("01");

    BOOST_REQUIRE(ProcessNewBlock(Params(), std::make_shared<const CBlock>(block), true, nullptr));
    BOOST_CHECK(chainActive.Tip() == originalTip);

    CBlockHeader header = block.GetBlockHeader();
    header.hashPrevBlock = block.GetHash();
    ++header.nTime;
    {
        LOCK(cs_main);
        header.nBits = GetNextWorkRequired(mapBlockIndex.at(block.GetHash()), &header, mutableParams);
    }
    while (!CheckProofOfWork(header.GetHash(), header.nBits, mutableParams))
        ++header.nNonce;

    const bool oldCheckpoints = fCheckpointsEnabled;
    fCheckpointsEnabled = false;
    CValidationState state;
    const bool accepted = ProcessNewBlockHeaders({header}, state, Params());
    fCheckpointsEnabled = oldCheckpoints;
    BOOST_CHECK(!accepted);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-mtp-anchor");
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(mapBlockIndex.count(header.GetHash()), 0);
    }

    mutableParams.hashMTPAnchor = header.GetHash();
    CValidationState anchorState;
    BOOST_REQUIRE(ProcessNewBlockHeaders({header}, anchorState, Params()));
    {
        LOCK(cs_main);
        BOOST_CHECK(IsBlockIndexAnchored(mapBlockIndex.at(block.GetHash()), mutableParams));
        BOOST_CHECK(IsBlockIndexAnchored(mapBlockIndex.at(header.GetHash()), mutableParams));
    }
    CValidationState activateState;
    BOOST_REQUIRE(ActivateBestChain(activateState, Params()));
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());
}

BOOST_AUTO_TEST_CASE(limit)
{
    mutableParams.nPPSwitchTime = INT_MAX;

    // normal initialization is skipped, so we need to set the maximum epoch number manually
    ethash::ethash_clamp_memory_usage(mutableParams.nMaxPPEpoch, mutableParams.nTerminalPPEpoch);

    while (chainActive.Height() < 1300*(mutableParams.nMaxPPEpoch+1) - 2) {
        CreateAndProcessBlock({}, m_coinbaseKey);
    }

    mutableParams.nPPSwitchTime = (uint32_t)(chainActive.Tip()->GetMedianTimePast()+10);
    SetMockTime(mutableParams.nPPSwitchTime+1);

    int epoch1 = ethash::get_epoch_number(chainActive.Height());
    for (int i=0; i<5; i++) {
        CBlock ppBlock = CreateAndProcessBlock({}, m_coinbaseKey);
        BOOST_ASSERT(ppBlock.IsProgPow());
    }
    int epoch2 = ethash::get_epoch_number(chainActive.Height());

    BOOST_CHECK_EQUAL(epoch1, mutableParams.nMaxPPEpoch);
    BOOST_CHECK_EQUAL(epoch2, mutableParams.nTerminalPPEpoch);
}

BOOST_AUTO_TEST_SUITE_END()
