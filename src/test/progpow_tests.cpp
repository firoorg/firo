#include "util.h"

#include "clientversion.h"
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
    BOOST_CHECK(!state.CorruptionPossible());

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(mapBlockIndex.count(block.GetHash()), 0);
}

BOOST_AUTO_TEST_CASE(header_mix_hash_mismatch)
{
    mutableParams.nPPSwitchTime = (uint32_t)(chainActive.Tip()->GetMedianTimePast()+10);
    SetMockTime(mutableParams.nPPSwitchTime+1);

    CBlock block = CreateBlock({}, m_coinbaseKey);
    BOOST_REQUIRE(block.IsProgPow());

    CBlockHeader forged = block.GetBlockHeader();
    forged.mix_hash.begin()[0] ^= 1;
    while (!CheckProofOfWork(forged.GetProgPowHashLight(), forged.nBits, mutableParams))
        ++forged.nNonce64;
    BOOST_REQUIRE(CheckProofOfWork(forged.GetProgPowHashLight(), forged.nBits, mutableParams));

    uint256 expectedMixHash;
    forged.GetProgPowHashFull(expectedMixHash);
    BOOST_REQUIRE(expectedMixHash != forged.mix_hash);

    CValidationState state;
    BOOST_CHECK(!ProcessNewBlockHeaders({forged}, state, Params()));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "invalid-mixhash");

    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(mapBlockIndex.count(forged.GetHash()), 0);
    }

    const CBlockIndex* validIndex = nullptr;
    CValidationState validState;
    BOOST_REQUIRE(ProcessNewBlockHeaders({block.GetBlockHeader()}, validState, Params(), &validIndex));
    {
        LOCK(cs_main);
        BOOST_REQUIRE(validIndex != nullptr);
        BOOST_CHECK(validIndex->fProgPowHeaderVerified);
    }
}

BOOST_AUTO_TEST_CASE(invalidate_header_only_descendants)
{
    mutableParams.nPPSwitchTime = INT_MAX;

    uint256 forkHash;
    uint32_t forkTime;
    {
        LOCK(cs_main);
        forkHash = chainActive.Tip()->GetBlockHash();
        forkTime = chainActive.Tip()->nTime;
    }

    CBlockHeader base = CreateBlock({}, m_coinbaseKey).GetBlockHeader();
    auto makeHeader = [&](const uint256& prevHash, uint32_t prevTime, unsigned char tag) {
        CBlockHeader header = base;
        header.hashPrevBlock = prevHash;
        header.hashMerkleRoot.SetNull();
        header.hashMerkleRoot.begin()[0] = tag;
        header.nTime = prevTime + 1;
        header.nNonce = 0;
        header.cachedPoWHash.SetNull();
        while (!CheckProofOfWork(header.GetHash(), header.nBits, mutableParams))
            ++header.nNonce;
        return header;
    };

    CBlockHeader badRoot = makeHeader(forkHash, forkTime, 1);
    CBlockHeader badChild = makeHeader(badRoot.GetHash(), badRoot.nTime, 2);
    CBlockHeader badTipHeader = makeHeader(badChild.GetHash(), badChild.nTime, 3);
    CBlockHeader badSibling = makeHeader(badRoot.GetHash(), badRoot.nTime, 5);
    CBlockHeader goodRoot = makeHeader(forkHash, forkTime, 11);
    CBlockHeader goodTipHeader = makeHeader(goodRoot.GetHash(), goodRoot.nTime, 12);
    CBlockHeader extension = makeHeader(badTipHeader.GetHash(), badTipHeader.nTime, 4);

    const CBlockIndex* badTip = nullptr;
    CValidationState badState;
    BOOST_REQUIRE(ProcessNewBlockHeaders({badRoot, badChild, badTipHeader}, badState, Params(), &badTip));
    CValidationState siblingState;
    BOOST_REQUIRE(ProcessNewBlockHeaders({badSibling}, siblingState, Params()));

    const CBlockIndex* goodTip = nullptr;
    CValidationState goodState;
    BOOST_REQUIRE(ProcessNewBlockHeaders({goodRoot, goodTipHeader}, goodState, Params(), &goodTip));

    CBlockIndex* badRootIndex;
    CBlockIndex* badTipIndex;
    {
        LOCK(cs_main);
        badRootIndex = mapBlockIndex.at(badRoot.GetHash());
        badTipIndex = mapBlockIndex.at(badTipHeader.GetHash());
        CValidationState state;
        BOOST_REQUIRE(InvalidateBlock(state, Params(), badRootIndex));
        BOOST_CHECK(badRootIndex->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(mapBlockIndex.at(badChild.GetHash())->nStatus & BLOCK_FAILED_CHILD);
        BOOST_CHECK(mapBlockIndex.at(badTipHeader.GetHash())->nStatus & BLOCK_FAILED_CHILD);
        BOOST_CHECK(mapBlockIndex.at(badSibling.GetHash())->nStatus & BLOCK_FAILED_CHILD);
        BOOST_CHECK(pindexBestHeader == goodTip);
    }

    CValidationState rejectState;
    BOOST_CHECK(!ProcessNewBlockHeaders({extension}, rejectState, Params()));
    BOOST_CHECK_EQUAL(rejectState.GetRejectReason(), "bad-prevblk");
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(mapBlockIndex.count(extension.GetHash()), 0);
    }

    {
        LOCK(cs_main);
        BOOST_REQUIRE(ResetBlockFailureFlags(badTipIndex));
        BOOST_CHECK_EQUAL(badRootIndex->nStatus & BLOCK_FAILED_MASK, 0);
        BOOST_CHECK_EQUAL(mapBlockIndex.at(badChild.GetHash())->nStatus & BLOCK_FAILED_MASK, 0);
        BOOST_CHECK_EQUAL(mapBlockIndex.at(badTipHeader.GetHash())->nStatus & BLOCK_FAILED_MASK, 0);
        BOOST_CHECK(mapBlockIndex.at(badSibling.GetHash())->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(pindexBestHeader == badTip);
    }

    const CBlockIndex* extensionIndex = nullptr;
    CValidationState retryState;
    BOOST_REQUIRE(ProcessNewBlockHeaders({extension}, retryState, Params(), &extensionIndex));
    BOOST_CHECK(extensionIndex != nullptr);
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
