// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_bitcoin.h"

#include "chainparams.h"
#include "compat/endian.h"
#include "consensus/validation.h"
#include "evo/cbtx.h"
#include "evo/deterministicmns.h"
#include "evo/evodb.h"
#include "llmq/quorums_blockprocessor.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "validation.h"

#include <array>
#include <boost/test/unit_test.hpp>
#include <cstdint>
#include <limits>
#include <string>
#include <tuple>

namespace
{

struct EvoValidationTestingSetup : BasicTestingSetup {
    std::array<uint256, 101> blockHashes;
    std::array<CBlockIndex, 101> blockIndexes;
    llmq::CQuorumBlockProcessor processor;
    llmq::CQuorumBlockProcessor* previousProcessor;

    EvoValidationTestingSetup() : BasicTestingSetup(CBaseChainParams::REGTEST),
                                  processor(*evoDb),
                                  previousProcessor(llmq::quorumBlockProcessor)
    {
        for (size_t i = 0; i < blockIndexes.size(); ++i) {
            const uint32_t encodedHeight = static_cast<uint32_t>(i + 1);
            for (size_t byte = 0; byte < sizeof(encodedHeight); ++byte) {
                blockHashes[i].begin()[byte] = static_cast<unsigned char>(encodedHeight >> (byte * 8));
            }

            blockIndexes[i].nHeight = static_cast<int>(i);
            blockIndexes[i].pprev = i == 0 ? nullptr : &blockIndexes[i - 1];
            blockIndexes[i].phashBlock = &blockHashes[i];
            blockIndexes[i].BuildSkip();
        }

        llmq::quorumBlockProcessor = &processor;
    }

    ~EvoValidationTestingSetup()
    {
        llmq::quorumBlockProcessor = previousProcessor;
    }

    const CBlockIndex* Tip() const
    {
        return &blockIndexes.back();
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(evo_validation_tests)

static CTransactionRef MakeMalformedSpecialTx(int32_t type)
{
    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = type;
    return MakeTransactionRef(tx);
}

static CBlock MakeMalformedSpecialTxBlock(int32_t type)
{
    CBlock block;
    block.vtx.emplace_back(MakeTransactionRef(CMutableTransaction()));
    block.vtx.emplace_back(MakeMalformedSpecialTx(type));
    return block;
}

BOOST_FIXTURE_TEST_CASE(evo_helpers_reject_invalid_state_without_asserting, EvoValidationTestingSetup)
{
    const CBlockIndex* pindexPrev = Tip();

    const std::array<int32_t, 5> specialTxTypes{
        TRANSACTION_PROVIDER_REGISTER,
        TRANSACTION_PROVIDER_UPDATE_SERVICE,
        TRANSACTION_PROVIDER_UPDATE_REGISTRAR,
        TRANSACTION_PROVIDER_UPDATE_REVOKE,
        TRANSACTION_QUORUM_COMMITMENT,
    };

    for (const int32_t type : specialTxTypes) {
        CValidationState state;
        CDeterministicMNList list;
        const CBlock block = MakeMalformedSpecialTxBlock(type);
        bool result;
        {
            LOCK(deterministicMNManager->cs);
            result = deterministicMNManager->BuildNewListFromBlock(block, pindexPrev, state, list, false);
        }

        BOOST_CHECK(!result);
        BOOST_CHECK(state.IsInvalid());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), type == TRANSACTION_QUORUM_COMMITMENT ? "bad-qc-payload" : "bad-protx-payload");
    }

    {
        CValidationState state;
        uint256 merkleRoot;
        const CBlock block = MakeMalformedSpecialTxBlock(TRANSACTION_QUORUM_COMMITMENT);

        BOOST_CHECK(!CalcCbTxMerkleRootQuorums(block, pindexPrev, merkleRoot, state));
        BOOST_CHECK(state.IsInvalid());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-qc-payload");
    }

    const auto llmqType = Params().GetConsensus().llmqs.begin()->first;
    const uint32_t minedHeight = static_cast<uint32_t>(pindexPrev->nHeight);
    const auto inverseHeightKey = std::make_tuple(
        std::string("q_mcih"),
        static_cast<uint8_t>(llmqType),
        htobe32(std::numeric_limits<uint32_t>::max() - minedHeight));
    BOOST_REQUIRE(!evoDb->Exists(inverseHeightKey));

    auto dbTransaction = evoDb->BeginTransaction();
    evoDb->Write(inverseHeightKey, 0);

    CValidationState state;
    uint256 merkleRoot;
    CBlock block;
    BOOST_CHECK(!CalcCbTxMerkleRootQuorums(block, pindexPrev, merkleRoot, state));
    BOOST_CHECK(state.IsInvalid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "commitment-not-found");
    dbTransaction->Rollback();
}

BOOST_AUTO_TEST_SUITE_END()
