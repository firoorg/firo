// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "evo/evodb.h"
#include "llmq/quorums_dkgsessionmgr.h"
#include "test/test_bitcoin.h"

#include <array>

#include <boost/test/unit_test.hpp>

namespace llmq
{

template<typename Message>
std::set<NodeId> BatchVerifyMessageSigs(CDKGSession& session,
    const std::vector<std::pair<NodeId, std::shared_ptr<Message>>>& messages);

struct DKGSessionHandlerTestingSetup : BasicTestingSetup
{
    CBLSWorker blsWorker;
    CDKGSessionManager dkgManager;

    DKGSessionHandlerTestingSetup() :
        BasicTestingSetup(CBaseChainParams::REGTEST),
        dkgManager(evoDb->GetRawDB(), blsWorker)
    {}
};

BOOST_FIXTURE_TEST_SUITE(llmq_dkgsessionhandler_tests, DKGSessionHandlerTestingSetup)

BOOST_AUTO_TEST_CASE(mixed_peers_fall_back_to_individual_verification)
{
    const auto& params = Params().GetConsensus().llmqs.at(Consensus::LLMQ_5_60);
    std::vector<CBLSSecretKey> keys(3);
    std::vector<CDeterministicMNCPtr> members;
    for (size_t i = 0; i < keys.size(); ++i) {
        keys[i].MakeNewKey();
        auto state = std::make_shared<CDeterministicMNState>();
        state->pubKeyOperator.Set(keys[i].GetPublicKey());
        auto member = std::make_shared<CDeterministicMN>();
        member->proTxHash = uint256S(strprintf("%064x", i + 1));
        member->pdmnState = state;
        members.emplace_back(member);
    }

    const uint256 quorumHash = uint256S("01");
    CBlockIndex quorumBlock;
    quorumBlock.phashBlock = &quorumHash;
    CDKGSession session(params, blsWorker, dkgManager);
    BOOST_REQUIRE(session.Init(&quorumBlock, members, uint256()));

    const std::array<NodeId, 3> nodeIds{101, 202, 101};
    std::vector<std::pair<NodeId, std::shared_ptr<CDKGComplaint>>> messages;
    for (size_t i = 0; i < members.size(); ++i) {
        auto message = std::make_shared<CDKGComplaint>(params);
        message->llmqType = params.type;
        message->quorumHash = quorumHash;
        message->proTxHash = members[i]->proTxHash;
        message->sig = keys[i].Sign(message->GetSignHash());
        messages.emplace_back(nodeIds[i], std::move(message));
    }

    CBLSSecretKey wrongKey;
    wrongKey.MakeNewKey();
    messages[1].second->sig = wrongKey.Sign(messages[1].second->GetSignHash());

    const auto badNodes = BatchVerifyMessageSigs(session, messages);
    BOOST_REQUIRE_EQUAL(badNodes.size(), 1U);
    BOOST_CHECK_EQUAL(*badNodes.begin(), 202);
}

BOOST_AUTO_TEST_SUITE_END()

}
