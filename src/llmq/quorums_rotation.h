// Distributed under the MIT software license, see the accompanying file COPYING.

#ifndef FIRO_LLMQ_QUORUMS_ROTATION_H
#define FIRO_LLMQ_QUORUMS_ROTATION_H

#include "consensus/params.h"
#include "evo/deterministicmns.h"
#include "serialize.h"

namespace llmq
{

constexpr int ROTATION_WORK_DEPTH = 8;
constexpr int ROTATION_QUARTER_COUNT = 4;

struct CQuorumRotationSnapshot
{
    enum SkipMode : int32_t { NO_SKIPPING = 0, KEEP_ENTRIES = 2, ALL_SKIPPED = 3 };

    int32_t skipMode{ALL_SKIPPED};
    std::vector<bool> activeMembers;
    std::vector<uint32_t> skipList;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(skipMode);
        READWRITE(DYNBITSET(activeMembers));
        READWRITE(skipList);
    }
};

using QuorumQuarters = std::vector<std::vector<uint256>>;

bool IsRotationCycle(const Consensus::LLMQParams& params, int cycleHeight);
bool IsRotationDkgCycle(const Consensus::LLMQParams& params, int cycleHeight);
int GetCompletedRotationCycle(const Consensus::LLMQParams& params, int height);
uint16_t GetRotatedSigningIndex(const Consensus::LLMQParams& params, const uint256& requestId);

// Select one complete quarter per index, sharing a cursor over the ranked candidates.
std::pair<CQuorumRotationSnapshot, QuorumQuarters> SelectQuorumQuarters(
    const Consensus::LLMQParams& params, const CDeterministicMNList& mnList, const uint256& modifier,
    const std::vector<QuorumQuarters>& previous);

bool WriteQuorumRotationSnapshot(const Consensus::LLMQParams& params, const CBlockIndex* prev);
void EraseQuorumRotationSnapshot(const Consensus::LLMQParams& params, const CBlockIndex* cycle);
bool ReadQuorumRotationSnapshot(const Consensus::LLMQParams& params, const CBlockIndex* cycle,
                                CQuorumRotationSnapshot& snapshot);
std::vector<CDeterministicMNCPtr> GetRotatedQuorumMembers(const Consensus::LLMQParams& params,
                                                          const CBlockIndex* quorumBase);

} // namespace llmq

#endif // FIRO_LLMQ_QUORUMS_ROTATION_H
