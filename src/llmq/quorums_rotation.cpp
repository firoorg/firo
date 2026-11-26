// Distributed under the MIT software license, see the accompanying file COPYING.

#include "llmq/quorums_rotation.h"

#include "chain.h"
#include "chainparams.h"
#include "evo/evodb.h"
#include "hash.h"

#include <algorithm>
#include <set>

namespace llmq
{
namespace
{
using StoredSnapshot = std::pair<CQuorumRotationSnapshot, QuorumQuarters>;

auto SnapshotKey(Consensus::LLMQType type, const CBlockIndex& workBlock)
{
    // The work block fixes the inputs to this computation, even when testing
    // an unmined block at the cycle boundary.
    return std::make_tuple(std::string("q_rs"), uint8_t(type), workBlock.GetBlockHash());
}

bool ReadSnapshot(const Consensus::LLMQParams& params, const CBlockIndex* ancestor,
                  int cycleHeight, StoredSnapshot& snapshot)
{
    const auto* workBlock = ancestor->GetAncestor(cycleHeight - ROTATION_WORK_DEPTH);
    return workBlock && evoDb->Read(SnapshotKey(params.type, *workBlock), snapshot) &&
           snapshot.second.size() == size_t(params.signingActiveQuorumCount);
}
} // namespace

bool IsRotationCycle(const Consensus::LLMQParams& params, int cycleHeight)
{
    const auto& consensus = Params().GetConsensus();
    return Consensus::IsRotatedLLMQType(params.type) &&
           cycleHeight >= std::max({ROTATION_WORK_DEPTH, consensus.nDIP24Height, consensus.DIP0003EnforcementHeight}) &&
           cycleHeight % params.dkgInterval == 0;
}

bool IsRotationDkgCycle(const Consensus::LLMQParams& params, int cycleHeight)
{
    return IsRotationCycle(params, cycleHeight - (ROTATION_QUARTER_COUNT - 1) * params.dkgInterval);
}

int GetCompletedRotationCycle(const Consensus::LLMQParams& params, int height)
{
    if (height < 0) return -1;
    const int offset = height % params.dkgInterval;
    const int cycleHeight = height - offset - (offset < params.dkgMiningWindowEnd ? params.dkgInterval : 0);
    return IsRotationDkgCycle(params, cycleHeight) ? cycleHeight : -1;
}

uint16_t GetRotatedSigningIndex(const Consensus::LLMQParams& params, const uint256& requestId)
{
    // The configured count is a power of two, so modulo selects the low bits.
    return requestId.GetUint64(0) % params.signingActiveQuorumCount;
}

std::pair<CQuorumRotationSnapshot, QuorumQuarters> SelectQuorumQuarters(
    const Consensus::LLMQParams& params, const CDeterministicMNList& mnList, const uint256& modifier,
    const std::vector<QuorumQuarters>& previous)
{
    const size_t count = params.signingActiveQuorumCount;
    const size_t quarterSize = params.size / ROTATION_QUARTER_COUNT;
    CQuorumRotationSnapshot snapshot;
    QuorumQuarters quarters(count);

    auto scores = mnList.CalculateScores(modifier);
    if (scores.size() < size_t(params.size)) return {std::move(snapshot), std::move(quarters)};
    // Break ties using an identifier also present in the simplified MN list.
    std::sort(scores.begin(), scores.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.first != rhs.first) return lhs.first > rhs.first;
        return lhs.second->proTxHash < rhs.second->proTxHash;
    });

    std::vector<std::set<uint256>> retained(count);
    std::set<uint256> used;
    for (const auto& cycle : previous) {
        for (size_t index = 0; index < count; ++index) {
            retained[index].insert(cycle[index].begin(), cycle[index].end());
            used.insert(cycle[index].begin(), cycle[index].end());
        }
    }

    std::vector<uint256> candidates, active;
    candidates.reserve(scores.size());
    snapshot.activeMembers.reserve(scores.size());
    for (const auto& score : scores) {
        const auto& id = score.second->proTxHash;
        const bool wasUsed = used.count(id) != 0;
        snapshot.activeMembers.push_back(wasUsed);
        (wasUsed ? active : candidates).push_back(id);
    }
    candidates.insert(candidates.end(), active.begin(), active.end());

    size_t cursor = 0;
    bool skipped = false;
    for (size_t index = 0; index < count; ++index) {
        for (size_t tried = 0; tried < candidates.size() && quarters[index].size() < quarterSize; ++tried) {
            const size_t pos = cursor;
            cursor = (cursor + 1) % candidates.size();
            if (retained[index].count(candidates[pos])) {
                skipped = true;
                continue;
            }
            quarters[index].push_back(candidates[pos]);
            snapshot.skipList.push_back(pos);
        }
        if (quarters[index].size() != quarterSize) {
            // Never serialize a partial quarter: replay must reconstruct the
            // same boundaries, even after a cycle with insufficient members.
            return {CQuorumRotationSnapshot{}, QuorumQuarters(count)};
        }
    }
    snapshot.skipMode = skipped ? CQuorumRotationSnapshot::KEEP_ENTRIES : CQuorumRotationSnapshot::NO_SKIPPING;
    if (!skipped) snapshot.skipList.clear();
    return {std::move(snapshot), std::move(quarters)};
}

bool WriteQuorumRotationSnapshot(const Consensus::LLMQParams& params, const CBlockIndex* prev)
{
    const int height = prev->nHeight + 1;
    if (!IsRotationCycle(params, height)) return true;

    std::vector<QuorumQuarters> previous;
    for (int i = 1; i < ROTATION_QUARTER_COUNT; ++i) {
        const int priorHeight = height - i * params.dkgInterval;
        if (!IsRotationCycle(params, priorHeight)) break;
        StoredSnapshot snapshot;
        if (!ReadSnapshot(params, prev, priorHeight, snapshot)) return false;
        previous.push_back(std::move(snapshot.second));
    }

    const auto* workBlock = prev->GetAncestor(height - ROTATION_WORK_DEPTH);
    const auto list = deterministicMNManager->GetListForBlock(workBlock);
    const auto modifier = SerializeHash(std::make_pair(uint8_t(params.type), workBlock->GetBlockHash()));
    evoDb->Write(SnapshotKey(params.type, *workBlock), SelectQuorumQuarters(params, list, modifier, previous));
    return true;
}

void EraseQuorumRotationSnapshot(const Consensus::LLMQParams& params, const CBlockIndex* cycle)
{
    if (!IsRotationCycle(params, cycle->nHeight)) return;
    evoDb->Erase(SnapshotKey(params.type, *cycle->GetAncestor(cycle->nHeight - ROTATION_WORK_DEPTH)));
}

bool ReadQuorumRotationSnapshot(const Consensus::LLMQParams& params, const CBlockIndex* cycle,
                                CQuorumRotationSnapshot& snapshot)
{
    StoredSnapshot stored;
    if (!IsRotationCycle(params, cycle->nHeight) || !ReadSnapshot(params, cycle, cycle->nHeight, stored)) return false;
    snapshot = std::move(stored.first);
    return true;
}

std::vector<CDeterministicMNCPtr> GetRotatedQuorumMembers(const Consensus::LLMQParams& params,
                                                          const CBlockIndex* quorumBase)
{
    const size_t index = quorumBase->nHeight % params.dkgInterval;
    const int height = quorumBase->nHeight - int(index);
    if (index >= size_t(params.signingActiveQuorumCount) || !IsRotationDkgCycle(params, height)) return {};

    const auto list = deterministicMNManager->GetListForBlock(quorumBase->GetAncestor(height - ROTATION_WORK_DEPTH));
    std::vector<CDeterministicMNCPtr> members;
    members.reserve(params.size);
    std::set<uint256> seen;
    for (int i = ROTATION_QUARTER_COUNT - 1; i >= 0; --i) {
        StoredSnapshot snapshot;
        if (!ReadSnapshot(params, quorumBase, height - i * params.dkgInterval, snapshot)) return {};
        const auto& quarter = snapshot.second[index];
        if (quarter.size() != size_t(params.size / ROTATION_QUARTER_COUNT)) return {};
        for (const auto& id : quarter) {
            if (!seen.insert(id).second) return {};
            // The identity rotates; its service and operator key come from the
            // current work block. Revoked/removed members cannot sign.
            if (auto dmn = list.GetValidMN(id)) members.push_back(std::move(dmn));
        }
    }
    if (members.size() < size_t(params.minSize)) return {};
    return members;
}
} // namespace llmq
