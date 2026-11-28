// Distributed under the MIT software license, see the accompanying file COPYING.

#include "llmq/quorums_rotationinfo.h"

#include "chainparams.h"
#include "llmq/quorums_blockprocessor.h"
#include "net.h"
#include "validation.h"

#include <set>

namespace llmq
{

bool BuildQuorumRotationInfo(const CGetQuorumRotationInfo& request, CQuorumRotationInfo& response, std::string& error)
{
    AssertLockHeld(cs_main);
    const auto& consensus = Params().GetConsensus();
    const auto type = consensus.llmqForRotatedInstantSend;
    const auto paramsIter = consensus.llmqs.find(type);
    if (paramsIter == consensus.llmqs.end()) return false;
    const auto& params = paramsIter->second;
    auto it = mapBlockIndex.find(request.blockHash);
    if (it == mapBlockIndex.end() || !chainActive.Contains(it->second)) {
        error = "Requested block is not on the active chain";
        return false;
    }
    const auto* block = it->second;
    const int current = block->nHeight - block->nHeight % params.dkgInterval;
    if (!IsRotationCycle(params, current)) {
        error = "Quorum rotation not active at requested block";
        return false;
    }

    std::map<int, uint256> baseHashes{{0, uint256{}}};
    for (const auto& hash : request.baseBlockHashes) {
        auto known = mapBlockIndex.find(hash);
        if (known == mapBlockIndex.end() || !chainActive.Contains(known->second)) {
            error = "Rotation diff base is not on the active chain";
            return false;
        }
        baseHashes.emplace(known->second->nHeight, hash);
    }

    std::set<int> cycles;
    auto addCycle = [&](int height, int quarters) {
        for (int depth = 0; depth < quarters; ++depth) {
            const int base = height - depth * params.dkgInterval;
            if (IsRotationCycle(params, base)) cycles.insert(base);
        }
    };
    addCycle(current, ROTATION_QUARTER_COUNT + request.extraShare);

    response = CQuorumRotationInfo{};
    for (const auto* base : quorumBlockProcessor->GetActiveIndexedCommitments(type, block, params.signingActiveQuorumCount)) {
        CFinalCommitment qc;
        uint256 minedHash;
        if (!quorumBlockProcessor->GetMinedCommitment(type, base->GetBlockHash(), qc, minedHash)) {
            error = "Missing active quorum commitment";
            return false;
        }
        addCycle(base->nHeight - qc.quorumIndex, ROTATION_QUARTER_COUNT);
        response.activeCommitments.push_back(std::move(qc));
    }

    // Chain the work-list diffs through the closest known or emitted bases.
    size_t serializedSize = GetSerializeSize(response.activeCommitments, SER_NETWORK, DIP24_PROTO_VERSION) + 9;
    for (const int height : cycles) {
        const auto* cycle = block->GetAncestor(height);
        const auto* work = cycle->GetAncestor(height - ROTATION_WORK_DEPTH);
        CQuorumRotationCycle entry;
        entry.cycleHash = cycle->GetBlockHash();
        if (!ReadQuorumRotationSnapshot(params, cycle, entry.snapshot)) {
            error = "Missing quorum rotation snapshot";
            return false;
        }
        if (!BuildSimplifiedMNListDiff(std::prev(baseHashes.upper_bound(work->nHeight))->second, work->GetBlockHash(),
                                       entry.workDiff, error)) return false;
        serializedSize += GetSerializeSize(entry, SER_NETWORK, DIP24_PROTO_VERSION);
        if (serializedSize > MAX_PROTOCOL_MESSAGE_LENGTH) {
            error = "Rotation info exceeds the message limit; supply a more recent base block";
            return false;
        }
        baseHashes.emplace(work->nHeight, work->GetBlockHash());
        response.cycles.push_back(std::move(entry));
    }
    if (!BuildSimplifiedMNListDiff(std::prev(baseHashes.upper_bound(block->nHeight))->second, request.blockHash,
                                   response.blockDiff, error)) return false;
    if (serializedSize + GetSerializeSize(response.blockDiff, SER_NETWORK, DIP24_PROTO_VERSION) > MAX_PROTOCOL_MESSAGE_LENGTH) {
        error = "Rotation info exceeds the message limit; supply a more recent base block";
        return false;
    }
    return true;
}

} // namespace llmq
