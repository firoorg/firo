// Distributed under the MIT software license, see the accompanying file COPYING.

#ifndef FIRO_LLMQ_QUORUMS_ROTATIONINFO_H
#define FIRO_LLMQ_QUORUMS_ROTATIONINFO_H

#include "evo/simplifiedmns.h"
#include "llmq/quorums_commitment.h"
#include "llmq/quorums_rotation.h"

namespace llmq
{

struct CGetQuorumRotationInfo
{
    std::vector<uint256> baseBlockHashes;
    uint256 blockHash;
    bool extraShare{false};

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const auto size = ReadCompactSize(s);
        if (size > 32) throw std::ios_base::failure("Too many quorum rotation base blocks");
        baseBlockHashes.resize(size);
        for (auto& hash : baseBlockHashes) s >> hash;
        s >> blockHash >> extraShare;
    }
};

struct CQuorumRotationCycle
{
    uint256 cycleHash;
    CQuorumRotationSnapshot snapshot;
    CSimplifiedMNListDiff workDiff;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(cycleHash);
        READWRITE(snapshot);
        READWRITE(workDiff);
    }
};

struct CQuorumRotationInfo
{
    std::vector<CQuorumRotationCycle> cycles;
    CSimplifiedMNListDiff blockDiff;
    std::vector<CFinalCommitment> activeCommitments;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(cycles);
        READWRITE(blockDiff);
        READWRITE(activeCommitments);
    }
};

bool BuildQuorumRotationInfo(const CGetQuorumRotationInfo& request, CQuorumRotationInfo& response, std::string& error);

} // namespace llmq

#endif // FIRO_LLMQ_QUORUMS_ROTATIONINFO_H
