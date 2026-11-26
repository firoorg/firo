// Copyright (c) 2018 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_QUORUMS_BLOCKPROCESSOR_H
#define DASH_QUORUMS_BLOCKPROCESSOR_H

#include "llmq/quorums_commitment.h"
#include "llmq/quorums_utils.h"

#include "consensus/params.h"
#include "primitives/transaction.h"
#include "saltedhasher.h"
#include "sync.h"

#include <map>
#include <unordered_map>

class CNode;
class CConnman;

namespace llmq
{

class CQuorumBlockProcessor
{
private:
    CEvoDB& evoDb;

    // TODO cleanup
    CCriticalSection minableCommitmentsCs;
    std::map<std::pair<Consensus::LLMQType, uint256>, uint256> minableCommitmentsByQuorum;
    std::map<uint256, CFinalCommitment> minableCommitments;

    std::unordered_map<std::pair<Consensus::LLMQType, uint256>, bool, StaticSaltedHasher> hasMinedCommitmentCache;

public:
    CQuorumBlockProcessor(CEvoDB& _evoDb) : evoDb(_evoDb) {}

    void UpgradeDB();

    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman);

    bool ProcessBlock(const CBlock& block, const CBlockIndex* pindex, CValidationState& state);
    bool UndoBlock(const CBlock& block, const CBlockIndex* pindex,
                   bool fAddMinable = true);

    void AddMinableCommitment(const CFinalCommitment& fqc);
    bool HasMinableCommitment(const uint256& hash);
    bool GetMinableCommitmentByHash(const uint256& commitmentHash, CFinalCommitment& ret);
    std::vector<CFinalCommitment> GetMinableCommitments(Consensus::LLMQType llmqType, const CBlockIndex* prev);
    std::vector<CTransactionRef> GetMinableCommitmentTxs(const CBlockIndex* prev);

    bool HasMinedCommitment(Consensus::LLMQType llmqType, const uint256& quorumHash);
    bool GetMinedCommitment(Consensus::LLMQType llmqType, const uint256& quorumHash, CFinalCommitment& ret, uint256& retMinedBlockHash);

    /** Drop database-derived results after temporary database traversal. */
    void ClearMinedCommitmentCache();

    std::vector<const CBlockIndex*> GetMinedCommitmentsUntilBlock(Consensus::LLMQType llmqType, const CBlockIndex* pindex, size_t maxCount);
    std::vector<const CBlockIndex*> GetActiveIndexedCommitments(Consensus::LLMQType llmqType, const CBlockIndex* pindex, size_t maxCount);
    const CBlockIndex* GetMinedCommitmentByIndex(Consensus::LLMQType llmqType, const CBlockIndex* pindex, uint16_t index);
    std::map<Consensus::LLMQType, std::vector<const CBlockIndex*>> GetMinedAndActiveCommitmentsUntilBlock(const CBlockIndex* pindex);

private:
    using Commitments = std::map<std::pair<Consensus::LLMQType, uint16_t>, CFinalCommitment>;
    bool GetCommitmentsFromBlock(const CBlock& block, const CBlockIndex* pindex, Commitments& ret, CValidationState& state);
    bool ProcessCommitment(const CBlockIndex* pindex, const uint256& blockHash, const CFinalCommitment& qc, CValidationState& state);
    const CBlockIndex* GetUnminedQuorumBase(const Consensus::LLMQParams& params, const CBlockIndex* prev, uint16_t index);
};

extern CQuorumBlockProcessor* quorumBlockProcessor;

}

#endif//DASH_QUORUMS_BLOCKPROCESSOR_H
