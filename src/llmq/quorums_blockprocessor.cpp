// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "quorums_blockprocessor.h"
#include "quorums_commitment.h"
#include "quorums_debug.h"
#include "quorums_rotation.h"
#include "quorums_utils.h"

#include "evo/specialtx.h"

#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "net.h"
#include "net_processing.h"
#include "primitives/block.h"
#include "validation.h"

namespace llmq
{

CQuorumBlockProcessor* quorumBlockProcessor;

static const std::string DB_MINED_COMMITMENT = "q_mc";
static const std::string DB_MINED_COMMITMENT_BY_INVERSED_HEIGHT = "q_mcih";
static const std::string DB_INDEXED_COMMITMENT_BY_INVERSED_HEIGHT = "q_mcii";
static const std::string DB_ROTATED_COMMITMENT_HISTORY = "q_mcir";

static const std::string DB_BEST_BLOCK_UPGRADE = "q_bbu2";

void CQuorumBlockProcessor::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman)
{
    if (strCommand == NetMsgType::QFCOMMITMENT) {
        CFinalCommitment qc;
        vRecv >> qc;
        if (qc.IsIndexed() && pfrom->nVersion < DIP24_PROTO_VERSION) return;

        auto hash = ::SerializeHash(qc);
        {
            LOCK(cs_main);
            connman.RemoveAskFor(hash);
        }

        if (qc.IsNull()) {
            LOCK(cs_main);
            LogPrintf("CQuorumBlockProcessor::%s -- null commitment from peer=%d\n", __func__, pfrom->id);
            Misbehaving(pfrom->id, 100);
            return;
        }

        if (!Params().GetConsensus().llmqs.count((Consensus::LLMQType)qc.llmqType)) {
            LOCK(cs_main);
            LogPrintf("llmq""CQuorumBlockProcessor::%s -- invalid commitment type %d from peer=%d\n", __func__,
                    qc.llmqType, pfrom->id);
            Misbehaving(pfrom->id, 100);
            return;
        }
        auto type = (Consensus::LLMQType)qc.llmqType;

        // Verify that quorumHash is part of the active chain and that it's the first block in the DKG interval
        const CBlockIndex* pquorumIndex;
        std::vector<CDeterministicMNCPtr> members;
        {
            LOCK(cs_main);
            if (!mapBlockIndex.count(qc.quorumHash)) {
                LogPrintf("CQuorumBlockProcessor::%s -- unknown block %s in commitment, peer=%d\n", __func__,
                        qc.quorumHash.ToString(), pfrom->id);
                // can't really punish the node here, as we might simply be the one that is on the wrong chain or not
                // fully synced
                return;
            }
            pquorumIndex = mapBlockIndex[qc.quorumHash];
            if (chainActive.Tip()->GetAncestor(pquorumIndex->nHeight) != pquorumIndex) {
                LogPrintf("CQuorumBlockProcessor::%s -- block %s not in active chain, peer=%d\n", __func__,
                          qc.quorumHash.ToString(), pfrom->id);
                // same, can't punish
                return;
            }
            if (!qc.MatchesQuorumBase(pquorumIndex)) {
                LogPrintf("CQuorumBlockProcessor::%s -- invalid quorum base block %s, peer=%d\n", __func__,
                          qc.quorumHash.ToString(), pfrom->id);
                Misbehaving(pfrom->id, 100);
                return;
            }
            if (qc.IsIndexed()) {
                const auto& params = Params().GetConsensus().llmqs.at(type);
                const int cycleHeight = pquorumIndex->nHeight - qc.quorumIndex;
                if (chainActive.Height() - cycleHeight > params.dkgMiningWindowEnd ||
                    HasMinedCommitment(type, qc.quorumHash)) return;
                members = CLLMQUtils::GetAllQuorumMembers(type, pquorumIndex);
                if (members.empty()) return;
            }
        }

        {
            // Check if we already got a better one locally
            // We do this before verifying the commitment to avoid DoS
            LOCK(minableCommitmentsCs);
            auto k = std::make_pair(type, qc.quorumHash);
            auto it = minableCommitmentsByQuorum.find(k);
            if (it != minableCommitmentsByQuorum.end()) {
                auto jt = minableCommitments.find(it->second);
                if (jt != minableCommitments.end()) {
                    if (jt->second.CountSigners() >= qc.CountSigners()) {
                        return;
                    }
                }
            }
        }

        if (!qc.IsIndexed()) members = CLLMQUtils::GetAllQuorumMembers(type, pquorumIndex);

        if (!qc.Verify(members, true)) {
            LOCK(cs_main);
            LogPrintf("CQuorumBlockProcessor::%s -- commitment for quorum %s:%d is not valid, peer=%d\n", __func__,
                      qc.quorumHash.ToString(), qc.llmqType, pfrom->id);
            Misbehaving(pfrom->id, 100);
            return;
        }

        LogPrint("llmq", "CQuorumBlockProcessor::%s -- received commitment for quorum %s:%d, validMembers=%d, signers=%d, peer=%d\n", __func__,
                  qc.quorumHash.ToString(), qc.llmqType, qc.CountValidMembers(), qc.CountSigners(), pfrom->id);

        AddMinableCommitment(qc);
    }
}

bool CQuorumBlockProcessor::ProcessBlock(const CBlock& block, const CBlockIndex* pindex, CValidationState& state)
{
    AssertLockHeld(cs_main);

    bool fDIP0003Active = pindex->nHeight >= Params().GetConsensus().DIP0003Height;
    if (!fDIP0003Active) {
        evoDb.Write(DB_BEST_BLOCK_UPGRADE, block.GetHash());
        return true;
    }

    Commitments qcs;
    if (!GetCommitmentsFromBlock(block, pindex, qcs, state)) {
        return false;
    }

    // The following checks make sure that there is always a (possibly null) commitment while in the mining phase
    // until the first non-null commitment has been mined. After the non-null commitment, no other commitments are
    // allowed, including null commitments.
    for (const auto& [type, params] : Params().GetConsensus().llmqs) {
        const int count = Consensus::IsRotatedLLMQType(type) ? params.signingActiveQuorumCount : 1;
        for (int index = 0; index < count; ++index) {
            const bool required = GetUnminedQuorumBase(params, pindex->pprev, index) != nullptr;
            const bool present = qcs.count({type, index}) != 0;
            if (present != required) {
                return state.DoS(100, false, REJECT_INVALID, present ? "bad-qc-not-allowed" : "bad-qc-missing");
            }
        }
    }

    auto blockHash = block.GetHash();

    for (const auto& [key, qc] : qcs) {
        if (!ProcessCommitment(pindex, blockHash, qc, state)) {
            return false;
        }
    }
    for (const auto& [type, params] : Params().GetConsensus().llmqs) {
        if (!WriteQuorumRotationSnapshot(params, pindex->pprev)) {
            return state.Error("Missing DIP24 quorum snapshot; rebuild chainstate with -reindex-chainstate");
        }
    }

    evoDb.Write(DB_BEST_BLOCK_UPGRADE, blockHash);

    return true;
}

// We store a mapping from minedHeight->quorumHeight in the DB
// minedHeight is inversed so that entries are traversable in reversed order
static std::tuple<std::string, uint8_t, uint32_t> BuildInversedHeightKey(Consensus::LLMQType llmqType, int nMinedHeight)
{
    // nMinedHeight must be converted to big endian to make it comparable when serialized
    return std::make_tuple(DB_MINED_COMMITMENT_BY_INVERSED_HEIGHT, (uint8_t)llmqType, htobe32(std::numeric_limits<uint32_t>::max() - nMinedHeight));
}

static auto BuildIndexedHeightKey(Consensus::LLMQType type, uint16_t index, int height)
{
    return std::make_tuple(DB_INDEXED_COMMITMENT_BY_INVERSED_HEIGHT, uint8_t(type), index,
                           htobe32(std::numeric_limits<uint32_t>::max() - height));
}

static auto BuildRotatedHistoryKey(Consensus::LLMQType type, int height, uint16_t index)
{
    return std::make_tuple(DB_ROTATED_COMMITMENT_HISTORY, uint8_t(type),
                           htobe32(std::numeric_limits<uint32_t>::max() - height), index);
}

bool CQuorumBlockProcessor::ProcessCommitment(const CBlockIndex* pindex, const uint256& blockHash, const CFinalCommitment& qc, CValidationState& state)
{
    const auto& params = Params().GetConsensus().llmqs.at(Consensus::LLMQType(qc.llmqType));
    const auto* base = GetUnminedQuorumBase(params, pindex->pprev, qc.quorumIndex);
    if (!qc.MatchesQuorumBase(base)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-qc-block");
    }

    if (qc.IsNull()) {
        if (!qc.VerifyNull()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-qc-invalid-null");
        }
        return true;
    }

    const auto& quorumHash = qc.quorumHash;
    auto members = CLLMQUtils::GetAllQuorumMembers(params.type, base);

    if (!qc.Verify(members, true)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-qc-invalid");
    }

    // Store commitment in DB
    evoDb.Write(std::make_pair(DB_MINED_COMMITMENT, std::make_pair((uint8_t)params.type, quorumHash)), std::make_pair(qc, blockHash));
    if (qc.IsIndexed()) {
        evoDb.Write(BuildIndexedHeightKey(params.type, qc.quorumIndex, pindex->nHeight), base->nHeight);
        evoDb.Write(BuildRotatedHistoryKey(params.type, pindex->nHeight, qc.quorumIndex), base->nHeight);
    } else {
        evoDb.Write(BuildInversedHeightKey(params.type, pindex->nHeight), base->nHeight);
    }

    {
        LOCK(minableCommitmentsCs);
        hasMinedCommitmentCache.erase(std::make_pair(params.type, quorumHash));
    }

    LogPrint("llmq", "CQuorumBlockProcessor::%s -- processed commitment from block. type=%d, quorumHash=%s, signers=%s, validMembers=%d, quorumPublicKey=%s\n", __func__,
              qc.llmqType, quorumHash.ToString(), qc.CountSigners(), qc.CountValidMembers(), qc.quorumPublicKey.ToString());

    return true;
}

bool CQuorumBlockProcessor::UndoBlock(
        const CBlock& block, const CBlockIndex* pindex, bool fAddMinable)
{
    AssertLockHeld(cs_main);

    Commitments qcs;
    CValidationState dummy;
    if (!GetCommitmentsFromBlock(block, pindex, qcs, dummy)) {
        return false;
    }

    for (auto& p : qcs) {
        auto& qc = p.second;
        if (qc.IsNull()) {
            continue;
        }

        evoDb.Erase(std::make_pair(DB_MINED_COMMITMENT, std::make_pair(qc.llmqType, qc.quorumHash)));
        if (qc.IsIndexed()) {
            evoDb.Erase(BuildIndexedHeightKey(Consensus::LLMQType(qc.llmqType), qc.quorumIndex, pindex->nHeight));
            evoDb.Erase(BuildRotatedHistoryKey(Consensus::LLMQType(qc.llmqType), pindex->nHeight, qc.quorumIndex));
        } else {
            evoDb.Erase(BuildInversedHeightKey(Consensus::LLMQType(qc.llmqType), pindex->nHeight));
        }
        {
            LOCK(minableCommitmentsCs);
            hasMinedCommitmentCache.erase(std::make_pair((Consensus::LLMQType)qc.llmqType, qc.quorumHash));
        }

        // If a real reorg happened, allow this commitment to be mined later.
        // VerifyDB's temporary disconnect must not mutate or relay mining work.
        if (fAddMinable)
            AddMinableCommitment(qc);
    }

    for (const auto& [type, params] : Params().GetConsensus().llmqs) {
        EraseQuorumRotationSnapshot(params, pindex);
    }
    evoDb.Write(DB_BEST_BLOCK_UPGRADE, pindex->pprev->GetBlockHash());

    return true;
}

// TODO remove this with 0.15.0
void CQuorumBlockProcessor::UpgradeDB()
{
    LOCK(cs_main);
    uint256 bestBlock;
    if (evoDb.GetRawDB().Read(DB_BEST_BLOCK_UPGRADE, bestBlock) && bestBlock == chainActive.Tip()->GetBlockHash()) {
        return;
    }

    LogPrintf("CQuorumBlockProcessor::%s -- Upgrading DB...\n", __func__);

    if (chainActive.Height() >= Params().GetConsensus().DIP0003EnforcementHeight) {
        auto pindex = chainActive[Params().GetConsensus().DIP0003EnforcementHeight];
        while (pindex) {
            CBlock block;
            bool r = ReadBlockFromDisk(block, pindex, Params().GetConsensus());
            assert(r);

            Commitments qcs;
            CValidationState dummyState;
            GetCommitmentsFromBlock(block, pindex, qcs, dummyState);

            for (const auto& p : qcs) {
                const auto& qc = p.second;
                if (qc.IsNull()) {
                    continue;
                }
                auto quorumIndex = mapBlockIndex.at(qc.quorumHash);
                evoDb.GetRawDB().Write(std::make_pair(DB_MINED_COMMITMENT, std::make_pair((uint8_t)qc.llmqType, qc.quorumHash)), std::make_pair(qc, pindex->GetBlockHash()));
                if (qc.IsIndexed()) {
                    evoDb.GetRawDB().Write(BuildIndexedHeightKey(Consensus::LLMQType(qc.llmqType), qc.quorumIndex, pindex->nHeight), quorumIndex->nHeight);
                    evoDb.GetRawDB().Write(BuildRotatedHistoryKey(Consensus::LLMQType(qc.llmqType), pindex->nHeight, qc.quorumIndex), quorumIndex->nHeight);
                } else {
                    evoDb.GetRawDB().Write(BuildInversedHeightKey(Consensus::LLMQType(qc.llmqType), pindex->nHeight), quorumIndex->nHeight);
                }
            }

            evoDb.GetRawDB().Write(DB_BEST_BLOCK_UPGRADE, pindex->GetBlockHash());

            pindex = chainActive.Next(pindex);
        }
    }

    LogPrintf("CQuorumBlockProcessor::%s -- Upgrade done...\n", __func__);
}

bool CQuorumBlockProcessor::GetCommitmentsFromBlock(const CBlock& block, const CBlockIndex* pindex, Commitments& ret, CValidationState& state)
{
    AssertLockHeld(cs_main);

    auto& consensus = Params().GetConsensus();
    bool fDIP0003Active = pindex->nHeight >= consensus.DIP0003Height;

    ret.clear();

    for (const auto& tx : block.vtx) {
        if (tx->nType == TRANSACTION_QUORUM_COMMITMENT) {
            CFinalCommitmentTxPayload qc;
            if (!GetTxPayload(*tx, qc)) {
                // should not happen as it was verified before processing the block
                return state.DoS(100, false, REJECT_INVALID, "bad-tx-payload");
            }

            const auto type = Consensus::LLMQType(qc.commitment.llmqType);
            const auto it = consensus.llmqs.find(type);
            if (it == consensus.llmqs.end()) {
                return state.DoS(100, false, REJECT_INVALID, "bad-qc-type");
            }
            const auto index = qc.commitment.quorumIndex;
            if (index >= (qc.commitment.IsIndexed() ? it->second.signingActiveQuorumCount : 1)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-qc-index");
            }
            if (!ret.emplace(std::make_pair(type, index), std::move(qc.commitment)).second) {
                return state.DoS(100, false, REJECT_INVALID, "bad-qc-dup");
            }
        }
    }

    if (!fDIP0003Active && !ret.empty()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-qc-premature");
    }

    return true;
}

const CBlockIndex* CQuorumBlockProcessor::GetUnminedQuorumBase(const Consensus::LLMQParams& params, const CBlockIndex* prev, uint16_t index)
{
    AssertLockHeld(cs_main);

    const int height = prev->nHeight + 1;
    const int offset = height % params.dkgInterval;
    const int cycleHeight = height - offset;
    if (offset < params.dkgMiningWindowStart || offset > params.dkgMiningWindowEnd ||
        (Consensus::IsRotatedLLMQType(params.type) && !IsRotationDkgCycle(params, cycleHeight))) return nullptr;
    const auto* base = prev->GetAncestor(cycleHeight + index);
    return base && !HasMinedCommitment(params.type, base->GetBlockHash()) ? base : nullptr;
}

bool CQuorumBlockProcessor::HasMinedCommitment(Consensus::LLMQType llmqType, const uint256& quorumHash)
{
    auto cacheKey = std::make_pair(llmqType, quorumHash);
    {
        LOCK(minableCommitmentsCs);
        auto cacheIt = hasMinedCommitmentCache.find(cacheKey);
        if (cacheIt != hasMinedCommitmentCache.end()) {
            return cacheIt->second;
        }
    }

    auto key = std::make_pair(DB_MINED_COMMITMENT, std::make_pair((uint8_t)llmqType, quorumHash));
    bool ret = evoDb.Exists(key);

    LOCK(minableCommitmentsCs);
    hasMinedCommitmentCache.emplace(cacheKey, ret);
    return ret;
}

void CQuorumBlockProcessor::ClearMinedCommitmentCache()
{
    LOCK(minableCommitmentsCs);
    hasMinedCommitmentCache.clear();
}

bool CQuorumBlockProcessor::GetMinedCommitment(Consensus::LLMQType llmqType, const uint256& quorumHash, CFinalCommitment& retQc, uint256& retMinedBlockHash)
{
    auto key = std::make_pair(DB_MINED_COMMITMENT, std::make_pair((uint8_t)llmqType, quorumHash));
    std::pair<CFinalCommitment, uint256> p;
    if (!evoDb.Read(key, p)) {
        return false;
    }
    retQc = std::move(p.first);
    retMinedBlockHash = p.second;
    return true;
}

std::vector<const CBlockIndex*> CQuorumBlockProcessor::GetMinedCommitmentsUntilBlock(Consensus::LLMQType llmqType, const CBlockIndex* pindex, size_t maxCount)
{
    if (Consensus::IsRotatedLLMQType(llmqType)) {
        LOCK(cs_main);
        std::vector<const CBlockIndex*> ret;
        if (pindex->nHeight < Params().GetConsensus().nDIP24Height || !chainActive.Contains(pindex)) return ret;
        auto it = evoDb.GetCurTransaction().NewIteratorUniquePtr();
        auto key = BuildRotatedHistoryKey(llmqType, pindex->nHeight, 0);
        for (it->Seek(key); it->Valid() && ret.size() < maxCount; it->Next()) {
            int height;
            if (!it->GetKey(key) || std::get<0>(key) != DB_ROTATED_COMMITMENT_HISTORY ||
                std::get<1>(key) != llmqType || !it->GetValue(height)) break;
            const auto* base = pindex->GetAncestor(height);
            if (!base) break;
            ret.push_back(base);
        }
        return ret;
    }
    auto dbIt = evoDb.GetCurTransaction().NewIteratorUniquePtr();

    auto firstKey = BuildInversedHeightKey(llmqType, pindex->nHeight);
    auto lastKey = BuildInversedHeightKey(llmqType, 0);

    dbIt->Seek(firstKey);

    std::vector<const CBlockIndex*> ret;
    ret.reserve(maxCount);

    while (dbIt->Valid() && ret.size() < maxCount) {
        decltype(firstKey) curKey;
        int quorumHeight;
        if (!dbIt->GetKey(curKey) || curKey >= lastKey) {
            break;
        }
        if (std::get<0>(curKey) != DB_MINED_COMMITMENT_BY_INVERSED_HEIGHT || std::get<1>(curKey) != (uint8_t)llmqType) {
            break;
        }

        uint32_t nMinedHeight = std::numeric_limits<uint32_t>::max() - be32toh(std::get<2>(curKey));
        if (cmp::greater(nMinedHeight, pindex->nHeight)) {
            break;
        }

        if (!dbIt->GetValue(quorumHeight)) {
            break;
        }

        auto quorumIndex = pindex->GetAncestor(quorumHeight);
        assert(quorumIndex);
        ret.emplace_back(quorumIndex);

        dbIt->Next();
    }

    return ret;
}

std::vector<const CBlockIndex*> CQuorumBlockProcessor::GetActiveIndexedCommitments(Consensus::LLMQType type, const CBlockIndex* pindex, size_t maxCount)
{
    LOCK(cs_main);
    std::vector<const CBlockIndex*> ret;
    if (!chainActive.Contains(pindex)) return ret;
    const int count = Params().GetConsensus().llmqs.at(type).signingActiveQuorumCount;
    for (int index = 0; index < count && ret.size() < maxCount; ++index) {
        if (const auto* base = GetMinedCommitmentByIndex(type, pindex, index)) ret.push_back(base);
    }
    return ret;
}

const CBlockIndex* CQuorumBlockProcessor::GetMinedCommitmentByIndex(Consensus::LLMQType type, const CBlockIndex* pindex, uint16_t index)
{
    AssertLockHeld(cs_main);
    const auto& params = Params().GetConsensus().llmqs.at(type);
    if (pindex->nHeight < Params().GetConsensus().nDIP24Height) return nullptr;

    auto it = evoDb.GetCurTransaction().NewIteratorUniquePtr();
    auto key = BuildIndexedHeightKey(type, index, pindex->nHeight);
    it->Seek(key);
    int quorumHeight;
    if (!it->Valid() || !it->GetKey(key) || std::get<0>(key) != DB_INDEXED_COMMITMENT_BY_INVERSED_HEIGHT ||
        std::get<1>(key) != type || std::get<2>(key) != index || !it->GetValue(quorumHeight)) return nullptr;
    assert(quorumHeight % params.dkgInterval == index);
    return pindex->GetAncestor(quorumHeight);
}

std::map<Consensus::LLMQType, std::vector<const CBlockIndex*>> CQuorumBlockProcessor::GetMinedAndActiveCommitmentsUntilBlock(const CBlockIndex* pindex)
{
    std::map<Consensus::LLMQType, std::vector<const CBlockIndex*>> ret;

    for (const auto& p : Params().GetConsensus().llmqs) {
        const auto& params = p.second;
        ret[params.type] = Consensus::IsRotatedLLMQType(params.type)
            ? GetActiveIndexedCommitments(params.type, pindex, params.signingActiveQuorumCount)
            : GetMinedCommitmentsUntilBlock(params.type, pindex, params.signingActiveQuorumCount);
    }

    return ret;
}

bool CQuorumBlockProcessor::HasMinableCommitment(const uint256& hash)
{
    LOCK(minableCommitmentsCs);
    return minableCommitments.count(hash) != 0;
}

void CQuorumBlockProcessor::AddMinableCommitment(const CFinalCommitment& fqc)
{
    bool relay = false;
    uint256 commitmentHash = ::SerializeHash(fqc);

    {
        LOCK(minableCommitmentsCs);

        auto k = std::make_pair((Consensus::LLMQType) fqc.llmqType, fqc.quorumHash);
        auto ins = minableCommitmentsByQuorum.emplace(k, commitmentHash);
        if (ins.second) {
            minableCommitments.emplace(commitmentHash, fqc);
            relay = true;
        } else {
            auto& oldFqc = minableCommitments.at(ins.first->second);
            if (fqc.CountSigners() > oldFqc.CountSigners()) {
                // new commitment has more signers, so override the known one
                minableCommitments.erase(ins.first->second);
                ins.first->second = commitmentHash;
                minableCommitments.emplace(commitmentHash, fqc);
                relay = true;
            }
        }
    }

    // We only relay the new commitment if it's new or better then the old one
    if (relay) {
        CInv inv(MSG_QUORUM_FINAL_COMMITMENT, commitmentHash);
        g_connman->RelayInv(inv, fqc.IsIndexed() ? DIP24_PROTO_VERSION : DMN_PROTO_VERSION);
    }
}

bool CQuorumBlockProcessor::GetMinableCommitmentByHash(const uint256& commitmentHash, llmq::CFinalCommitment& ret)
{
    LOCK(minableCommitmentsCs);
    auto it = minableCommitments.find(commitmentHash);
    if (it == minableCommitments.end()) {
        return false;
    }
    ret = it->second;
    return true;
}

// Will return false if no commitment should be mined
// Will return true and a null commitment if no minable commitment is known and none was mined yet
std::vector<CFinalCommitment> CQuorumBlockProcessor::GetMinableCommitments(Consensus::LLMQType type, const CBlockIndex* prev)
{
    AssertLockHeld(cs_main);

    const auto& params = Params().GetConsensus().llmqs.at(type);
    const int count = Consensus::IsRotatedLLMQType(type) ? params.signingActiveQuorumCount : 1;
    std::vector<CFinalCommitment> ret;
    for (int index = 0; index < count; ++index) {
        const auto* base = GetUnminedQuorumBase(params, prev, index);
        if (!base) continue;
        auto hash = base->GetBlockHash();
        LOCK(minableCommitmentsCs);
        auto it = minableCommitmentsByQuorum.find({type, hash});
        if (it == minableCommitmentsByQuorum.end()) {
            ret.emplace_back(params, hash, index);
        } else {
            ret.push_back(minableCommitments.at(it->second));
        }
    }
    return ret;
}

std::vector<CTransactionRef> CQuorumBlockProcessor::GetMinableCommitmentTxs(const CBlockIndex* prev)
{
    AssertLockHeld(cs_main);

    std::vector<CTransactionRef> ret;
    for (const auto& [type, params] : Params().GetConsensus().llmqs) {
        for (auto& commitment : GetMinableCommitments(type, prev)) {
            CFinalCommitmentTxPayload qc;
            qc.nHeight = prev->nHeight + 1;
            qc.commitment = std::move(commitment);
            CMutableTransaction tx;
            tx.nVersion = 3;
            tx.nType = TRANSACTION_QUORUM_COMMITMENT;
            SetTxPayload(tx, qc);
            ret.push_back(MakeTransactionRef(tx));
        }
    }
    return ret;
}

}
