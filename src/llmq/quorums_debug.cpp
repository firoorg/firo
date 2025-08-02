// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "quorums_debug.h"

#include "chainparams.h"
#include "validation.h"

#include "evo/deterministicmns.h"
#include "quorums_utils.h"

namespace llmq
{
CDKGDebugManager* quorumDKGDebugManager;

UniValue CDKGDebugSessionStatus::ToJson(int detailLevel) const
{
    UniValue ret(UniValue::VOBJ);

    if (!Params().GetConsensus().llmqs.count((Consensus::LLMQType)llmqType) || quorumHash.IsNull()) {
        return ret;
    }

    std::vector<CDeterministicMNCPtr> dmnMembers;
    if (detailLevel == 2) {
        const CBlockIndex* pindex = nullptr;
        {
            LOCK(cs_main);
            auto it = mapBlockIndex.find(quorumHash);
            if (it != mapBlockIndex.end()) {
                pindex = it->second;
            }
        }
        if (pindex != nullptr) {
            dmnMembers = CLLMQUtils::GetAllQuorumMembers((Consensus::LLMQType) llmqType, pindex);
        }
    }

    ret.push_back(Pair("llmqType", llmqType));
    ret.push_back(Pair("quorumHash", quorumHash.ToString()));
    ret.push_back(Pair("quorumHeight", (int)quorumHeight));
    ret.push_back(Pair("phase", (int)phase));

    ret.push_back(Pair("sentContributions", debugStatus.status.sentContributions));
    ret.push_back(Pair("sentComplaint", debugStatus.status.sentComplaint));
    ret.push_back(Pair("sentJustification", debugStatus.status.sentJustification));
    ret.push_back(Pair("sentPrematureCommitment", debugStatus.status.sentPrematureCommitment));
    ret.push_back(Pair("aborted", debugStatus.status.aborted));

    struct ArrOrCount {
        int count{0};
        UniValue arr{UniValue::VARR};
    };

    ArrOrCount badMembers;
    ArrOrCount weComplain;
    ArrOrCount receivedContributions;
    ArrOrCount receivedComplaints;
    ArrOrCount receivedJustifications;
    ArrOrCount receivedPrematureCommitments;
    ArrOrCount complaintsFromMembers;

    auto add = [&](ArrOrCount& v, size_t idx, bool flag) {
        if (flag) {
            if (detailLevel == 0) {
                v.count++;
            } else if (detailLevel == 1) {
                v.arr.push_back((int)idx);
            } else if (detailLevel == 2) {
                UniValue a(UniValue::VOBJ);
                a.push_back(Pair("memberIndex", (int)idx));
                if (idx < dmnMembers.size()) {
                    a.push_back(Pair("proTxHash", dmnMembers[idx]->proTxHash.ToString()));
                }
                v.arr.push_back(a);
            }
        }
    };
    auto push = [&](ArrOrCount& v, const std::string& name) {
        if (detailLevel == 0) {
            ret.push_back(Pair(name, v.count));
        } else {
            ret.push_back(Pair(name, v.arr));
        }
    };

    for (size_t i = 0; i < members.size(); i++) {
        const auto& m = members[i];
        add(badMembers, i, m.debugStatus.status.bad);
        add(weComplain, i, m.debugStatus.status.weComplain);
        add(receivedContributions, i, m.debugStatus.status.receivedContribution);
        add(receivedComplaints, i, m.debugStatus.status.receivedComplaint);
        add(receivedJustifications, i, m.debugStatus.status.receivedJustification);
        add(receivedPrematureCommitments, i, m.debugStatus.status.receivedPrematureCommitment);
    }
    push(badMembers, "badMembers");
    push(weComplain, "weComplain");
    push(receivedContributions, "receivedContributions");
    push(receivedComplaints, "receivedComplaints");
    push(receivedJustifications, "receivedJustifications");
    push(receivedPrematureCommitments, "receivedPrematureCommitments");

    if (detailLevel == 2) {
        UniValue arr(UniValue::VARR);
        for (const auto& dmn : dmnMembers) {
            arr.push_back(dmn->proTxHash.ToString());
        }
        ret.push_back(Pair("allMembers", arr));
    }

    return ret;
}

CDKGDebugManager::CDKGDebugManager()
{
}

UniValue CDKGDebugStatus::ToJson(int detailLevel) const
{
    UniValue ret(UniValue::VOBJ);

    ret.push_back(Pair("time", nTime));
    ret.push_back(Pair("timeStr", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nTime)));

    UniValue sessionsJson(UniValue::VOBJ);
    for (const auto& p : sessions) {
        if (!Params().GetConsensus().llmqs.count((Consensus::LLMQType)p.first)) {
            continue;
        }
        const auto& params = Params().GetConsensus().llmqs.at((Consensus::LLMQType)p.first);
        sessionsJson.push_back(Pair(params.name, p.second.ToJson(detailLevel)));
    }

    ret.push_back(Pair("session", sessionsJson));

    return ret;
}

void CDKGDebugManager::GetLocalDebugStatus(llmq::CDKGDebugStatus& ret)
{
    LOCK(cs);
    ret = localStatus;
}

void CDKGDebugManager::ResetLocalSessionStatus(Consensus::LLMQType llmqType)
{
    LOCK(cs);

    auto it = localStatus.sessions.find(llmqType);
    if (it == localStatus.sessions.end()) {
        return;
    }

    localStatus.sessions.erase(it);
    localStatus.nTime = GetAdjustedTime();
}

void CDKGDebugManager::InitLocalSessionStatus(Consensus::LLMQType llmqType, const uint256& quorumHash, int quorumHeight)
{
    LOCK(cs);

    auto it = localStatus.sessions.find(llmqType);
    if (it == localStatus.sessions.end()) {
        it = localStatus.sessions.emplace((uint8_t)llmqType, CDKGDebugSessionStatus()).first;
    }

    auto& params = Params().GetConsensus().llmqs.at(llmqType);
    auto& session = it->second;
    session.llmqType = llmqType;
    session.quorumHash = quorumHash;
    session.quorumHeight = (uint32_t)quorumHeight;
    session.phase = 0;
    session.debugStatus.statusBitset = 0;
    session.members.clear();
    session.members.resize((size_t)params.size);
}

void CDKGDebugManager::UpdateLocalStatus(std::function<bool(CDKGDebugStatus& status)>&& func)
{
    LOCK(cs);
    if (func(localStatus)) {
        localStatus.nTime = GetAdjustedTime();
    }
}

void CDKGDebugManager::UpdateLocalSessionStatus(Consensus::LLMQType llmqType, std::function<bool(CDKGDebugSessionStatus& status)>&& func)
{
    LOCK(cs);

    auto it = localStatus.sessions.find(llmqType);
    if (it == localStatus.sessions.end()) {
        return;
    }

    if (func(it->second)) {
        localStatus.nTime = GetAdjustedTime();
    }
}

void CDKGDebugManager::UpdateLocalMemberStatus(Consensus::LLMQType llmqType, size_t memberIdx, std::function<bool(CDKGDebugMemberStatus& status)>&& func)
{
    LOCK(cs);

    auto it = localStatus.sessions.find(llmqType);
    if (it == localStatus.sessions.end()) {
        return;
    }

    if (func(it->second.members.at(memberIdx))) {
        localStatus.nTime = GetAdjustedTime();
    }
}

}
