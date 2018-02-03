// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activesmartnode.h"
#include "../addrman.h"
//#include "governance.h"
#include "../messagesigner.h"
#include "script/standard.h"
#include "smartnodepayments.h"
#include "smartnodesync.h"
#include "smartnodeman.h"
#include "netfulfilledman.h"
#include "../util.h"

/** Smartnode manager */
CSmartnodeMan mnodeman;

const std::string CSmartnodeMan::SERIALIZATION_VERSION_STRING = "CSmartnodeMan-Version-7";

struct CompareLastPaidBlock
{
    bool operator()(const std::pair<int, CSmartnode*>& t1,
                    const std::pair<int, CSmartnode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->vin < t2.second->vin);
    }
};

struct CompareScoreMN
{
    bool operator()(const std::pair<arith_uint256, CSmartnode*>& t1,
                    const std::pair<arith_uint256, CSmartnode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->vin < t2.second->vin);
    }
};

struct CompareByAddr

{
    bool operator()(const CSmartnode* t1,
                    const CSmartnode* t2) const
    {
        return t1->addr < t2->addr;
    }
};

CSmartnodeMan::CSmartnodeMan()
: cs(),
  mapSmartnodes(),
  mAskedUsForSmartnodeList(),
  mWeAskedForSmartnodeList(),
  mWeAskedForSmartnodeListEntry(),
  mWeAskedForVerification(),
  mMnbRecoveryRequests(),
  mMnbRecoveryGoodReplies(),
  listScheduledMnbRequestConnections(),
  fSmartnodesAdded(false),
  fSmartnodesRemoved(false),
  vecDirtyGovernanceObjectHashes(),
  nLastWatchdogVoteTime(0),
  mapSeenSmartnodeBroadcast(),
  mapSeenSmartnodePing(),
  nDsqCount(0)
{}

bool CSmartnodeMan::Add(CSmartnode &mn)
{
    LOCK(cs);

    if (Has(mn.vin.prevout)) return false;

    LogPrint("smartnode", "CSmartnodeMan::Add -- Adding new Smartnode: addr=%s, %i now\n", mn.addr.ToString(), size() + 1);
    mapSmartnodes[mn.vin.prevout] = mn;
    fSmartnodesAdded = true;
    return true;
}

void CSmartnodeMan::AskForMN(CNode* pnode, const COutPoint& outpoint, CConnman& connman)
{
    if(!pnode) return;

    LOCK(cs);

    std::map<COutPoint, std::map<CNetAddr, int64_t> >::iterator it1 = mWeAskedForSmartnodeListEntry.find(outpoint);
    if (it1 != mWeAskedForSmartnodeListEntry.end()) {
        std::map<CNetAddr, int64_t>::iterator it2 = it1->second.find(pnode->addr);
        if (it2 != it1->second.end()) {
            if (GetTime() < it2->second) {
                // we've asked recently, should not repeat too often or we could get banned
                return;
            }
            // we asked this node for this outpoint but it's ok to ask again already
            LogPrintf("CSmartnodeMan::AskForMN -- Asking same peer %s for missing smartnode entry again: %s\n", pnode->addr.ToString(), outpoint.ToStringShort());
        } else {
            // we already asked for this outpoint but not this node
            LogPrintf("CSmartnodeMan::AskForMN -- Asking new peer %s for missing smartnode entry: %s\n", pnode->addr.ToString(), outpoint.ToStringShort());
        }
    } else {
        // we never asked any node for this outpoint
        LogPrintf("CSmartnodeMan::AskForMN -- Asking peer %s for missing smartnode entry for the first time: %s\n", pnode->addr.ToString(), outpoint.ToStringShort());
    }
    mWeAskedForSmartnodeListEntry[outpoint][pnode->addr] = GetTime() + DSEG_UPDATE_SECONDS;

    connman.PushMessage(pnode, NetMsgType::DSEG, CTxIn(outpoint));
}

bool CSmartnodeMan::AllowMixing(const COutPoint &outpoint)
{
    LOCK(cs);
    CSmartnode* pmn = Find(outpoint);
    if (!pmn) {
        return false;
    }
    nDsqCount++;
    pmn->nLastDsq = nDsqCount;
    pmn->fAllowMixingTx = true;

    return true;
}

bool CSmartnodeMan::DisallowMixing(const COutPoint &outpoint)
{
    LOCK(cs);
    CSmartnode* pmn = Find(outpoint);
    if (!pmn) {
        return false;
    }
    pmn->fAllowMixingTx = false;

    return true;
}

bool CSmartnodeMan::PoSeBan(const COutPoint &outpoint)
{
    LOCK(cs);
    CSmartnode* pmn = Find(outpoint);
    if (!pmn) {
        return false;
    }
    pmn->PoSeBan();

    return true;
}

void CSmartnodeMan::Check()
{
    LOCK(cs);

    LogPrint("smartnode", "CSmartnodeMan::Check -- nLastWatchdogVoteTime=%d, IsWatchdogActive()=%d\n", nLastWatchdogVoteTime, IsWatchdogActive());

    for (auto& mnpair : mapSmartnodes) {
        mnpair.second.Check();
    }
}

void CSmartnodeMan::CheckAndRemove(CConnman& connman)
{
    if(!smartnodeSync.IsSmartnodeListSynced()) return;

    LogPrintf("CSmartnodeMan::CheckAndRemove\n");

    {
        // Need LOCK2 here to ensure consistent locking order because code below locks cs_main
        // in CheckMnbAndUpdateSmartnodeList()
        LOCK2(cs_main, cs);

        Check();

        // Remove spent smartnodes, prepare structures and make requests to reasure the state of inactive ones
        rank_pair_vec_t vecSmartnodeRanks;
        // ask for up to MNB_RECOVERY_MAX_ASK_ENTRIES smartnode entries at a time
        int nAskForMnbRecovery = MNB_RECOVERY_MAX_ASK_ENTRIES;
        std::map<COutPoint, CSmartnode>::iterator it = mapSmartnodes.begin();
        while (it != mapSmartnodes.end()) {
            CSmartnodeBroadcast mnb = CSmartnodeBroadcast(it->second);
            uint256 hash = mnb.GetHash();
            // If collateral was spent ...
            if (it->second.IsOutpointSpent()) {
                LogPrint("smartnode", "CSmartnodeMan::CheckAndRemove -- Removing Smartnode: %s  addr=%s  %i now\n", it->second.GetStateString(), it->second.addr.ToString(), size() - 1);

                // erase all of the broadcasts we've seen from this txin, ...
                mapSeenSmartnodeBroadcast.erase(hash);
                mWeAskedForSmartnodeListEntry.erase(it->first);

                // and finally remove it from the list
                it->second.FlagGovernanceItemsAsDirty();
                mapSmartnodes.erase(it++);
                fSmartnodesRemoved = true;
            } else {
                bool fAsk = (nAskForMnbRecovery > 0) &&
                            smartnodeSync.IsSynced() &&
                            it->second.IsNewStartRequired() &&
                            !IsMnbRecoveryRequested(hash);
                if(fAsk) {
                    // this mn is in a non-recoverable state and we haven't asked other nodes yet
                    std::set<CNetAddr> setRequested;
                    // calulate only once and only when it's needed
                    if(vecSmartnodeRanks.empty()) {
                        int nRandomBlockHeight = GetRandInt(nCachedBlockHeight);
                        GetSmartnodeRanks(vecSmartnodeRanks, nRandomBlockHeight);
                    }
                    bool fAskedForMnbRecovery = false;
                    // ask first MNB_RECOVERY_QUORUM_TOTAL smartnodes we can connect to and we haven't asked recently
                    for(int i = 0; setRequested.size() < MNB_RECOVERY_QUORUM_TOTAL && i < (int)vecSmartnodeRanks.size(); i++) {
                        // avoid banning
                        if(mWeAskedForSmartnodeListEntry.count(it->first) && mWeAskedForSmartnodeListEntry[it->first].count(vecSmartnodeRanks[i].second.addr)) continue;
                        // didn't ask recently, ok to ask now
                        CService addr = vecSmartnodeRanks[i].second.addr;
                        setRequested.insert(addr);
                        listScheduledMnbRequestConnections.push_back(std::make_pair(addr, hash));
                        fAskedForMnbRecovery = true;
                    }
                    if(fAskedForMnbRecovery) {
                        LogPrint("smartnode", "CSmartnodeMan::CheckAndRemove -- Recovery initiated, smartnode=%s\n", it->first.ToStringShort());
                        nAskForMnbRecovery--;
                    }
                    // wait for mnb recovery replies for MNB_RECOVERY_WAIT_SECONDS seconds
                    mMnbRecoveryRequests[hash] = std::make_pair(GetTime() + MNB_RECOVERY_WAIT_SECONDS, setRequested);
                }
                ++it;
            }
        }

        // proces replies for SMARTNODE_NEW_START_REQUIRED smartnodes
        LogPrint("smartnode", "CSmartnodeMan::CheckAndRemove -- mMnbRecoveryGoodReplies size=%d\n", (int)mMnbRecoveryGoodReplies.size());
        std::map<uint256, std::vector<CSmartnodeBroadcast> >::iterator itMnbReplies = mMnbRecoveryGoodReplies.begin();
        while(itMnbReplies != mMnbRecoveryGoodReplies.end()){
            if(mMnbRecoveryRequests[itMnbReplies->first].first < GetTime()) {
                // all nodes we asked should have replied now
                if(itMnbReplies->second.size() >= MNB_RECOVERY_QUORUM_REQUIRED) {
                    // majority of nodes we asked agrees that this mn doesn't require new mnb, reprocess one of new mnbs
                    LogPrint("smartnode", "CSmartnodeMan::CheckAndRemove -- reprocessing mnb, smartnode=%s\n", itMnbReplies->second[0].vin.prevout.ToStringShort());
                    // mapSeenSmartnodeBroadcast.erase(itMnbReplies->first);
                    int nDos;
                    itMnbReplies->second[0].fRecovery = true;
                    CheckMnbAndUpdateSmartnodeList(NULL, itMnbReplies->second[0], nDos, connman);
                }
                LogPrint("smartnode", "CSmartnodeMan::CheckAndRemove -- removing mnb recovery reply, smartnode=%s, size=%d\n", itMnbReplies->second[0].vin.prevout.ToStringShort(), (int)itMnbReplies->second.size());
                mMnbRecoveryGoodReplies.erase(itMnbReplies++);
            } else {
                ++itMnbReplies;
            }
        }
    }
    {
        // no need for cm_main below
        LOCK(cs);

        std::map<uint256, std::pair< int64_t, std::set<CNetAddr> > >::iterator itMnbRequest = mMnbRecoveryRequests.begin();
        while(itMnbRequest != mMnbRecoveryRequests.end()){
            // Allow this mnb to be re-verified again after MNB_RECOVERY_RETRY_SECONDS seconds
            // if mn is still in SMARTNODE_NEW_START_REQUIRED state.
            if(GetTime() - itMnbRequest->second.first > MNB_RECOVERY_RETRY_SECONDS) {
                mMnbRecoveryRequests.erase(itMnbRequest++);
            } else {
                ++itMnbRequest;
            }
        }

        // check who's asked for the Smartnode list
        std::map<CNetAddr, int64_t>::iterator it1 = mAskedUsForSmartnodeList.begin();
        while(it1 != mAskedUsForSmartnodeList.end()){
            if((*it1).second < GetTime()) {
                mAskedUsForSmartnodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check who we asked for the Smartnode list
        it1 = mWeAskedForSmartnodeList.begin();
        while(it1 != mWeAskedForSmartnodeList.end()){
            if((*it1).second < GetTime()){
                mWeAskedForSmartnodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check which Smartnodes we've asked for
        std::map<COutPoint, std::map<CNetAddr, int64_t> >::iterator it2 = mWeAskedForSmartnodeListEntry.begin();
        while(it2 != mWeAskedForSmartnodeListEntry.end()){
            std::map<CNetAddr, int64_t>::iterator it3 = it2->second.begin();
            while(it3 != it2->second.end()){
                if(it3->second < GetTime()){
                    it2->second.erase(it3++);
                } else {
                    ++it3;
                }
            }
            if(it2->second.empty()) {
                mWeAskedForSmartnodeListEntry.erase(it2++);
            } else {
                ++it2;
            }
        }

        std::map<CNetAddr, CSmartnodeVerification>::iterator it3 = mWeAskedForVerification.begin();
        while(it3 != mWeAskedForVerification.end()){
            if(it3->second.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS) {
                mWeAskedForVerification.erase(it3++);
            } else {
                ++it3;
            }
        }

        // NOTE: do not expire mapSeenSmartnodeBroadcast entries here, clean them on mnb updates!

        // remove expired mapSeenSmartnodePing
        std::map<uint256, CSmartnodePing>::iterator it4 = mapSeenSmartnodePing.begin();
        while(it4 != mapSeenSmartnodePing.end()){
            if((*it4).second.IsExpired()) {
                LogPrint("smartnode", "CSmartnodeMan::CheckAndRemove -- Removing expired Smartnode ping: hash=%s\n", (*it4).second.GetHash().ToString());
                mapSeenSmartnodePing.erase(it4++);
            } else {
                ++it4;
            }
        }

        // remove expired mapSeenSmartnodeVerification
        std::map<uint256, CSmartnodeVerification>::iterator itv2 = mapSeenSmartnodeVerification.begin();
        while(itv2 != mapSeenSmartnodeVerification.end()){
            if((*itv2).second.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS){
                LogPrint("smartnode", "CSmartnodeMan::CheckAndRemove -- Removing expired Smartnode verification: hash=%s\n", (*itv2).first.ToString());
                mapSeenSmartnodeVerification.erase(itv2++);
            } else {
                ++itv2;
            }
        }

        LogPrintf("CSmartnodeMan::CheckAndRemove -- %s\n", ToString());
    }

    if(fSmartnodesRemoved) {
        NotifySmartnodeUpdates(connman);
    }
}

void CSmartnodeMan::Clear()
{
    LOCK(cs);
    mapSmartnodes.clear();
    mAskedUsForSmartnodeList.clear();
    mWeAskedForSmartnodeList.clear();
    mWeAskedForSmartnodeListEntry.clear();
    mapSeenSmartnodeBroadcast.clear();
    mapSeenSmartnodePing.clear();
    nDsqCount = 0;
    nLastWatchdogVoteTime = 0;
}

int CSmartnodeMan::CountSmartnodes(int nProtocolVersion)
{
    LOCK(cs);
    int nCount = 0;
    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinSmartnodePaymentsProto() : nProtocolVersion;

    for (auto& mnpair : mapSmartnodes) {
        if(mnpair.second.nProtocolVersion < nProtocolVersion) continue;
        nCount++;
    }

    return nCount;
}

int CSmartnodeMan::CountEnabled(int nProtocolVersion)
{
    LOCK(cs);
    int nCount = 0;
    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinSmartnodePaymentsProto() : nProtocolVersion;

    for (auto& mnpair : mapSmartnodes) {
        if(mnpair.second.nProtocolVersion < nProtocolVersion || !mnpair.second.IsEnabled()) continue;
        nCount++;
    }

    return nCount;
}

/* Only IPv4 smartnodes are allowed in 12.1, saving this for later
int CSmartnodeMan::CountByIP(int nNetworkType)
{
    LOCK(cs);
    int nNodeCount = 0;

    for (auto& mnpair : mapSmartnodes)
        if ((nNetworkType == NET_IPV4 && mnpair.second.addr.IsIPv4()) ||
            (nNetworkType == NET_TOR  && mnpair.second.addr.IsTor())  ||
            (nNetworkType == NET_IPV6 && mnpair.second.addr.IsIPv6())) {
                nNodeCount++;
        }

    return nNodeCount;
}
*/

void CSmartnodeMan::DsegUpdate(CNode* pnode, CConnman& connman)
{
    LOCK(cs);

    if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if(!(pnode->addr.IsRFC1918() || pnode->addr.IsLocal())) {
            std::map<CNetAddr, int64_t>::iterator it = mWeAskedForSmartnodeList.find(pnode->addr);
            if(it != mWeAskedForSmartnodeList.end() && GetTime() < (*it).second) {
                LogPrintf("CSmartnodeMan::DsegUpdate -- we already asked %s for the list; skipping...\n", pnode->addr.ToString());
                return;
            }
        }
    }

    connman.PushMessage(pnode, NetMsgType::DSEG, CTxIn());
    int64_t askAgain = GetTime() + DSEG_UPDATE_SECONDS;
    mWeAskedForSmartnodeList[pnode->addr] = askAgain;

    LogPrint("smartnode", "CSmartnodeMan::DsegUpdate -- asked %s for the list\n", pnode->addr.ToString());
}

CSmartnode* CSmartnodeMan::Find(const COutPoint &outpoint)
{
    LOCK(cs);
    auto it = mapSmartnodes.find(outpoint);
    return it == mapSmartnodes.end() ? NULL : &(it->second);
}

bool CSmartnodeMan::Get(const COutPoint& outpoint, CSmartnode& smartnodeRet)
{
    // Theses mutexes are recursive so double locking by the same thread is safe.
    LOCK(cs);
    auto it = mapSmartnodes.find(outpoint);
    if (it == mapSmartnodes.end()) {
        return false;
    }

    smartnodeRet = it->second;
    return true;
}

bool CSmartnodeMan::GetSmartnodeInfo(const COutPoint& outpoint, smartnode_info_t& mnInfoRet)
{
    LOCK(cs);
    auto it = mapSmartnodes.find(outpoint);
    if (it == mapSmartnodes.end()) {
        return false;
    }
    mnInfoRet = it->second.GetInfo();
    return true;
}

bool CSmartnodeMan::GetSmartnodeInfo(const CPubKey& pubKeySmartnode, smartnode_info_t& mnInfoRet)
{
    LOCK(cs);
    for (auto& mnpair : mapSmartnodes) {
        if (mnpair.second.pubKeySmartnode == pubKeySmartnode) {
            mnInfoRet = mnpair.second.GetInfo();
            return true;
        }
    }
    return false;
}

bool CSmartnodeMan::GetSmartnodeInfo(const CScript& payee, smartnode_info_t& mnInfoRet)
{
    LOCK(cs);
    for (auto& mnpair : mapSmartnodes) {
        CScript scriptCollateralAddress = GetScriptForDestination(mnpair.second.pubKeyCollateralAddress.GetID());
        if (scriptCollateralAddress == payee) {
            mnInfoRet = mnpair.second.GetInfo();
            return true;
        }
    }
    return false;
}

bool CSmartnodeMan::Has(const COutPoint& outpoint)
{
    LOCK(cs);
    return mapSmartnodes.find(outpoint) != mapSmartnodes.end();
}

//
// Deterministically select the oldest/best smartnode to pay on the network
//
bool CSmartnodeMan::GetNextSmartnodeInQueueForPayment(bool fFilterSigTime, int& nCountRet, smartnode_info_t& mnInfoRet)
{
    return GetNextSmartnodeInQueueForPayment(nCachedBlockHeight, fFilterSigTime, nCountRet, mnInfoRet);
}

bool CSmartnodeMan::GetNextSmartnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCountRet, smartnode_info_t& mnInfoRet)
{
    mnInfoRet = smartnode_info_t();
    nCountRet = 0;

    if (!smartnodeSync.IsWinnersListSynced()) {
        // without winner list we can't reliably find the next winner anyway
        return false;
    }

    // Need LOCK2 here to ensure consistent locking order because the GetBlockHash call below locks cs_main
    LOCK2(cs_main,cs);

    std::vector<std::pair<int, CSmartnode*> > vecSmartnodeLastPaid;

    /*
        Make a vector with all of the last paid times
    */

    int nMnCount = CountSmartnodes();

    for (auto& mnpair : mapSmartnodes) {
        if(!mnpair.second.IsValidForPayment()) continue;

        //check protocol version
        if(mnpair.second.nProtocolVersion < mnpayments.GetMinSmartnodePaymentsProto()) continue;

        //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
        if(mnpayments.IsScheduled(mnpair.second, nBlockHeight)) continue;

        //it's too new, wait for a cycle
        if(fFilterSigTime && mnpair.second.sigTime + (nMnCount*55) > GetAdjustedTime()) continue;

        //make sure it has at least as many confirmations as there are smartnodes
        if(GetUTXOConfirmations(mnpair.first) < nMnCount) continue;

        vecSmartnodeLastPaid.push_back(std::make_pair(mnpair.second.GetLastPaidBlock(), &mnpair.second));
    }

    nCountRet = (int)vecSmartnodeLastPaid.size();

    //when the network is in the process of upgrading, don't penalize nodes that recently restarted
    if(fFilterSigTime && nCountRet < nMnCount/3)
        return GetNextSmartnodeInQueueForPayment(nBlockHeight, false, nCountRet, mnInfoRet);

    // Sort them low to high
    sort(vecSmartnodeLastPaid.begin(), vecSmartnodeLastPaid.end(), CompareLastPaidBlock());

    uint256 blockHash;
    if(!GetBlockHash(blockHash, nBlockHeight - 101)) {
        LogPrintf("CSmartnode::GetNextSmartnodeInQueueForPayment -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", nBlockHeight - 101);
        return false;
    }
    // Look at 1/10 of the oldest nodes (by last payment), calculate their scores and pay the best one
    //  -- This doesn't look at who is being paid in the +8-10 blocks, allowing for double payments very rarely
    //  -- 1/100 payments should be a double payment on mainnet - (1/(3000/10))*2
    //  -- (chance per block * chances before IsScheduled will fire)
    int nTenthNetwork = nMnCount/10;
    int nCountTenth = 0;
    arith_uint256 nHighest = 0;
    CSmartnode *pBestSmartnode = NULL;
    BOOST_FOREACH (PAIRTYPE(int, CSmartnode*)& s, vecSmartnodeLastPaid){
        arith_uint256 nScore = s.second->CalculateScore(blockHash);
        if(nScore > nHighest){
            nHighest = nScore;
            pBestSmartnode = s.second;
        }
        nCountTenth++;
        if(nCountTenth >= nTenthNetwork) break;
    }
    if (pBestSmartnode) {
        mnInfoRet = pBestSmartnode->GetInfo();
    }
    return mnInfoRet.fInfoValid;
}

smartnode_info_t CSmartnodeMan::FindRandomNotInVec(const std::vector<COutPoint> &vecToExclude, int nProtocolVersion)
{
    LOCK(cs);

    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinSmartnodePaymentsProto() : nProtocolVersion;

    int nCountEnabled = CountEnabled(nProtocolVersion);
    int nCountNotExcluded = nCountEnabled - vecToExclude.size();

    LogPrintf("CSmartnodeMan::FindRandomNotInVec -- %d enabled smartnodes, %d smartnodes to choose from\n", nCountEnabled, nCountNotExcluded);
    if(nCountNotExcluded < 1) return smartnode_info_t();

    // fill a vector of pointers
    std::vector<CSmartnode*> vpSmartnodesShuffled;
    for (auto& mnpair : mapSmartnodes) {
        vpSmartnodesShuffled.push_back(&mnpair.second);
    }

    InsecureRand insecureRand;
    // shuffle pointers
    std::random_shuffle(vpSmartnodesShuffled.begin(), vpSmartnodesShuffled.end(), insecureRand);
    bool fExclude;

    // loop through
    BOOST_FOREACH(CSmartnode* pmn, vpSmartnodesShuffled) {
        if(pmn->nProtocolVersion < nProtocolVersion || !pmn->IsEnabled()) continue;
        fExclude = false;
        BOOST_FOREACH(const COutPoint &outpointToExclude, vecToExclude) {
            if(pmn->vin.prevout == outpointToExclude) {
                fExclude = true;
                break;
            }
        }
        if(fExclude) continue;
        // found the one not in vecToExclude
        LogPrint("smartnode", "CSmartnodeMan::FindRandomNotInVec -- found, smartnode=%s\n", pmn->vin.prevout.ToStringShort());
        return pmn->GetInfo();
    }

    LogPrint("smartnode", "CSmartnodeMan::FindRandomNotInVec -- failed\n");
    return smartnode_info_t();
}

bool CSmartnodeMan::GetSmartnodeScores(const uint256& nBlockHash, CSmartnodeMan::score_pair_vec_t& vecSmartnodeScoresRet, int nMinProtocol)
{
    vecSmartnodeScoresRet.clear();

    if (!smartnodeSync.IsSmartnodeListSynced())
        return false;

    AssertLockHeld(cs);

    if (mapSmartnodes.empty())
        return false;

    // calculate scores
    for (auto& mnpair : mapSmartnodes) {
        if (mnpair.second.nProtocolVersion >= nMinProtocol) {
            vecSmartnodeScoresRet.push_back(std::make_pair(mnpair.second.CalculateScore(nBlockHash), &mnpair.second));
        }
    }

    sort(vecSmartnodeScoresRet.rbegin(), vecSmartnodeScoresRet.rend(), CompareScoreMN());
    return !vecSmartnodeScoresRet.empty();
}

bool CSmartnodeMan::GetSmartnodeRank(const COutPoint& outpoint, int& nRankRet, int nBlockHeight, int nMinProtocol)
{
    nRankRet = -1;

    if (!smartnodeSync.IsSmartnodeListSynced())
        return false;

    // make sure we know about this block
    uint256 nBlockHash = uint256();
    if (!GetBlockHash(nBlockHash, nBlockHeight)) {
        LogPrintf("CSmartnodeMan::%s -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", __func__, nBlockHeight);
        return false;
    }

    LOCK(cs);

    score_pair_vec_t vecSmartnodeScores;
    if (!GetSmartnodeScores(nBlockHash, vecSmartnodeScores, nMinProtocol))
        return false;

    int nRank = 0;
    for (auto& scorePair : vecSmartnodeScores) {
        nRank++;
        if(scorePair.second->vin.prevout == outpoint) {
            nRankRet = nRank;
            return true;
        }
    }

    return false;
}

bool CSmartnodeMan::GetSmartnodeRanks(CSmartnodeMan::rank_pair_vec_t& vecSmartnodeRanksRet, int nBlockHeight, int nMinProtocol)
{
    vecSmartnodeRanksRet.clear();

    if (!smartnodeSync.IsSmartnodeListSynced())
        return false;

    // make sure we know about this block
    uint256 nBlockHash = uint256();
    if (!GetBlockHash(nBlockHash, nBlockHeight)) {
        LogPrintf("CSmartnodeMan::%s -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", __func__, nBlockHeight);
        return false;
    }

    LOCK(cs);

    score_pair_vec_t vecSmartnodeScores;
    if (!GetSmartnodeScores(nBlockHash, vecSmartnodeScores, nMinProtocol))
        return false;

    int nRank = 0;
    for (auto& scorePair : vecSmartnodeScores) {
        nRank++;
        vecSmartnodeRanksRet.push_back(std::make_pair(nRank, *scorePair.second));
    }

    return true;
}

void CSmartnodeMan::ProcessSmartnodeConnections(CConnman& connman)
{
    //we don't care about this for regtest
    if(Params().NetworkIDString() == CBaseChainParams::REGTEST) return;

    connman.ForEachNode(CConnman::AllNodes, [](CNode* pnode) {
//#ifdef ENABLE_WALLET
//        if(pnode->fSmartnode && !privateSendClient.IsMixingSmartnode(pnode)) {
//#else
        if(pnode->fSmartnode) {
//#endif // ENABLE_WALLET
            LogPrintf("Closing Smartnode connection: peer=%d, addr=%s\n", pnode->id, pnode->addr.ToString());
            pnode->fDisconnect = true;
        }
    });
}

std::pair<CService, std::set<uint256> > CSmartnodeMan::PopScheduledMnbRequestConnection()
{
    LOCK(cs);
    if(listScheduledMnbRequestConnections.empty()) {
        return std::make_pair(CService(), std::set<uint256>());
    }

    std::set<uint256> setResult;

    listScheduledMnbRequestConnections.sort();
    std::pair<CService, uint256> pairFront = listScheduledMnbRequestConnections.front();

    // squash hashes from requests with the same CService as the first one into setResult
    std::list< std::pair<CService, uint256> >::iterator it = listScheduledMnbRequestConnections.begin();
    while(it != listScheduledMnbRequestConnections.end()) {
        if(pairFront.first == it->first) {
            setResult.insert(it->second);
            it = listScheduledMnbRequestConnections.erase(it);
        } else {
            // since list is sorted now, we can be sure that there is no more hashes left
            // to ask for from this addr
            break;
        }
    }
    return std::make_pair(pairFront.first, setResult);
}


void CSmartnodeMan::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv, CConnman& connman)
{
    if(fLiteMode) return; // disable all Smartcash specific functionality

    if (strCommand == NetMsgType::MNANNOUNCE) { //Smartnode Broadcast

        CSmartnodeBroadcast mnb;
        vRecv >> mnb;

        pfrom->setAskFor.erase(mnb.GetHash());

        if(!smartnodeSync.IsBlockchainSynced()) return;

        LogPrint("smartnode", "MNANNOUNCE -- Smartnode announce, smartnode=%s\n", mnb.vin.prevout.ToStringShort());

        int nDos = 0;

        if (CheckMnbAndUpdateSmartnodeList(pfrom, mnb, nDos, connman)) {
            // use announced Smartnode as a peer
            connman.AddNewAddress(CAddress(mnb.addr, NODE_NETWORK), pfrom->addr, 2*60*60);
        } else if(nDos > 0) {
            Misbehaving(pfrom->GetId(), nDos);
        }

        if(fSmartnodesAdded) {
            NotifySmartnodeUpdates(connman);
        }
    } else if (strCommand == NetMsgType::MNPING) { //Smartnode Ping

        CSmartnodePing mnp;
        vRecv >> mnp;

        uint256 nHash = mnp.GetHash();

        pfrom->setAskFor.erase(nHash);

        if(!smartnodeSync.IsBlockchainSynced()) return;

        LogPrint("smartnode", "MNPING -- Smartnode ping, smartnode=%s\n", mnp.vin.prevout.ToStringShort());

        // Need LOCK2 here to ensure consistent locking order because the CheckAndUpdate call below locks cs_main
        LOCK2(cs_main, cs);

        if(mapSeenSmartnodePing.count(nHash)) return; //seen
        mapSeenSmartnodePing.insert(std::make_pair(nHash, mnp));

        LogPrint("smartnode", "MNPING -- Smartnode ping, smartnode=%s new\n", mnp.vin.prevout.ToStringShort());

        // see if we have this Smartnode
        CSmartnode* pmn = Find(mnp.vin.prevout);

        // if smartnode uses sentinel ping instead of watchdog
        // we shoud update nTimeLastWatchdogVote here if sentinel
        // ping flag is actual
        if(pmn && mnp.fSentinelIsCurrent)
            UpdateWatchdogVoteTime(mnp.vin.prevout, mnp.sigTime);

        // too late, new MNANNOUNCE is required
        if(pmn && pmn->IsNewStartRequired()) return;

        int nDos = 0;
        if(mnp.CheckAndUpdate(pmn, false, nDos, connman)) return;

        if(nDos > 0) {
            // if anything significant failed, mark that node
            Misbehaving(pfrom->GetId(), nDos);
        } else if(pmn != NULL) {
            // nothing significant failed, mn is a known one too
            return;
        }

        // something significant is broken or mn is unknown,
        // we might have to ask for a smartnode entry once
        AskForMN(pfrom, mnp.vin.prevout, connman);

    } else if (strCommand == NetMsgType::DSEG) { //Get Smartnode list or specific entry
        // Ignore such requests until we are fully synced.
        // We could start processing this after smartnode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!smartnodeSync.IsSynced()) return;

        CTxIn vin;
        vRecv >> vin;

        LogPrint("smartnode", "DSEG -- Smartnode list, smartnode=%s\n", vin.prevout.ToStringShort());

        LOCK(cs);

        if(vin == CTxIn()) { //only should ask for this once
            //local network
            bool isLocal = (pfrom->addr.IsRFC1918() || pfrom->addr.IsLocal());

            if(!isLocal && Params().NetworkIDString() == CBaseChainParams::MAIN) {
                std::map<CNetAddr, int64_t>::iterator it = mAskedUsForSmartnodeList.find(pfrom->addr);
                if (it != mAskedUsForSmartnodeList.end() && it->second > GetTime()) {
                    Misbehaving(pfrom->GetId(), 34);
                    LogPrintf("DSEG -- peer already asked me for the list, peer=%d\n", pfrom->id);
                    return;
                }
                int64_t askAgain = GetTime() + DSEG_UPDATE_SECONDS;
                mAskedUsForSmartnodeList[pfrom->addr] = askAgain;
            }
        } //else, asking for a specific node which is ok

        int nInvCount = 0;

        for (auto& mnpair : mapSmartnodes) {
            if (vin != CTxIn() && vin != mnpair.second.vin) continue; // asked for specific vin but we are not there yet
            if (mnpair.second.addr.IsRFC1918() || mnpair.second.addr.IsLocal()) continue; // do not send local network smartnode
            if (mnpair.second.IsUpdateRequired()) continue; // do not send outdated smartnodes

            LogPrint("smartnode", "DSEG -- Sending Smartnode entry: smartnode=%s  addr=%s\n", mnpair.first.ToStringShort(), mnpair.second.addr.ToString());
            CSmartnodeBroadcast mnb = CSmartnodeBroadcast(mnpair.second);
            CSmartnodePing mnp = mnpair.second.lastPing;
            uint256 hashMNB = mnb.GetHash();
            uint256 hashMNP = mnp.GetHash();
            pfrom->PushInventory(CInv(MSG_SMARTNODE_ANNOUNCE, hashMNB));
            pfrom->PushInventory(CInv(MSG_SMARTNODE_PING, hashMNP));
            nInvCount++;

            mapSeenSmartnodeBroadcast.insert(std::make_pair(hashMNB, std::make_pair(GetTime(), mnb)));
            mapSeenSmartnodePing.insert(std::make_pair(hashMNP, mnp));

            if (vin.prevout == mnpair.first) {
                LogPrintf("DSEG -- Sent 1 Smartnode inv to peer %d\n", pfrom->id);
                return;
            }
        }

        if(vin == CTxIn()) {
            connman.PushMessage(pfrom, NetMsgType::SYNCSTATUSCOUNT, SMARTNODE_SYNC_LIST, nInvCount);
            LogPrintf("DSEG -- Sent %d Smartnode invs to peer %d\n", nInvCount, pfrom->id);
            return;
        }
        // smth weird happen - someone asked us for vin we have no idea about?
        LogPrint("smartnode", "DSEG -- No invs sent to peer %d\n", pfrom->id);

    } else if (strCommand == NetMsgType::MNVERIFY) { // Smartnode Verify

        // Need LOCK2 here to ensure consistent locking order because the all functions below call GetBlockHash which locks cs_main
        LOCK2(cs_main, cs);

        CSmartnodeVerification mnv;
        vRecv >> mnv;

        pfrom->setAskFor.erase(mnv.GetHash());

        if(!smartnodeSync.IsSmartnodeListSynced()) return;

        if(mnv.vchSig1.empty()) {
            // CASE 1: someone asked me to verify myself /IP we are using/
            SendVerifyReply(pfrom, mnv, connman);
        } else if (mnv.vchSig2.empty()) {
            // CASE 2: we _probably_ got verification we requested from some smartnode
            ProcessVerifyReply(pfrom, mnv);
        } else {
            // CASE 3: we _probably_ got verification broadcast signed by some smartnode which verified another one
            ProcessVerifyBroadcast(pfrom, mnv);
        }
    }
}

// Verification of smartnodes via unique direct requests.

void CSmartnodeMan::DoFullVerificationStep(CConnman& connman)
{
    if(activeSmartnode.outpoint == COutPoint()) return;
    if(!smartnodeSync.IsSynced()) return;

    rank_pair_vec_t vecSmartnodeRanks;
    GetSmartnodeRanks(vecSmartnodeRanks, nCachedBlockHeight - 1, MIN_POSE_PROTO_VERSION);

    // Need LOCK2 here to ensure consistent locking order because the SendVerifyRequest call below locks cs_main
    // through GetHeight() signal in ConnectNode
    LOCK2(cs_main, cs);

    int nCount = 0;

    int nMyRank = -1;
    int nRanksTotal = (int)vecSmartnodeRanks.size();

    // send verify requests only if we are in top MAX_POSE_RANK
    std::vector<std::pair<int, CSmartnode> >::iterator it = vecSmartnodeRanks.begin();
    while(it != vecSmartnodeRanks.end()) {
        if(it->first > MAX_POSE_RANK) {
            LogPrint("smartnode", "CSmartnodeMan::DoFullVerificationStep -- Must be in top %d to send verify request\n",
                        (int)MAX_POSE_RANK);
            return;
        }
        if(it->second.vin.prevout == activeSmartnode.outpoint) {
            nMyRank = it->first;
            LogPrint("smartnode", "CSmartnodeMan::DoFullVerificationStep -- Found self at rank %d/%d, verifying up to %d smartnodes\n",
                        nMyRank, nRanksTotal, (int)MAX_POSE_CONNECTIONS);
            break;
        }
        ++it;
    }

    // edge case: list is too short and this smartnode is not enabled
    if(nMyRank == -1) return;

    // send verify requests to up to MAX_POSE_CONNECTIONS smartnodes
    // starting from MAX_POSE_RANK + nMyRank and using MAX_POSE_CONNECTIONS as a step
    int nOffset = MAX_POSE_RANK + nMyRank - 1;
    if(nOffset >= (int)vecSmartnodeRanks.size()) return;

    std::vector<CSmartnode*> vSortedByAddr;
    for (auto& mnpair : mapSmartnodes) {
        vSortedByAddr.push_back(&mnpair.second);
    }

    sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

    it = vecSmartnodeRanks.begin() + nOffset;
    while(it != vecSmartnodeRanks.end()) {
        if(it->second.IsPoSeVerified() || it->second.IsPoSeBanned()) {
            LogPrint("smartnode", "CSmartnodeMan::DoFullVerificationStep -- Already %s%s%s smartnode %s address %s, skipping...\n",
                        it->second.IsPoSeVerified() ? "verified" : "",
                        it->second.IsPoSeVerified() && it->second.IsPoSeBanned() ? " and " : "",
                        it->second.IsPoSeBanned() ? "banned" : "",
                        it->second.vin.prevout.ToStringShort(), it->second.addr.ToString());
            nOffset += MAX_POSE_CONNECTIONS;
            if(nOffset >= (int)vecSmartnodeRanks.size()) break;
            it += MAX_POSE_CONNECTIONS;
            continue;
        }
        LogPrint("smartnode", "CSmartnodeMan::DoFullVerificationStep -- Verifying smartnode %s rank %d/%d address %s\n",
                    it->second.vin.prevout.ToStringShort(), it->first, nRanksTotal, it->second.addr.ToString());
        if(SendVerifyRequest(CAddress(it->second.addr, NODE_NETWORK), vSortedByAddr, connman)) {
            nCount++;
            if(nCount >= MAX_POSE_CONNECTIONS) break;
        }
        nOffset += MAX_POSE_CONNECTIONS;
        if(nOffset >= (int)vecSmartnodeRanks.size()) break;
        it += MAX_POSE_CONNECTIONS;
    }

    LogPrint("smartnode", "CSmartnodeMan::DoFullVerificationStep -- Sent verification requests to %d smartnodes\n", nCount);
}

// This function tries to find smartnodes with the same addr,
// find a verified one and ban all the other. If there are many nodes
// with the same addr but none of them is verified yet, then none of them are banned.
// It could take many times to run this before most of the duplicate nodes are banned.

void CSmartnodeMan::CheckSameAddr()
{
    if(!smartnodeSync.IsSynced() || mapSmartnodes.empty()) return;

    std::vector<CSmartnode*> vBan;
    std::vector<CSmartnode*> vSortedByAddr;

    {
        LOCK(cs);

        CSmartnode* pprevSmartnode = NULL;
        CSmartnode* pverifiedSmartnode = NULL;

        for (auto& mnpair : mapSmartnodes) {
            vSortedByAddr.push_back(&mnpair.second);
        }

        sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

        BOOST_FOREACH(CSmartnode* pmn, vSortedByAddr) {
            // check only (pre)enabled smartnodes
            if(!pmn->IsEnabled() && !pmn->IsPreEnabled()) continue;
            // initial step
            if(!pprevSmartnode) {
                pprevSmartnode = pmn;
                pverifiedSmartnode = pmn->IsPoSeVerified() ? pmn : NULL;
                continue;
            }
            // second+ step
            if(pmn->addr == pprevSmartnode->addr) {
                if(pverifiedSmartnode) {
                    // another smartnode with the same ip is verified, ban this one
                    vBan.push_back(pmn);
                } else if(pmn->IsPoSeVerified()) {
                    // this smartnode with the same ip is verified, ban previous one
                    vBan.push_back(pprevSmartnode);
                    // and keep a reference to be able to ban following smartnodes with the same ip
                    pverifiedSmartnode = pmn;
                }
            } else {
                pverifiedSmartnode = pmn->IsPoSeVerified() ? pmn : NULL;
            }
            pprevSmartnode = pmn;
        }
    }

    // ban duplicates
    BOOST_FOREACH(CSmartnode* pmn, vBan) {
        LogPrintf("CSmartnodeMan::CheckSameAddr -- increasing PoSe ban score for smartnode %s\n", pmn->vin.prevout.ToStringShort());
        pmn->IncreasePoSeBanScore();
    }
}

bool CSmartnodeMan::SendVerifyRequest(const CAddress& addr, const std::vector<CSmartnode*>& vSortedByAddr, CConnman& connman)
{
    if(netfulfilledman.HasFulfilledRequest(addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request")) {
        // we already asked for verification, not a good idea to do this too often, skip it
        LogPrint("smartnode", "CSmartnodeMan::SendVerifyRequest -- too many requests, skipping... addr=%s\n", addr.ToString());
        return false;
    }

    CNode* pnode = connman.ConnectNode(addr, NULL, true);
    if(pnode == NULL) {
        LogPrintf("CSmartnodeMan::SendVerifyRequest -- can't connect to node to verify it, addr=%s\n", addr.ToString());
        return false;
    }

    netfulfilledman.AddFulfilledRequest(addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request");
    // use random nonce, store it and require node to reply with correct one later
    CSmartnodeVerification mnv(addr, GetRandInt(999999), nCachedBlockHeight - 1);
    mWeAskedForVerification[addr] = mnv;
    LogPrintf("CSmartnodeMan::SendVerifyRequest -- verifying node using nonce %d addr=%s\n", mnv.nonce, addr.ToString());
    connman.PushMessage(pnode, NetMsgType::MNVERIFY, mnv);

    return true;
}

void CSmartnodeMan::SendVerifyReply(CNode* pnode, CSmartnodeVerification& mnv, CConnman& connman)
{
    // only smartnodes can sign this, why would someone ask regular node?
    if(!fSmartNode) {
        // do not ban, malicious node might be using my IP
        // and trying to confuse the node which tries to verify it
        return;
    }

    if(netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-reply")) {
        // peer should not ask us that often
        LogPrintf("SmartnodeMan::SendVerifyReply -- ERROR: peer already asked me recently, peer=%d\n", pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        LogPrintf("SmartnodeMan::SendVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->id);
        return;
    }

    std::string strMessage = strprintf("%s%d%s", activeSmartnode.service.ToString(false), mnv.nonce, blockHash.ToString());

    if(!CMessageSigner::SignMessage(strMessage, mnv.vchSig1, activeSmartnode.keySmartnode)) {
        LogPrintf("SmartnodeMan::SendVerifyReply -- SignMessage() failed\n");
        return;
    }

    std::string strError;

    if(!CMessageSigner::VerifyMessage(activeSmartnode.pubKeySmartnode, mnv.vchSig1, strMessage, strError)) {
        LogPrintf("SmartnodeMan::SendVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
        return;
    }

    connman.PushMessage(pnode, NetMsgType::MNVERIFY, mnv);
    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-reply");
}

void CSmartnodeMan::ProcessVerifyReply(CNode* pnode, CSmartnodeVerification& mnv)
{
    std::string strError;

    // did we even ask for it? if that's the case we should have matching fulfilled request
    if(!netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request")) {
        LogPrintf("CSmartnodeMan::ProcessVerifyReply -- ERROR: we didn't ask for verification of %s, peer=%d\n", pnode->addr.ToString(), pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    // Received nonce for a known address must match the one we sent
    if(mWeAskedForVerification[pnode->addr].nonce != mnv.nonce) {
        LogPrintf("CSmartnodeMan::ProcessVerifyReply -- ERROR: wrong nounce: requested=%d, received=%d, peer=%d\n",
                    mWeAskedForVerification[pnode->addr].nonce, mnv.nonce, pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    // Received nBlockHeight for a known address must match the one we sent
    if(mWeAskedForVerification[pnode->addr].nBlockHeight != mnv.nBlockHeight) {
        LogPrintf("CSmartnodeMan::ProcessVerifyReply -- ERROR: wrong nBlockHeight: requested=%d, received=%d, peer=%d\n",
                    mWeAskedForVerification[pnode->addr].nBlockHeight, mnv.nBlockHeight, pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        // this shouldn't happen...
        LogPrintf("SmartnodeMan::ProcessVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->id);
        return;
    }

    // we already verified this address, why node is spamming?
    if(netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-done")) {
        LogPrintf("CSmartnodeMan::ProcessVerifyReply -- ERROR: already verified %s recently\n", pnode->addr.ToString());
        Misbehaving(pnode->id, 20);
        return;
    }

    {
        LOCK(cs);

        CSmartnode* prealSmartnode = NULL;
        std::vector<CSmartnode*> vpSmartnodesToBan;
        std::string strMessage1 = strprintf("%s%d%s", pnode->addr.ToString(false), mnv.nonce, blockHash.ToString());
        for (auto& mnpair : mapSmartnodes) {
            if(CAddress(mnpair.second.addr, NODE_NETWORK) == pnode->addr) {
                if(CMessageSigner::VerifyMessage(mnpair.second.pubKeySmartnode, mnv.vchSig1, strMessage1, strError)) {
                    // found it!
                    prealSmartnode = &mnpair.second;
                    if(!mnpair.second.IsPoSeVerified()) {
                        mnpair.second.DecreasePoSeBanScore();
                    }
                    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-done");

                    // we can only broadcast it if we are an activated smartnode
                    if(activeSmartnode.outpoint == COutPoint()) continue;
                    // update ...
                    mnv.addr = mnpair.second.addr;
                    mnv.vin1 = mnpair.second.vin;
                    mnv.vin2 = CTxIn(activeSmartnode.outpoint);
                    std::string strMessage2 = strprintf("%s%d%s%s%s", mnv.addr.ToString(false), mnv.nonce, blockHash.ToString(),
                                            mnv.vin1.prevout.ToStringShort(), mnv.vin2.prevout.ToStringShort());
                    // ... and sign it
                    if(!CMessageSigner::SignMessage(strMessage2, mnv.vchSig2, activeSmartnode.keySmartnode)) {
                        LogPrintf("SmartnodeMan::ProcessVerifyReply -- SignMessage() failed\n");
                        return;
                    }

                    std::string strError;

                    if(!CMessageSigner::VerifyMessage(activeSmartnode.pubKeySmartnode, mnv.vchSig2, strMessage2, strError)) {
                        LogPrintf("SmartnodeMan::ProcessVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
                        return;
                    }

                    mWeAskedForVerification[pnode->addr] = mnv;
                    mapSeenSmartnodeVerification.insert(std::make_pair(mnv.GetHash(), mnv));
                    mnv.Relay();

                } else {
                    vpSmartnodesToBan.push_back(&mnpair.second);
                }
            }
        }
        // no real smartnode found?...
        if(!prealSmartnode) {
            // this should never be the case normally,
            // only if someone is trying to game the system in some way or smth like that
            LogPrintf("CSmartnodeMan::ProcessVerifyReply -- ERROR: no real smartnode found for addr %s\n", pnode->addr.ToString());
            Misbehaving(pnode->id, 20);
            return;
        }
        LogPrintf("CSmartnodeMan::ProcessVerifyReply -- verified real smartnode %s for addr %s\n",
                    prealSmartnode->vin.prevout.ToStringShort(), pnode->addr.ToString());
        // increase ban score for everyone else
        BOOST_FOREACH(CSmartnode* pmn, vpSmartnodesToBan) {
            pmn->IncreasePoSeBanScore();
            LogPrint("smartnode", "CSmartnodeMan::ProcessVerifyReply -- increased PoSe ban score for %s addr %s, new score %d\n",
                        prealSmartnode->vin.prevout.ToStringShort(), pnode->addr.ToString(), pmn->nPoSeBanScore);
        }
        if(!vpSmartnodesToBan.empty())
            LogPrintf("CSmartnodeMan::ProcessVerifyReply -- PoSe score increased for %d fake smartnodes, addr %s\n",
                        (int)vpSmartnodesToBan.size(), pnode->addr.ToString());
    }
}

void CSmartnodeMan::ProcessVerifyBroadcast(CNode* pnode, const CSmartnodeVerification& mnv)
{
    std::string strError;

    if(mapSeenSmartnodeVerification.find(mnv.GetHash()) != mapSeenSmartnodeVerification.end()) {
        // we already have one
        return;
    }
    mapSeenSmartnodeVerification[mnv.GetHash()] = mnv;

    // we don't care about history
    if(mnv.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS) {
        LogPrint("smartnode", "CSmartnodeMan::ProcessVerifyBroadcast -- Outdated: current block %d, verification block %d, peer=%d\n",
                    nCachedBlockHeight, mnv.nBlockHeight, pnode->id);
        return;
    }

    if(mnv.vin1.prevout == mnv.vin2.prevout) {
        LogPrint("smartnode", "CSmartnodeMan::ProcessVerifyBroadcast -- ERROR: same vins %s, peer=%d\n",
                    mnv.vin1.prevout.ToStringShort(), pnode->id);
        // that was NOT a good idea to cheat and verify itself,
        // ban the node we received such message from
        Misbehaving(pnode->id, 100);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        // this shouldn't happen...
        LogPrintf("CSmartnodeMan::ProcessVerifyBroadcast -- Can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->id);
        return;
    }

    int nRank;

    if (!GetSmartnodeRank(mnv.vin2.prevout, nRank, mnv.nBlockHeight, MIN_POSE_PROTO_VERSION)) {
        LogPrint("smartnode", "CSmartnodeMan::ProcessVerifyBroadcast -- Can't calculate rank for smartnode %s\n",
                    mnv.vin2.prevout.ToStringShort());
        return;
    }

    if(nRank > MAX_POSE_RANK) {
        LogPrint("smartnode", "CSmartnodeMan::ProcessVerifyBroadcast -- Smartnode %s is not in top %d, current rank %d, peer=%d\n",
                    mnv.vin2.prevout.ToStringShort(), (int)MAX_POSE_RANK, nRank, pnode->id);
        return;
    }

    {
        LOCK(cs);

        std::string strMessage1 = strprintf("%s%d%s", mnv.addr.ToString(false), mnv.nonce, blockHash.ToString());
        std::string strMessage2 = strprintf("%s%d%s%s%s", mnv.addr.ToString(false), mnv.nonce, blockHash.ToString(),
                                mnv.vin1.prevout.ToStringShort(), mnv.vin2.prevout.ToStringShort());

        CSmartnode* pmn1 = Find(mnv.vin1.prevout);
        if(!pmn1) {
            LogPrintf("CSmartnodeMan::ProcessVerifyBroadcast -- can't find smartnode1 %s\n", mnv.vin1.prevout.ToStringShort());
            return;
        }

        CSmartnode* pmn2 = Find(mnv.vin2.prevout);
        if(!pmn2) {
            LogPrintf("CSmartnodeMan::ProcessVerifyBroadcast -- can't find smartnode2 %s\n", mnv.vin2.prevout.ToStringShort());
            return;
        }

        if(pmn1->addr != mnv.addr) {
            LogPrintf("CSmartnodeMan::ProcessVerifyBroadcast -- addr %s does not match %s\n", mnv.addr.ToString(), pmn1->addr.ToString());
            return;
        }

        if(!CMessageSigner::VerifyMessage(pmn1->pubKeySmartnode, mnv.vchSig1, strMessage1, strError)) {
            LogPrintf("CSmartnodeMan::ProcessVerifyBroadcast -- VerifyMessage() for smartnode1 failed, error: %s\n", strError);
            return;
        }

        if(!CMessageSigner::VerifyMessage(pmn2->pubKeySmartnode, mnv.vchSig2, strMessage2, strError)) {
            LogPrintf("CSmartnodeMan::ProcessVerifyBroadcast -- VerifyMessage() for smartnode2 failed, error: %s\n", strError);
            return;
        }

        if(!pmn1->IsPoSeVerified()) {
            pmn1->DecreasePoSeBanScore();
        }
        mnv.Relay();

        LogPrintf("CSmartnodeMan::ProcessVerifyBroadcast -- verified smartnode %s for addr %s\n",
                    pmn1->vin.prevout.ToStringShort(), pmn1->addr.ToString());

        // increase ban score for everyone else with the same addr
        int nCount = 0;
        for (auto& mnpair : mapSmartnodes) {
            if(mnpair.second.addr != mnv.addr || mnpair.first == mnv.vin1.prevout) continue;
            mnpair.second.IncreasePoSeBanScore();
            nCount++;
            LogPrint("smartnode", "CSmartnodeMan::ProcessVerifyBroadcast -- increased PoSe ban score for %s addr %s, new score %d\n",
                        mnpair.first.ToStringShort(), mnpair.second.addr.ToString(), mnpair.second.nPoSeBanScore);
        }
        if(nCount)
            LogPrintf("CSmartnodeMan::ProcessVerifyBroadcast -- PoSe score increased for %d fake smartnodes, addr %s\n",
                        nCount, pmn1->addr.ToString());
    }
}

std::string CSmartnodeMan::ToString() const
{
    std::ostringstream info;

    info << "Smartnodes: " << (int)mapSmartnodes.size() <<
            ", peers who asked us for Smartnode list: " << (int)mAskedUsForSmartnodeList.size() <<
            ", peers we asked for Smartnode list: " << (int)mWeAskedForSmartnodeList.size() <<
            ", entries in Smartnode list we asked for: " << (int)mWeAskedForSmartnodeListEntry.size() <<
            ", nDsqCount: " << (int)nDsqCount;

    return info.str();
}

void CSmartnodeMan::UpdateSmartnodeList(CSmartnodeBroadcast mnb, CConnman& connman)
{
    LOCK2(cs_main, cs);
    mapSeenSmartnodePing.insert(std::make_pair(mnb.lastPing.GetHash(), mnb.lastPing));
    mapSeenSmartnodeBroadcast.insert(std::make_pair(mnb.GetHash(), std::make_pair(GetTime(), mnb)));

    LogPrintf("CSmartnodeMan::UpdateSmartnodeList -- smartnode=%s  addr=%s\n", mnb.vin.prevout.ToStringShort(), mnb.addr.ToString());

    CSmartnode* pmn = Find(mnb.vin.prevout);
    if(pmn == NULL) {
        if(Add(mnb)) {
            smartnodeSync.BumpAssetLastTime("CSmartnodeMan::UpdateSmartnodeList - new");
        }
    } else {
        CSmartnodeBroadcast mnbOld = mapSeenSmartnodeBroadcast[CSmartnodeBroadcast(*pmn).GetHash()].second;
        if(pmn->UpdateFromNewBroadcast(mnb, connman)) {
            smartnodeSync.BumpAssetLastTime("CSmartnodeMan::UpdateSmartnodeList - seen");
            mapSeenSmartnodeBroadcast.erase(mnbOld.GetHash());
        }
    }
}

bool CSmartnodeMan::CheckMnbAndUpdateSmartnodeList(CNode* pfrom, CSmartnodeBroadcast mnb, int& nDos, CConnman& connman)
{
    // Need to lock cs_main here to ensure consistent locking order because the SimpleCheck call below locks cs_main
    LOCK(cs_main);

    {
        LOCK(cs);
        nDos = 0;
        LogPrint("smartnode", "CSmartnodeMan::CheckMnbAndUpdateSmartnodeList -- smartnode=%s\n", mnb.vin.prevout.ToStringShort());

        uint256 hash = mnb.GetHash();
        if(mapSeenSmartnodeBroadcast.count(hash) && !mnb.fRecovery) { //seen
            LogPrint("smartnode", "CSmartnodeMan::CheckMnbAndUpdateSmartnodeList -- smartnode=%s seen\n", mnb.vin.prevout.ToStringShort());
            // less then 2 pings left before this MN goes into non-recoverable state, bump sync timeout
            if(GetTime() - mapSeenSmartnodeBroadcast[hash].first > SMARTNODE_NEW_START_REQUIRED_SECONDS - SMARTNODE_MIN_MNP_SECONDS * 2) {
                LogPrint("smartnode", "CSmartnodeMan::CheckMnbAndUpdateSmartnodeList -- smartnode=%s seen update\n", mnb.vin.prevout.ToStringShort());
                mapSeenSmartnodeBroadcast[hash].first = GetTime();
                smartnodeSync.BumpAssetLastTime("CSmartnodeMan::CheckMnbAndUpdateSmartnodeList - seen");
            }
            // did we ask this node for it?
            if(pfrom && IsMnbRecoveryRequested(hash) && GetTime() < mMnbRecoveryRequests[hash].first) {
                LogPrint("smartnode", "CSmartnodeMan::CheckMnbAndUpdateSmartnodeList -- mnb=%s seen request\n", hash.ToString());
                if(mMnbRecoveryRequests[hash].second.count(pfrom->addr)) {
                    LogPrint("smartnode", "CSmartnodeMan::CheckMnbAndUpdateSmartnodeList -- mnb=%s seen request, addr=%s\n", hash.ToString(), pfrom->addr.ToString());
                    // do not allow node to send same mnb multiple times in recovery mode
                    mMnbRecoveryRequests[hash].second.erase(pfrom->addr);
                    // does it have newer lastPing?
                    if(mnb.lastPing.sigTime > mapSeenSmartnodeBroadcast[hash].second.lastPing.sigTime) {
                        // simulate Check
                        CSmartnode mnTemp = CSmartnode(mnb);
                        mnTemp.Check();
                        LogPrint("smartnode", "CSmartnodeMan::CheckMnbAndUpdateSmartnodeList -- mnb=%s seen request, addr=%s, better lastPing: %d min ago, projected mn state: %s\n", hash.ToString(), pfrom->addr.ToString(), (GetAdjustedTime() - mnb.lastPing.sigTime)/60, mnTemp.GetStateString());
                        if(mnTemp.IsValidStateForAutoStart(mnTemp.nActiveState)) {
                            // this node thinks it's a good one
                            LogPrint("smartnode", "CSmartnodeMan::CheckMnbAndUpdateSmartnodeList -- smartnode=%s seen good\n", mnb.vin.prevout.ToStringShort());
                            mMnbRecoveryGoodReplies[hash].push_back(mnb);
                        }
                    }
                }
            }
            return true;
        }
        mapSeenSmartnodeBroadcast.insert(std::make_pair(hash, std::make_pair(GetTime(), mnb)));

        LogPrint("smartnode", "CSmartnodeMan::CheckMnbAndUpdateSmartnodeList -- smartnode=%s new\n", mnb.vin.prevout.ToStringShort());

        if(!mnb.SimpleCheck(nDos)) {
            LogPrint("smartnode", "CSmartnodeMan::CheckMnbAndUpdateSmartnodeList -- SimpleCheck() failed, smartnode=%s\n", mnb.vin.prevout.ToStringShort());
            return false;
        }

        // search Smartnode list
        CSmartnode* pmn = Find(mnb.vin.prevout);
        if(pmn) {
            CSmartnodeBroadcast mnbOld = mapSeenSmartnodeBroadcast[CSmartnodeBroadcast(*pmn).GetHash()].second;
            if(!mnb.Update(pmn, nDos, connman)) {
                LogPrint("smartnode", "CSmartnodeMan::CheckMnbAndUpdateSmartnodeList -- Update() failed, smartnode=%s\n", mnb.vin.prevout.ToStringShort());
                return false;
            }
            if(hash != mnbOld.GetHash()) {
                mapSeenSmartnodeBroadcast.erase(mnbOld.GetHash());
            }
            return true;
        }
    }

    if(mnb.CheckOutpoint(nDos)) {
        Add(mnb);
        smartnodeSync.BumpAssetLastTime("CSmartnodeMan::CheckMnbAndUpdateSmartnodeList - new");
        // if it matches our Smartnode privkey...
        if(fSmartNode && mnb.pubKeySmartnode == activeSmartnode.pubKeySmartnode) {
            mnb.nPoSeBanScore = -SMARTNODE_POSE_BAN_MAX_SCORE;
            if(mnb.nProtocolVersion == PROTOCOL_VERSION) {
                // ... and PROTOCOL_VERSION, then we've been remotely activated ...
                LogPrintf("CSmartnodeMan::CheckMnbAndUpdateSmartnodeList -- Got NEW Smartnode entry: smartnode=%s  sigTime=%lld  addr=%s\n",
                            mnb.vin.prevout.ToStringShort(), mnb.sigTime, mnb.addr.ToString());
                activeSmartnode.ManageState(connman);
            } else {
                // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
                // but also do not ban the node we get this message from
                LogPrintf("CSmartnodeMan::CheckMnbAndUpdateSmartnodeList -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", mnb.nProtocolVersion, PROTOCOL_VERSION);
                return false;
            }
        }
        mnb.Relay(connman);
    } else {
        LogPrintf("CSmartnodeMan::CheckMnbAndUpdateSmartnodeList -- Rejected Smartnode entry: %s  addr=%s\n", mnb.vin.prevout.ToStringShort(), mnb.addr.ToString());
        return false;
    }

    return true;
}

void CSmartnodeMan::UpdateLastPaid(const CBlockIndex* pindex)
{
    LOCK(cs);

    if(fLiteMode || !smartnodeSync.IsWinnersListSynced() || mapSmartnodes.empty()) return;

    static bool IsFirstRun = true;
    // Do full scan on first run or if we are not a smartnode
    // (MNs should update this info on every block, so limited scan should be enough for them)
    int nMaxBlocksToScanBack = (IsFirstRun || !fSmartNode) ? mnpayments.GetStorageLimit() : LAST_PAID_SCAN_BLOCKS;

    // LogPrint("mnpayments", "CSmartnodeMan::UpdateLastPaid -- nHeight=%d, nMaxBlocksToScanBack=%d, IsFirstRun=%s\n",
    //                         nCachedBlockHeight, nMaxBlocksToScanBack, IsFirstRun ? "true" : "false");

    for (auto& mnpair: mapSmartnodes) {
        mnpair.second.UpdateLastPaid(pindex, nMaxBlocksToScanBack);
    }

    IsFirstRun = false;
}

void CSmartnodeMan::UpdateWatchdogVoteTime(const COutPoint& outpoint, uint64_t nVoteTime)
{
    LOCK(cs);
    CSmartnode* pmn = Find(outpoint);
    if(!pmn) {
        return;
    }
    pmn->UpdateWatchdogVoteTime(nVoteTime);
    nLastWatchdogVoteTime = GetTime();
}

bool CSmartnodeMan::IsWatchdogActive()
{
    LOCK(cs);
    // Check if any smartnodes have voted recently, otherwise return false
    return (GetTime() - nLastWatchdogVoteTime) <= SMARTNODE_WATCHDOG_MAX_SECONDS;
}

bool CSmartnodeMan::AddGovernanceVote(const COutPoint& outpoint, uint256 nGovernanceObjectHash)
{
    LOCK(cs);
    CSmartnode* pmn = Find(outpoint);
    if(!pmn) {
        return false;
    }
    pmn->AddGovernanceVote(nGovernanceObjectHash);
    return true;
}

void CSmartnodeMan::RemoveGovernanceObject(uint256 nGovernanceObjectHash)
{
    LOCK(cs);
    for(auto& mnpair : mapSmartnodes) {
        mnpair.second.RemoveGovernanceObject(nGovernanceObjectHash);
    }
}

void CSmartnodeMan::CheckSmartnode(const CPubKey& pubKeySmartnode, bool fForce)
{
    LOCK(cs);
    for (auto& mnpair : mapSmartnodes) {
        if (mnpair.second.pubKeySmartnode == pubKeySmartnode) {
            mnpair.second.Check(fForce);
            return;
        }
    }
}

bool CSmartnodeMan::IsSmartnodePingedWithin(const COutPoint& outpoint, int nSeconds, int64_t nTimeToCheckAt)
{
    LOCK(cs);
    CSmartnode* pmn = Find(outpoint);
    return pmn ? pmn->IsPingedWithin(nSeconds, nTimeToCheckAt) : false;
}

void CSmartnodeMan::SetSmartnodeLastPing(const COutPoint& outpoint, const CSmartnodePing& mnp)
{
    LOCK(cs);
    CSmartnode* pmn = Find(outpoint);
    if(!pmn) {
        return;
    }
    pmn->lastPing = mnp;
    // if smartnode uses sentinel ping instead of watchdog
    // we shoud update nTimeLastWatchdogVote here if sentinel
    // ping flag is actual
    if(mnp.fSentinelIsCurrent) {
        UpdateWatchdogVoteTime(mnp.vin.prevout, mnp.sigTime);
    }
    mapSeenSmartnodePing.insert(std::make_pair(mnp.GetHash(), mnp));

    CSmartnodeBroadcast mnb(*pmn);
    uint256 hash = mnb.GetHash();
    if(mapSeenSmartnodeBroadcast.count(hash)) {
        mapSeenSmartnodeBroadcast[hash].second.lastPing = mnp;
    }
}

void CSmartnodeMan::UpdatedBlockTip(const CBlockIndex *pindex)
{
    nCachedBlockHeight = pindex->nHeight;
    LogPrint("smartnode", "CSmartnodeMan::UpdatedBlockTip -- nCachedBlockHeight=%d\n", nCachedBlockHeight);

    CheckSameAddr();

    if(fSmartNode) {
        // normal wallet does not need to update this every block, doing update on rpc call should be enough
        UpdateLastPaid(pindex);
    }
}

void CSmartnodeMan::NotifySmartnodeUpdates(CConnman& connman)
{
    // Avoid double locking
    // bool fSmartnodesAddedLocal = false;
    // bool fSmartnodesRemovedLocal = false;
    // {
    //     LOCK(cs);
    //     fSmartnodesAddedLocal = fSmartnodesAdded;
    //     fSmartnodesRemovedLocal = fSmartnodesRemoved;
    // }

    // if(fSmartnodesAddedLocal) {
    //     governance.CheckSmartnodeOrphanObjects(connman);
    //     governance.CheckSmartnodeOrphanVotes(connman);
    // }
    // if(fSmartnodesRemovedLocal) {
    //     governance.UpdateCachesAndClean();
    // }

    LOCK(cs);
    fSmartnodesAdded = false;
    fSmartnodesRemoved = false;
}
