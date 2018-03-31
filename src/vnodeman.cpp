// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activevnode.h"
#include "addrman.h"
#include "darksend.h"
//#include "governance.h"
#include "vnode-payments.h"
#include "vnode-sync.h"
#include "vnodeman.h"
#include "netfulfilledman.h"
#include "util.h"

/** Vnode manager */
CVnodeMan mnodeman;

const std::string CVnodeMan::SERIALIZATION_VERSION_STRING = "CVnodeMan-Version-4";

struct CompareLastPaidBlock
{
    bool operator()(const std::pair<int, CVnode*>& t1,
                    const std::pair<int, CVnode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->vin < t2.second->vin);
    }
};

struct CompareScoreMN
{
    bool operator()(const std::pair<int64_t, CVnode*>& t1,
                    const std::pair<int64_t, CVnode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->vin < t2.second->vin);
    }
};

CVnodeIndex::CVnodeIndex()
    : nSize(0),
      mapIndex(),
      mapReverseIndex()
{}

bool CVnodeIndex::Get(int nIndex, CTxIn& vinVnode) const
{
    rindex_m_cit it = mapReverseIndex.find(nIndex);
    if(it == mapReverseIndex.end()) {
        return false;
    }
    vinVnode = it->second;
    return true;
}

int CVnodeIndex::GetVnodeIndex(const CTxIn& vinVnode) const
{
    index_m_cit it = mapIndex.find(vinVnode);
    if(it == mapIndex.end()) {
        return -1;
    }
    return it->second;
}

void CVnodeIndex::AddVnodeVIN(const CTxIn& vinVnode)
{
    index_m_it it = mapIndex.find(vinVnode);
    if(it != mapIndex.end()) {
        return;
    }
    int nNextIndex = nSize;
    mapIndex[vinVnode] = nNextIndex;
    mapReverseIndex[nNextIndex] = vinVnode;
    ++nSize;
}

void CVnodeIndex::Clear()
{
    mapIndex.clear();
    mapReverseIndex.clear();
    nSize = 0;
}
struct CompareByAddr

{
    bool operator()(const CVnode* t1,
                    const CVnode* t2) const
    {
        return t1->addr < t2->addr;
    }
};

void CVnodeIndex::RebuildIndex()
{
    nSize = mapIndex.size();
    for(index_m_it it = mapIndex.begin(); it != mapIndex.end(); ++it) {
        mapReverseIndex[it->second] = it->first;
    }
}

CVnodeMan::CVnodeMan() : cs(),
  vVnodes(),
  mAskedUsForVnodeList(),
  mWeAskedForVnodeList(),
  mWeAskedForVnodeListEntry(),
  mWeAskedForVerification(),
  mMnbRecoveryRequests(),
  mMnbRecoveryGoodReplies(),
  listScheduledMnbRequestConnections(),
  nLastIndexRebuildTime(0),
  indexVnodes(),
  indexVnodesOld(),
  fIndexRebuilt(false),
  fVnodesAdded(false),
  fVnodesRemoved(false),
//  vecDirtyGovernanceObjectHashes(),
  nLastWatchdogVoteTime(0),
  mapSeenVnodeBroadcast(),
  mapSeenVnodePing(),
  nDsqCount(0)
{}

bool CVnodeMan::Add(CVnode &mn)
{
    LOCK(cs);

    CVnode *pmn = Find(mn.vin);
    if (pmn == NULL) {
        LogPrint("vnode", "CVnodeMan::Add -- Adding new Vnode: addr=%s, %i now\n", mn.addr.ToString(), size() + 1);
        vVnodes.push_back(mn);
        indexVnodes.AddVnodeVIN(mn.vin);
        fVnodesAdded = true;
        return true;
    }

    return false;
}

void CVnodeMan::AskForMN(CNode* pnode, const CTxIn &vin)
{
    if(!pnode) return;

    LOCK(cs);

    std::map<COutPoint, std::map<CNetAddr, int64_t> >::iterator it1 = mWeAskedForVnodeListEntry.find(vin.prevout);
    if (it1 != mWeAskedForVnodeListEntry.end()) {
        std::map<CNetAddr, int64_t>::iterator it2 = it1->second.find(pnode->addr);
        if (it2 != it1->second.end()) {
            if (GetTime() < it2->second) {
                // we've asked recently, should not repeat too often or we could get banned
                return;
            }
            // we asked this node for this outpoint but it's ok to ask again already
            LogPrintf("CVnodeMan::AskForMN -- Asking same peer %s for missing vnode entry again: %s\n", pnode->addr.ToString(), vin.prevout.ToStringShort());
        } else {
            // we already asked for this outpoint but not this node
            LogPrintf("CVnodeMan::AskForMN -- Asking new peer %s for missing vnode entry: %s\n", pnode->addr.ToString(), vin.prevout.ToStringShort());
        }
    } else {
        // we never asked any node for this outpoint
        LogPrintf("CVnodeMan::AskForMN -- Asking peer %s for missing vnode entry for the first time: %s\n", pnode->addr.ToString(), vin.prevout.ToStringShort());
    }
    mWeAskedForVnodeListEntry[vin.prevout][pnode->addr] = GetTime() + DSEG_UPDATE_SECONDS;

    pnode->PushMessage(NetMsgType::DSEG, vin);
}

void CVnodeMan::Check()
{
    LOCK(cs);

//    LogPrint("vnode", "CVnodeMan::Check -- nLastWatchdogVoteTime=%d, IsWatchdogActive()=%d\n", nLastWatchdogVoteTime, IsWatchdogActive());

    BOOST_FOREACH(CVnode& mn, vVnodes) {
        mn.Check();
    }
}

void CVnodeMan::CheckAndRemove()
{
    if(!vnodeSync.IsVnodeListSynced()) return;

    LogPrintf("CVnodeMan::CheckAndRemove\n");

    {
        // Need LOCK2 here to ensure consistent locking order because code below locks cs_main
        // in CheckMnbAndUpdateVnodeList()
        LOCK2(cs_main, cs);

        Check();

        // Remove spent vnodes, prepare structures and make requests to reasure the state of inactive ones
        std::vector<CVnode>::iterator it = vVnodes.begin();
        std::vector<std::pair<int, CVnode> > vecVnodeRanks;
        // ask for up to MNB_RECOVERY_MAX_ASK_ENTRIES vnode entries at a time
        int nAskForMnbRecovery = MNB_RECOVERY_MAX_ASK_ENTRIES;
        while(it != vVnodes.end()) {
            CVnodeBroadcast mnb = CVnodeBroadcast(*it);
            uint256 hash = mnb.GetHash();
            // If collateral was spent ...
            if ((*it).IsOutpointSpent()) {
                LogPrint("vnode", "CVnodeMan::CheckAndRemove -- Removing Vnode: %s  addr=%s  %i now\n", (*it).GetStateString(), (*it).addr.ToString(), size() - 1);

                // erase all of the broadcasts we've seen from this txin, ...
                mapSeenVnodeBroadcast.erase(hash);
                mWeAskedForVnodeListEntry.erase((*it).vin.prevout);

                // and finally remove it from the list
//                it->FlagGovernanceItemsAsDirty();
                it = vVnodes.erase(it);
                fVnodesRemoved = true;
            } else {
                bool fAsk = pCurrentBlockIndex &&
                            (nAskForMnbRecovery > 0) &&
                            vnodeSync.IsSynced() &&
                            it->IsNewStartRequired() &&
                            !IsMnbRecoveryRequested(hash);
                if(fAsk) {
                    // this mn is in a non-recoverable state and we haven't asked other nodes yet
                    std::set<CNetAddr> setRequested;
                    // calulate only once and only when it's needed
                    if(vecVnodeRanks.empty()) {
                        int nRandomBlockHeight = GetRandInt(pCurrentBlockIndex->nHeight);
                        vecVnodeRanks = GetVnodeRanks(nRandomBlockHeight);
                    }
                    bool fAskedForMnbRecovery = false;
                    // ask first MNB_RECOVERY_QUORUM_TOTAL vnodes we can connect to and we haven't asked recently
                    for(int i = 0; setRequested.size() < MNB_RECOVERY_QUORUM_TOTAL && i < (int)vecVnodeRanks.size(); i++) {
                        // avoid banning
                        if(mWeAskedForVnodeListEntry.count(it->vin.prevout) && mWeAskedForVnodeListEntry[it->vin.prevout].count(vecVnodeRanks[i].second.addr)) continue;
                        // didn't ask recently, ok to ask now
                        CService addr = vecVnodeRanks[i].second.addr;
                        setRequested.insert(addr);
                        listScheduledMnbRequestConnections.push_back(std::make_pair(addr, hash));
                        fAskedForMnbRecovery = true;
                    }
                    if(fAskedForMnbRecovery) {
                        LogPrint("vnode", "CVnodeMan::CheckAndRemove -- Recovery initiated, vnode=%s\n", it->vin.prevout.ToStringShort());
                        nAskForMnbRecovery--;
                    }
                    // wait for mnb recovery replies for MNB_RECOVERY_WAIT_SECONDS seconds
                    mMnbRecoveryRequests[hash] = std::make_pair(GetTime() + MNB_RECOVERY_WAIT_SECONDS, setRequested);
                }
                ++it;
            }
        }

        // proces replies for ZNODE_NEW_START_REQUIRED vnodes
        LogPrint("vnode", "CVnodeMan::CheckAndRemove -- mMnbRecoveryGoodReplies size=%d\n", (int)mMnbRecoveryGoodReplies.size());
        std::map<uint256, std::vector<CVnodeBroadcast> >::iterator itMnbReplies = mMnbRecoveryGoodReplies.begin();
        while(itMnbReplies != mMnbRecoveryGoodReplies.end()){
            if(mMnbRecoveryRequests[itMnbReplies->first].first < GetTime()) {
                // all nodes we asked should have replied now
                if(itMnbReplies->second.size() >= MNB_RECOVERY_QUORUM_REQUIRED) {
                    // majority of nodes we asked agrees that this mn doesn't require new mnb, reprocess one of new mnbs
                    LogPrint("vnode", "CVnodeMan::CheckAndRemove -- reprocessing mnb, vnode=%s\n", itMnbReplies->second[0].vin.prevout.ToStringShort());
                    // mapSeenVnodeBroadcast.erase(itMnbReplies->first);
                    int nDos;
                    itMnbReplies->second[0].fRecovery = true;
                    CheckMnbAndUpdateVnodeList(NULL, itMnbReplies->second[0], nDos);
                }
                LogPrint("vnode", "CVnodeMan::CheckAndRemove -- removing mnb recovery reply, vnode=%s, size=%d\n", itMnbReplies->second[0].vin.prevout.ToStringShort(), (int)itMnbReplies->second.size());
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
            // if mn is still in ZNODE_NEW_START_REQUIRED state.
            if(GetTime() - itMnbRequest->second.first > MNB_RECOVERY_RETRY_SECONDS) {
                mMnbRecoveryRequests.erase(itMnbRequest++);
            } else {
                ++itMnbRequest;
            }
        }

        // check who's asked for the Vnode list
        std::map<CNetAddr, int64_t>::iterator it1 = mAskedUsForVnodeList.begin();
        while(it1 != mAskedUsForVnodeList.end()){
            if((*it1).second < GetTime()) {
                mAskedUsForVnodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check who we asked for the Vnode list
        it1 = mWeAskedForVnodeList.begin();
        while(it1 != mWeAskedForVnodeList.end()){
            if((*it1).second < GetTime()){
                mWeAskedForVnodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check which Vnodes we've asked for
        std::map<COutPoint, std::map<CNetAddr, int64_t> >::iterator it2 = mWeAskedForVnodeListEntry.begin();
        while(it2 != mWeAskedForVnodeListEntry.end()){
            std::map<CNetAddr, int64_t>::iterator it3 = it2->second.begin();
            while(it3 != it2->second.end()){
                if(it3->second < GetTime()){
                    it2->second.erase(it3++);
                } else {
                    ++it3;
                }
            }
            if(it2->second.empty()) {
                mWeAskedForVnodeListEntry.erase(it2++);
            } else {
                ++it2;
            }
        }

        std::map<CNetAddr, CVnodeVerification>::iterator it3 = mWeAskedForVerification.begin();
        while(it3 != mWeAskedForVerification.end()){
            if(it3->second.nBlockHeight < pCurrentBlockIndex->nHeight - MAX_POSE_BLOCKS) {
                mWeAskedForVerification.erase(it3++);
            } else {
                ++it3;
            }
        }

        // NOTE: do not expire mapSeenVnodeBroadcast entries here, clean them on mnb updates!

        // remove expired mapSeenVnodePing
        std::map<uint256, CVnodePing>::iterator it4 = mapSeenVnodePing.begin();
        while(it4 != mapSeenVnodePing.end()){
            if((*it4).second.IsExpired()) {
                LogPrint("vnode", "CVnodeMan::CheckAndRemove -- Removing expired Vnode ping: hash=%s\n", (*it4).second.GetHash().ToString());
                mapSeenVnodePing.erase(it4++);
            } else {
                ++it4;
            }
        }

        // remove expired mapSeenVnodeVerification
        std::map<uint256, CVnodeVerification>::iterator itv2 = mapSeenVnodeVerification.begin();
        while(itv2 != mapSeenVnodeVerification.end()){
            if((*itv2).second.nBlockHeight < pCurrentBlockIndex->nHeight - MAX_POSE_BLOCKS){
                LogPrint("vnode", "CVnodeMan::CheckAndRemove -- Removing expired Vnode verification: hash=%s\n", (*itv2).first.ToString());
                mapSeenVnodeVerification.erase(itv2++);
            } else {
                ++itv2;
            }
        }

        LogPrintf("CVnodeMan::CheckAndRemove -- %s\n", ToString());

        if(fVnodesRemoved) {
            CheckAndRebuildVnodeIndex();
        }
    }

    if(fVnodesRemoved) {
        NotifyVnodeUpdates();
    }
}

void CVnodeMan::Clear()
{
    LOCK(cs);
    vVnodes.clear();
    mAskedUsForVnodeList.clear();
    mWeAskedForVnodeList.clear();
    mWeAskedForVnodeListEntry.clear();
    mapSeenVnodeBroadcast.clear();
    mapSeenVnodePing.clear();
    nDsqCount = 0;
    nLastWatchdogVoteTime = 0;
    indexVnodes.Clear();
    indexVnodesOld.Clear();
}

int CVnodeMan::CountVnodes(int nProtocolVersion)
{
    LOCK(cs);
    int nCount = 0;
    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinVnodePaymentsProto() : nProtocolVersion;

    BOOST_FOREACH(CVnode& mn, vVnodes) {
        if(mn.nProtocolVersion < nProtocolVersion) continue;
        nCount++;
    }

    return nCount;
}

int CVnodeMan::CountEnabled(int nProtocolVersion)
{
    LOCK(cs);
    int nCount = 0;
    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinVnodePaymentsProto() : nProtocolVersion;

    BOOST_FOREACH(CVnode& mn, vVnodes) {
        if(mn.nProtocolVersion < nProtocolVersion || !mn.IsEnabled()) continue;
        nCount++;
    }

    return nCount;
}

/* Only IPv4 vnodes are allowed in 12.1, saving this for later
int CVnodeMan::CountByIP(int nNetworkType)
{
    LOCK(cs);
    int nNodeCount = 0;

    BOOST_FOREACH(CVnode& mn, vVnodes)
        if ((nNetworkType == NET_IPV4 && mn.addr.IsIPv4()) ||
            (nNetworkType == NET_TOR  && mn.addr.IsTor())  ||
            (nNetworkType == NET_IPV6 && mn.addr.IsIPv6())) {
                nNodeCount++;
        }

    return nNodeCount;
}
*/

void CVnodeMan::DsegUpdate(CNode* pnode)
{
    LOCK(cs);

    if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if(!(pnode->addr.IsRFC1918() || pnode->addr.IsLocal())) {
            std::map<CNetAddr, int64_t>::iterator it = mWeAskedForVnodeList.find(pnode->addr);
            if(it != mWeAskedForVnodeList.end() && GetTime() < (*it).second) {
                LogPrintf("CVnodeMan::DsegUpdate -- we already asked %s for the list; skipping...\n", pnode->addr.ToString());
                return;
            }
        }
    }
    
    pnode->PushMessage(NetMsgType::DSEG, CTxIn());
    int64_t askAgain = GetTime() + DSEG_UPDATE_SECONDS;
    mWeAskedForVnodeList[pnode->addr] = askAgain;

    LogPrint("vnode", "CVnodeMan::DsegUpdate -- asked %s for the list\n", pnode->addr.ToString());
}

CVnode* CVnodeMan::Find(const CScript &payee)
{
    LOCK(cs);

    BOOST_FOREACH(CVnode& mn, vVnodes)
    {
        if(GetScriptForDestination(mn.pubKeyCollateralAddress.GetID()) == payee)
            return &mn;
    }
    return NULL;
}

CVnode* CVnodeMan::Find(const CTxIn &vin)
{
    LOCK(cs);

    BOOST_FOREACH(CVnode& mn, vVnodes)
    {
        if(mn.vin.prevout == vin.prevout)
            return &mn;
    }
    return NULL;
}

CVnode* CVnodeMan::Find(const CPubKey &pubKeyVnode)
{
    LOCK(cs);

    BOOST_FOREACH(CVnode& mn, vVnodes)
    {
        if(mn.pubKeyVnode == pubKeyVnode)
            return &mn;
    }
    return NULL;
}

bool CVnodeMan::Get(const CPubKey& pubKeyVnode, CVnode& vnode)
{
    // Theses mutexes are recursive so double locking by the same thread is safe.
    LOCK(cs);
    CVnode* pMN = Find(pubKeyVnode);
    if(!pMN)  {
        return false;
    }
    vnode = *pMN;
    return true;
}

bool CVnodeMan::Get(const CTxIn& vin, CVnode& vnode)
{
    // Theses mutexes are recursive so double locking by the same thread is safe.
    LOCK(cs);
    CVnode* pMN = Find(vin);
    if(!pMN)  {
        return false;
    }
    vnode = *pMN;
    return true;
}

vnode_info_t CVnodeMan::GetVnodeInfo(const CTxIn& vin)
{
    vnode_info_t info;
    LOCK(cs);
    CVnode* pMN = Find(vin);
    if(!pMN)  {
        return info;
    }
    info = pMN->GetInfo();
    return info;
}

vnode_info_t CVnodeMan::GetVnodeInfo(const CPubKey& pubKeyVnode)
{
    vnode_info_t info;
    LOCK(cs);
    CVnode* pMN = Find(pubKeyVnode);
    if(!pMN)  {
        return info;
    }
    info = pMN->GetInfo();
    return info;
}

bool CVnodeMan::Has(const CTxIn& vin)
{
    LOCK(cs);
    CVnode* pMN = Find(vin);
    return (pMN != NULL);
}

char* CVnodeMan::GetNotQualifyReason(CVnode& mn, int nBlockHeight, bool fFilterSigTime, int nMnCount)
{
    if (!mn.IsValidForPayment()) {
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'not valid for payment'");
        return reasonStr;
    }
    // //check protocol version
    if (mn.nProtocolVersion < mnpayments.GetMinVnodePaymentsProto()) {
        // LogPrintf("Invalid nProtocolVersion!\n");
        // LogPrintf("mn.nProtocolVersion=%s!\n", mn.nProtocolVersion);
        // LogPrintf("mnpayments.GetMinVnodePaymentsProto=%s!\n", mnpayments.GetMinVnodePaymentsProto());
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'Invalid nProtocolVersion', nProtocolVersion=%d", mn.nProtocolVersion);
        return reasonStr;
    }
    //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
    if (mnpayments.IsScheduled(mn, nBlockHeight)) {
        // LogPrintf("mnpayments.IsScheduled!\n");
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'is scheduled'");
        return reasonStr;
    }
    //it's too new, wait for a cycle
    if (fFilterSigTime && mn.sigTime + (nMnCount * 2.6 * 60) > GetAdjustedTime()) {
        // LogPrintf("it's too new, wait for a cycle!\n");
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'too new', sigTime=%s, will be qualifed after=%s",
                DateTimeStrFormat("%Y-%m-%d %H:%M UTC", mn.sigTime).c_str(), DateTimeStrFormat("%Y-%m-%d %H:%M UTC", mn.sigTime + (nMnCount * 2.6 * 60)).c_str());
        return reasonStr;
    }
    //make sure it has at least as many confirmations as there are vnodes
    if (mn.GetCollateralAge() < nMnCount) {
        // LogPrintf("mn.GetCollateralAge()=%s!\n", mn.GetCollateralAge());
        // LogPrintf("nMnCount=%s!\n", nMnCount);
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'collateralAge < znCount', collateralAge=%d, znCount=%d", mn.GetCollateralAge(), nMnCount);
        return reasonStr;
    }
    return NULL;
}

//
// Deterministically select the oldest/best vnode to pay on the network
//
CVnode* CVnodeMan::GetNextVnodeInQueueForPayment(bool fFilterSigTime, int& nCount)
{
    if(!pCurrentBlockIndex) {
        nCount = 0;
        return NULL;
    }
    return GetNextVnodeInQueueForPayment(pCurrentBlockIndex->nHeight, fFilterSigTime, nCount);
}

CVnode* CVnodeMan::GetNextVnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCount)
{
    // Need LOCK2 here to ensure consistent locking order because the GetBlockHash call below locks cs_main
    LOCK2(cs_main,cs);

    CVnode *pBestVnode = NULL;
    std::vector<std::pair<int, CVnode*> > vecVnodeLastPaid;

    /*
        Make a vector with all of the last paid times
    */
    int nMnCount = CountEnabled();
    int index = 0;
    BOOST_FOREACH(CVnode &mn, vVnodes)
    {
        index += 1;
        // LogPrintf("index=%s, mn=%s\n", index, mn.ToString());
        /*if (!mn.IsValidForPayment()) {
            LogPrint("vnodeman", "Vnode, %s, addr(%s), not-qualified: 'not valid for payment'\n",
                     mn.vin.prevout.ToStringShort(), CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString());
            continue;
        }
        // //check protocol version
        if (mn.nProtocolVersion < mnpayments.GetMinVnodePaymentsProto()) {
            // LogPrintf("Invalid nProtocolVersion!\n");
            // LogPrintf("mn.nProtocolVersion=%s!\n", mn.nProtocolVersion);
            // LogPrintf("mnpayments.GetMinVnodePaymentsProto=%s!\n", mnpayments.GetMinVnodePaymentsProto());
            LogPrint("vnodeman", "Vnode, %s, addr(%s), not-qualified: 'invalid nProtocolVersion'\n",
                     mn.vin.prevout.ToStringShort(), CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString());
            continue;
        }
        //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
        if (mnpayments.IsScheduled(mn, nBlockHeight)) {
            // LogPrintf("mnpayments.IsScheduled!\n");
            LogPrint("vnodeman", "Vnode, %s, addr(%s), not-qualified: 'IsScheduled'\n",
                     mn.vin.prevout.ToStringShort(), CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString());
            continue;
        }
        //it's too new, wait for a cycle
        if (fFilterSigTime && mn.sigTime + (nMnCount * 2.6 * 60) > GetAdjustedTime()) {
            // LogPrintf("it's too new, wait for a cycle!\n");
            LogPrint("vnodeman", "Vnode, %s, addr(%s), not-qualified: 'it's too new, wait for a cycle!', sigTime=%s, will be qualifed after=%s\n",
                     mn.vin.prevout.ToStringShort(), CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString(), DateTimeStrFormat("%Y-%m-%d %H:%M UTC", mn.sigTime).c_str(), DateTimeStrFormat("%Y-%m-%d %H:%M UTC", mn.sigTime + (nMnCount * 2.6 * 60)).c_str());
            continue;
        }
        //make sure it has at least as many confirmations as there are vnodes
        if (mn.GetCollateralAge() < nMnCount) {
            // LogPrintf("mn.GetCollateralAge()=%s!\n", mn.GetCollateralAge());
            // LogPrintf("nMnCount=%s!\n", nMnCount);
            LogPrint("vnodeman", "Vnode, %s, addr(%s), not-qualified: 'mn.GetCollateralAge() < nMnCount', CollateralAge=%d, nMnCount=%d\n",
                     mn.vin.prevout.ToStringShort(), CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString(), mn.GetCollateralAge(), nMnCount);
            continue;
        }*/
        char* reasonStr = GetNotQualifyReason(mn, nBlockHeight, fFilterSigTime, nMnCount);
        if (reasonStr != NULL) {
            LogPrint("vnodeman", "Vnode, %s, addr(%s), qualify %s\n",
                     mn.vin.prevout.ToStringShort(), CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString(), reasonStr);
            delete [] reasonStr;
            continue;
        }
        vecVnodeLastPaid.push_back(std::make_pair(mn.GetLastPaidBlock(), &mn));
    }
    nCount = (int)vecVnodeLastPaid.size();

    //when the network is in the process of upgrading, don't penalize nodes that recently restarted
    if(fFilterSigTime && nCount < nMnCount / 3) {
        // LogPrintf("Need Return, nCount=%s, nMnCount/3=%s\n", nCount, nMnCount/3);
        return GetNextVnodeInQueueForPayment(nBlockHeight, false, nCount);
    }

    // Sort them low to high
    sort(vecVnodeLastPaid.begin(), vecVnodeLastPaid.end(), CompareLastPaidBlock());

    uint256 blockHash;
    if(!GetBlockHash(blockHash, nBlockHeight - 101)) {
        LogPrintf("CVnode::GetNextVnodeInQueueForPayment -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", nBlockHeight - 101);
        return NULL;
    }
    // Look at 1/10 of the oldest nodes (by last payment), calculate their scores and pay the best one
    //  -- This doesn't look at who is being paid in the +8-10 blocks, allowing for double payments very rarely
    //  -- 1/100 payments should be a double payment on mainnet - (1/(3000/10))*2
    //  -- (chance per block * chances before IsScheduled will fire)
    int nTenthNetwork = nMnCount/10;
    int nCountTenth = 0;
    arith_uint256 nHighest = 0;
    BOOST_FOREACH (PAIRTYPE(int, CVnode*)& s, vecVnodeLastPaid){
        arith_uint256 nScore = s.second->CalculateScore(blockHash);
        if(nScore > nHighest){
            nHighest = nScore;
            pBestVnode = s.second;
        }
        nCountTenth++;
        if(nCountTenth >= nTenthNetwork) break;
    }
    return pBestVnode;
}

CVnode* CVnodeMan::FindRandomNotInVec(const std::vector<CTxIn> &vecToExclude, int nProtocolVersion)
{
    LOCK(cs);

    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinVnodePaymentsProto() : nProtocolVersion;

    int nCountEnabled = CountEnabled(nProtocolVersion);
    int nCountNotExcluded = nCountEnabled - vecToExclude.size();

    LogPrintf("CVnodeMan::FindRandomNotInVec -- %d enabled vnodes, %d vnodes to choose from\n", nCountEnabled, nCountNotExcluded);
    if(nCountNotExcluded < 1) return NULL;

    // fill a vector of pointers
    std::vector<CVnode*> vpVnodesShuffled;
    BOOST_FOREACH(CVnode &mn, vVnodes) {
        vpVnodesShuffled.push_back(&mn);
    }

    InsecureRand insecureRand;
    // shuffle pointers
    std::random_shuffle(vpVnodesShuffled.begin(), vpVnodesShuffled.end(), insecureRand);
    bool fExclude;

    // loop through
    BOOST_FOREACH(CVnode* pmn, vpVnodesShuffled) {
        if(pmn->nProtocolVersion < nProtocolVersion || !pmn->IsEnabled()) continue;
        fExclude = false;
        BOOST_FOREACH(const CTxIn &txinToExclude, vecToExclude) {
            if(pmn->vin.prevout == txinToExclude.prevout) {
                fExclude = true;
                break;
            }
        }
        if(fExclude) continue;
        // found the one not in vecToExclude
        LogPrint("vnode", "CVnodeMan::FindRandomNotInVec -- found, vnode=%s\n", pmn->vin.prevout.ToStringShort());
        return pmn;
    }

    LogPrint("vnode", "CVnodeMan::FindRandomNotInVec -- failed\n");
    return NULL;
}

int CVnodeMan::GetVnodeRank(const CTxIn& vin, int nBlockHeight, int nMinProtocol, bool fOnlyActive)
{
    std::vector<std::pair<int64_t, CVnode*> > vecVnodeScores;

    //make sure we know about this block
    uint256 blockHash = uint256();
    if(!GetBlockHash(blockHash, nBlockHeight)) return -1;

    LOCK(cs);

    // scan for winner
    BOOST_FOREACH(CVnode& mn, vVnodes) {
        if(mn.nProtocolVersion < nMinProtocol) continue;
        if(fOnlyActive) {
            if(!mn.IsEnabled()) continue;
        }
        else {
            if(!mn.IsValidForPayment()) continue;
        }
        int64_t nScore = mn.CalculateScore(blockHash).GetCompact(false);

        vecVnodeScores.push_back(std::make_pair(nScore, &mn));
    }

    sort(vecVnodeScores.rbegin(), vecVnodeScores.rend(), CompareScoreMN());

    int nRank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CVnode*)& scorePair, vecVnodeScores) {
        nRank++;
        if(scorePair.second->vin.prevout == vin.prevout) return nRank;
    }

    return -1;
}

std::vector<std::pair<int, CVnode> > CVnodeMan::GetVnodeRanks(int nBlockHeight, int nMinProtocol)
{
    std::vector<std::pair<int64_t, CVnode*> > vecVnodeScores;
    std::vector<std::pair<int, CVnode> > vecVnodeRanks;

    //make sure we know about this block
    uint256 blockHash = uint256();
    if(!GetBlockHash(blockHash, nBlockHeight)) return vecVnodeRanks;

    LOCK(cs);

    // scan for winner
    BOOST_FOREACH(CVnode& mn, vVnodes) {

        if(mn.nProtocolVersion < nMinProtocol || !mn.IsEnabled()) continue;

        int64_t nScore = mn.CalculateScore(blockHash).GetCompact(false);

        vecVnodeScores.push_back(std::make_pair(nScore, &mn));
    }

    sort(vecVnodeScores.rbegin(), vecVnodeScores.rend(), CompareScoreMN());

    int nRank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CVnode*)& s, vecVnodeScores) {
        nRank++;
        vecVnodeRanks.push_back(std::make_pair(nRank, *s.second));
    }

    return vecVnodeRanks;
}

CVnode* CVnodeMan::GetVnodeByRank(int nRank, int nBlockHeight, int nMinProtocol, bool fOnlyActive)
{
    std::vector<std::pair<int64_t, CVnode*> > vecVnodeScores;

    LOCK(cs);

    uint256 blockHash;
    if(!GetBlockHash(blockHash, nBlockHeight)) {
        LogPrintf("CVnode::GetVnodeByRank -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", nBlockHeight);
        return NULL;
    }

    // Fill scores
    BOOST_FOREACH(CVnode& mn, vVnodes) {

        if(mn.nProtocolVersion < nMinProtocol) continue;
        if(fOnlyActive && !mn.IsEnabled()) continue;

        int64_t nScore = mn.CalculateScore(blockHash).GetCompact(false);

        vecVnodeScores.push_back(std::make_pair(nScore, &mn));
    }

    sort(vecVnodeScores.rbegin(), vecVnodeScores.rend(), CompareScoreMN());

    int rank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CVnode*)& s, vecVnodeScores){
        rank++;
        if(rank == nRank) {
            return s.second;
        }
    }

    return NULL;
}

void CVnodeMan::ProcessVnodeConnections()
{
    //we don't care about this for regtest
    if(Params().NetworkIDString() == CBaseChainParams::REGTEST) return;

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes) {
        if(pnode->fVnode) {
            if(darkSendPool.pSubmittedToVnode != NULL && pnode->addr == darkSendPool.pSubmittedToVnode->addr) continue;
            // LogPrintf("Closing Vnode connection: peer=%d, addr=%s\n", pnode->id, pnode->addr.ToString());
            pnode->fDisconnect = true;
        }
    }
}

std::pair<CService, std::set<uint256> > CVnodeMan::PopScheduledMnbRequestConnection()
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


void CVnodeMan::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{

//    LogPrint("vnode", "CVnodeMan::ProcessMessage, strCommand=%s\n", strCommand);
    if(fLiteMode) return; // disable all Dash specific functionality
    if(!vnodeSync.IsBlockchainSynced()) return;

    if (strCommand == NetMsgType::MNANNOUNCE) { //Vnode Broadcast
        CVnodeBroadcast mnb;
        vRecv >> mnb;

        pfrom->setAskFor.erase(mnb.GetHash());

        LogPrintf("MNANNOUNCE -- Vnode announce, vnode=%s\n", mnb.vin.prevout.ToStringShort());

        int nDos = 0;

        if (CheckMnbAndUpdateVnodeList(pfrom, mnb, nDos)) {
            // use announced Vnode as a peer
            addrman.Add(CAddress(mnb.addr, NODE_NETWORK), pfrom->addr, 2*60*60);
        } else if(nDos > 0) {
            Misbehaving(pfrom->GetId(), nDos);
        }

        if(fVnodesAdded) {
            NotifyVnodeUpdates();
        }
    } else if (strCommand == NetMsgType::MNPING) { //Vnode Ping

        CVnodePing mnp;
        vRecv >> mnp;

        uint256 nHash = mnp.GetHash();

        pfrom->setAskFor.erase(nHash);

        LogPrint("vnode", "MNPING -- Vnode ping, vnode=%s\n", mnp.vin.prevout.ToStringShort());

        // Need LOCK2 here to ensure consistent locking order because the CheckAndUpdate call below locks cs_main
        LOCK2(cs_main, cs);

        if(mapSeenVnodePing.count(nHash)) return; //seen
        mapSeenVnodePing.insert(std::make_pair(nHash, mnp));

        LogPrint("vnode", "MNPING -- Vnode ping, vnode=%s new\n", mnp.vin.prevout.ToStringShort());

        // see if we have this Vnode
        CVnode* pmn = mnodeman.Find(mnp.vin);

        // too late, new MNANNOUNCE is required
        if(pmn && pmn->IsNewStartRequired()) return;

        int nDos = 0;
        if(mnp.CheckAndUpdate(pmn, false, nDos)) return;

        if(nDos > 0) {
            // if anything significant failed, mark that node
            Misbehaving(pfrom->GetId(), nDos);
        } else if(pmn != NULL) {
            // nothing significant failed, mn is a known one too
            return;
        }

        // something significant is broken or mn is unknown,
        // we might have to ask for a vnode entry once
        AskForMN(pfrom, mnp.vin);

    } else if (strCommand == NetMsgType::DSEG) { //Get Vnode list or specific entry
        // Ignore such requests until we are fully synced.
        // We could start processing this after vnode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!vnodeSync.IsSynced()) return;

        CTxIn vin;
        vRecv >> vin;

        LogPrint("vnode", "DSEG -- Vnode list, vnode=%s\n", vin.prevout.ToStringShort());

        LOCK(cs);

        if(vin == CTxIn()) { //only should ask for this once
            //local network
            bool isLocal = (pfrom->addr.IsRFC1918() || pfrom->addr.IsLocal());

            if(!isLocal && Params().NetworkIDString() == CBaseChainParams::MAIN) {
                std::map<CNetAddr, int64_t>::iterator i = mAskedUsForVnodeList.find(pfrom->addr);
                if (i != mAskedUsForVnodeList.end()){
                    int64_t t = (*i).second;
                    if (GetTime() < t) {
                        Misbehaving(pfrom->GetId(), 34);
                        LogPrintf("DSEG -- peer already asked me for the list, peer=%d\n", pfrom->id);
                        return;
                    }
                }
                int64_t askAgain = GetTime() + DSEG_UPDATE_SECONDS;
                mAskedUsForVnodeList[pfrom->addr] = askAgain;
            }
        } //else, asking for a specific node which is ok

        int nInvCount = 0;

        BOOST_FOREACH(CVnode& mn, vVnodes) {
            if (vin != CTxIn() && vin != mn.vin) continue; // asked for specific vin but we are not there yet
            if (mn.addr.IsRFC1918() || mn.addr.IsLocal()) continue; // do not send local network vnode
            if (mn.IsUpdateRequired()) continue; // do not send outdated vnodes

            LogPrint("vnode", "DSEG -- Sending Vnode entry: vnode=%s  addr=%s\n", mn.vin.prevout.ToStringShort(), mn.addr.ToString());
            CVnodeBroadcast mnb = CVnodeBroadcast(mn);
            uint256 hash = mnb.GetHash();
            pfrom->PushInventory(CInv(MSG_ZNODE_ANNOUNCE, hash));
            pfrom->PushInventory(CInv(MSG_ZNODE_PING, mn.lastPing.GetHash()));
            nInvCount++;

            if (!mapSeenVnodeBroadcast.count(hash)) {
                mapSeenVnodeBroadcast.insert(std::make_pair(hash, std::make_pair(GetTime(), mnb)));
            }

            if (vin == mn.vin) {
                LogPrintf("DSEG -- Sent 1 Vnode inv to peer %d\n", pfrom->id);
                return;
            }
        }

        if(vin == CTxIn()) {
            pfrom->PushMessage(NetMsgType::SYNCSTATUSCOUNT, ZNODE_SYNC_LIST, nInvCount);
            LogPrintf("DSEG -- Sent %d Vnode invs to peer %d\n", nInvCount, pfrom->id);
            return;
        }
        // smth weird happen - someone asked us for vin we have no idea about?
        LogPrint("vnode", "DSEG -- No invs sent to peer %d\n", pfrom->id);

    } else if (strCommand == NetMsgType::MNVERIFY) { // Vnode Verify

        // Need LOCK2 here to ensure consistent locking order because the all functions below call GetBlockHash which locks cs_main
        LOCK2(cs_main, cs);

        CVnodeVerification mnv;
        vRecv >> mnv;

        if(mnv.vchSig1.empty()) {
            // CASE 1: someone asked me to verify myself /IP we are using/
            SendVerifyReply(pfrom, mnv);
        } else if (mnv.vchSig2.empty()) {
            // CASE 2: we _probably_ got verification we requested from some vnode
            ProcessVerifyReply(pfrom, mnv);
        } else {
            // CASE 3: we _probably_ got verification broadcast signed by some vnode which verified another one
            ProcessVerifyBroadcast(pfrom, mnv);
        }
    }
}

// Verification of vnodes via unique direct requests.

void CVnodeMan::DoFullVerificationStep()
{
    if(activeVnode.vin == CTxIn()) return;
    if(!vnodeSync.IsSynced()) return;

    std::vector<std::pair<int, CVnode> > vecVnodeRanks = GetVnodeRanks(pCurrentBlockIndex->nHeight - 1, MIN_POSE_PROTO_VERSION);

    // Need LOCK2 here to ensure consistent locking order because the SendVerifyRequest call below locks cs_main
    // through GetHeight() signal in ConnectNode
    LOCK2(cs_main, cs);

    int nCount = 0;

    int nMyRank = -1;
    int nRanksTotal = (int)vecVnodeRanks.size();

    // send verify requests only if we are in top MAX_POSE_RANK
    std::vector<std::pair<int, CVnode> >::iterator it = vecVnodeRanks.begin();
    while(it != vecVnodeRanks.end()) {
        if(it->first > MAX_POSE_RANK) {
            LogPrint("vnode", "CVnodeMan::DoFullVerificationStep -- Must be in top %d to send verify request\n",
                        (int)MAX_POSE_RANK);
            return;
        }
        if(it->second.vin == activeVnode.vin) {
            nMyRank = it->first;
            LogPrint("vnode", "CVnodeMan::DoFullVerificationStep -- Found self at rank %d/%d, verifying up to %d vnodes\n",
                        nMyRank, nRanksTotal, (int)MAX_POSE_CONNECTIONS);
            break;
        }
        ++it;
    }

    // edge case: list is too short and this vnode is not enabled
    if(nMyRank == -1) return;

    // send verify requests to up to MAX_POSE_CONNECTIONS vnodes
    // starting from MAX_POSE_RANK + nMyRank and using MAX_POSE_CONNECTIONS as a step
    int nOffset = MAX_POSE_RANK + nMyRank - 1;
    if(nOffset >= (int)vecVnodeRanks.size()) return;

    std::vector<CVnode*> vSortedByAddr;
    BOOST_FOREACH(CVnode& mn, vVnodes) {
        vSortedByAddr.push_back(&mn);
    }

    sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

    it = vecVnodeRanks.begin() + nOffset;
    while(it != vecVnodeRanks.end()) {
        if(it->second.IsPoSeVerified() || it->second.IsPoSeBanned()) {
            LogPrint("vnode", "CVnodeMan::DoFullVerificationStep -- Already %s%s%s vnode %s address %s, skipping...\n",
                        it->second.IsPoSeVerified() ? "verified" : "",
                        it->second.IsPoSeVerified() && it->second.IsPoSeBanned() ? " and " : "",
                        it->second.IsPoSeBanned() ? "banned" : "",
                        it->second.vin.prevout.ToStringShort(), it->second.addr.ToString());
            nOffset += MAX_POSE_CONNECTIONS;
            if(nOffset >= (int)vecVnodeRanks.size()) break;
            it += MAX_POSE_CONNECTIONS;
            continue;
        }
        LogPrint("vnode", "CVnodeMan::DoFullVerificationStep -- Verifying vnode %s rank %d/%d address %s\n",
                    it->second.vin.prevout.ToStringShort(), it->first, nRanksTotal, it->second.addr.ToString());
        if(SendVerifyRequest(CAddress(it->second.addr, NODE_NETWORK), vSortedByAddr)) {
            nCount++;
            if(nCount >= MAX_POSE_CONNECTIONS) break;
        }
        nOffset += MAX_POSE_CONNECTIONS;
        if(nOffset >= (int)vecVnodeRanks.size()) break;
        it += MAX_POSE_CONNECTIONS;
    }

    LogPrint("vnode", "CVnodeMan::DoFullVerificationStep -- Sent verification requests to %d vnodes\n", nCount);
}

// This function tries to find vnodes with the same addr,
// find a verified one and ban all the other. If there are many nodes
// with the same addr but none of them is verified yet, then none of them are banned.
// It could take many times to run this before most of the duplicate nodes are banned.

void CVnodeMan::CheckSameAddr()
{
    if(!vnodeSync.IsSynced() || vVnodes.empty()) return;

    std::vector<CVnode*> vBan;
    std::vector<CVnode*> vSortedByAddr;

    {
        LOCK(cs);

        CVnode* pprevVnode = NULL;
        CVnode* pverifiedVnode = NULL;

        BOOST_FOREACH(CVnode& mn, vVnodes) {
            vSortedByAddr.push_back(&mn);
        }

        sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

        BOOST_FOREACH(CVnode* pmn, vSortedByAddr) {
            // check only (pre)enabled vnodes
            if(!pmn->IsEnabled() && !pmn->IsPreEnabled()) continue;
            // initial step
            if(!pprevVnode) {
                pprevVnode = pmn;
                pverifiedVnode = pmn->IsPoSeVerified() ? pmn : NULL;
                continue;
            }
            // second+ step
            if(pmn->addr == pprevVnode->addr) {
                if(pverifiedVnode) {
                    // another vnode with the same ip is verified, ban this one
                    vBan.push_back(pmn);
                } else if(pmn->IsPoSeVerified()) {
                    // this vnode with the same ip is verified, ban previous one
                    vBan.push_back(pprevVnode);
                    // and keep a reference to be able to ban following vnodes with the same ip
                    pverifiedVnode = pmn;
                }
            } else {
                pverifiedVnode = pmn->IsPoSeVerified() ? pmn : NULL;
            }
            pprevVnode = pmn;
        }
    }

    // ban duplicates
    BOOST_FOREACH(CVnode* pmn, vBan) {
        LogPrintf("CVnodeMan::CheckSameAddr -- increasing PoSe ban score for vnode %s\n", pmn->vin.prevout.ToStringShort());
        pmn->IncreasePoSeBanScore();
    }
}

bool CVnodeMan::SendVerifyRequest(const CAddress& addr, const std::vector<CVnode*>& vSortedByAddr)
{
    if(netfulfilledman.HasFulfilledRequest(addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request")) {
        // we already asked for verification, not a good idea to do this too often, skip it
        LogPrint("vnode", "CVnodeMan::SendVerifyRequest -- too many requests, skipping... addr=%s\n", addr.ToString());
        return false;
    }

    CNode* pnode = ConnectNode(addr, NULL, false, true);
    if(pnode == NULL) {
        LogPrintf("CVnodeMan::SendVerifyRequest -- can't connect to node to verify it, addr=%s\n", addr.ToString());
        return false;
    }

    netfulfilledman.AddFulfilledRequest(addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request");
    // use random nonce, store it and require node to reply with correct one later
    CVnodeVerification mnv(addr, GetRandInt(999999), pCurrentBlockIndex->nHeight - 1);
    mWeAskedForVerification[addr] = mnv;
    LogPrintf("CVnodeMan::SendVerifyRequest -- verifying node using nonce %d addr=%s\n", mnv.nonce, addr.ToString());
    pnode->PushMessage(NetMsgType::MNVERIFY, mnv);

    return true;
}

void CVnodeMan::SendVerifyReply(CNode* pnode, CVnodeVerification& mnv)
{
    // only vnodes can sign this, why would someone ask regular node?
    if(!fVNode) {
        // do not ban, malicious node might be using my IP
        // and trying to confuse the node which tries to verify it
        return;
    }

    if(netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-reply")) {
//        // peer should not ask us that often
        LogPrintf("VnodeMan::SendVerifyReply -- ERROR: peer already asked me recently, peer=%d\n", pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        LogPrintf("VnodeMan::SendVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->id);
        return;
    }

    std::string strMessage = strprintf("%s%d%s", activeVnode.service.ToString(), mnv.nonce, blockHash.ToString());

    if(!darkSendSigner.SignMessage(strMessage, mnv.vchSig1, activeVnode.keyVnode)) {
        LogPrintf("VnodeMan::SendVerifyReply -- SignMessage() failed\n");
        return;
    }

    std::string strError;

    if(!darkSendSigner.VerifyMessage(activeVnode.pubKeyVnode, mnv.vchSig1, strMessage, strError)) {
        LogPrintf("VnodeMan::SendVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
        return;
    }

    pnode->PushMessage(NetMsgType::MNVERIFY, mnv);
    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-reply");
}

void CVnodeMan::ProcessVerifyReply(CNode* pnode, CVnodeVerification& mnv)
{
    std::string strError;

    // did we even ask for it? if that's the case we should have matching fulfilled request
    if(!netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request")) {
        LogPrintf("CVnodeMan::ProcessVerifyReply -- ERROR: we didn't ask for verification of %s, peer=%d\n", pnode->addr.ToString(), pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    // Received nonce for a known address must match the one we sent
    if(mWeAskedForVerification[pnode->addr].nonce != mnv.nonce) {
        LogPrintf("CVnodeMan::ProcessVerifyReply -- ERROR: wrong nounce: requested=%d, received=%d, peer=%d\n",
                    mWeAskedForVerification[pnode->addr].nonce, mnv.nonce, pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    // Received nBlockHeight for a known address must match the one we sent
    if(mWeAskedForVerification[pnode->addr].nBlockHeight != mnv.nBlockHeight) {
        LogPrintf("CVnodeMan::ProcessVerifyReply -- ERROR: wrong nBlockHeight: requested=%d, received=%d, peer=%d\n",
                    mWeAskedForVerification[pnode->addr].nBlockHeight, mnv.nBlockHeight, pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        // this shouldn't happen...
        LogPrintf("VnodeMan::ProcessVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->id);
        return;
    }

//    // we already verified this address, why node is spamming?
    if(netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-done")) {
        LogPrintf("CVnodeMan::ProcessVerifyReply -- ERROR: already verified %s recently\n", pnode->addr.ToString());
        Misbehaving(pnode->id, 20);
        return;
    }

    {
        LOCK(cs);

        CVnode* prealVnode = NULL;
        std::vector<CVnode*> vpVnodesToBan;
        std::vector<CVnode>::iterator it = vVnodes.begin();
        std::string strMessage1 = strprintf("%s%d%s", pnode->addr.ToString(), mnv.nonce, blockHash.ToString());
        while(it != vVnodes.end()) {
            if(CAddress(it->addr, NODE_NETWORK) == pnode->addr) {
                if(darkSendSigner.VerifyMessage(it->pubKeyVnode, mnv.vchSig1, strMessage1, strError)) {
                    // found it!
                    prealVnode = &(*it);
                    if(!it->IsPoSeVerified()) {
                        it->DecreasePoSeBanScore();
                    }
                    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-done");

                    // we can only broadcast it if we are an activated vnode
                    if(activeVnode.vin == CTxIn()) continue;
                    // update ...
                    mnv.addr = it->addr;
                    mnv.vin1 = it->vin;
                    mnv.vin2 = activeVnode.vin;
                    std::string strMessage2 = strprintf("%s%d%s%s%s", mnv.addr.ToString(), mnv.nonce, blockHash.ToString(),
                                            mnv.vin1.prevout.ToStringShort(), mnv.vin2.prevout.ToStringShort());
                    // ... and sign it
                    if(!darkSendSigner.SignMessage(strMessage2, mnv.vchSig2, activeVnode.keyVnode)) {
                        LogPrintf("VnodeMan::ProcessVerifyReply -- SignMessage() failed\n");
                        return;
                    }

                    std::string strError;

                    if(!darkSendSigner.VerifyMessage(activeVnode.pubKeyVnode, mnv.vchSig2, strMessage2, strError)) {
                        LogPrintf("VnodeMan::ProcessVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
                        return;
                    }

                    mWeAskedForVerification[pnode->addr] = mnv;
                    mnv.Relay();

                } else {
                    vpVnodesToBan.push_back(&(*it));
                }
            }
            ++it;
        }
        // no real vnode found?...
        if(!prealVnode) {
            // this should never be the case normally,
            // only if someone is trying to game the system in some way or smth like that
            LogPrintf("CVnodeMan::ProcessVerifyReply -- ERROR: no real vnode found for addr %s\n", pnode->addr.ToString());
            Misbehaving(pnode->id, 20);
            return;
        }
        LogPrintf("CVnodeMan::ProcessVerifyReply -- verified real vnode %s for addr %s\n",
                    prealVnode->vin.prevout.ToStringShort(), pnode->addr.ToString());
        // increase ban score for everyone else
        BOOST_FOREACH(CVnode* pmn, vpVnodesToBan) {
            pmn->IncreasePoSeBanScore();
            LogPrint("vnode", "CVnodeMan::ProcessVerifyBroadcast -- increased PoSe ban score for %s addr %s, new score %d\n",
                        prealVnode->vin.prevout.ToStringShort(), pnode->addr.ToString(), pmn->nPoSeBanScore);
        }
        LogPrintf("CVnodeMan::ProcessVerifyBroadcast -- PoSe score increased for %d fake vnodes, addr %s\n",
                    (int)vpVnodesToBan.size(), pnode->addr.ToString());
    }
}

void CVnodeMan::ProcessVerifyBroadcast(CNode* pnode, const CVnodeVerification& mnv)
{
    std::string strError;

    if(mapSeenVnodeVerification.find(mnv.GetHash()) != mapSeenVnodeVerification.end()) {
        // we already have one
        return;
    }
    mapSeenVnodeVerification[mnv.GetHash()] = mnv;

    // we don't care about history
    if(mnv.nBlockHeight < pCurrentBlockIndex->nHeight - MAX_POSE_BLOCKS) {
        LogPrint("vnode", "VnodeMan::ProcessVerifyBroadcast -- Outdated: current block %d, verification block %d, peer=%d\n",
                    pCurrentBlockIndex->nHeight, mnv.nBlockHeight, pnode->id);
        return;
    }

    if(mnv.vin1.prevout == mnv.vin2.prevout) {
        LogPrint("vnode", "VnodeMan::ProcessVerifyBroadcast -- ERROR: same vins %s, peer=%d\n",
                    mnv.vin1.prevout.ToStringShort(), pnode->id);
        // that was NOT a good idea to cheat and verify itself,
        // ban the node we received such message from
        Misbehaving(pnode->id, 100);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        // this shouldn't happen...
        LogPrintf("VnodeMan::ProcessVerifyBroadcast -- Can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->id);
        return;
    }

    int nRank = GetVnodeRank(mnv.vin2, mnv.nBlockHeight, MIN_POSE_PROTO_VERSION);

    if (nRank == -1) {
        LogPrint("vnode", "CVnodeMan::ProcessVerifyBroadcast -- Can't calculate rank for vnode %s\n",
                    mnv.vin2.prevout.ToStringShort());
        return;
    }

    if(nRank > MAX_POSE_RANK) {
        LogPrint("vnode", "CVnodeMan::ProcessVerifyBroadcast -- Mastrernode %s is not in top %d, current rank %d, peer=%d\n",
                    mnv.vin2.prevout.ToStringShort(), (int)MAX_POSE_RANK, nRank, pnode->id);
        return;
    }

    {
        LOCK(cs);

        std::string strMessage1 = strprintf("%s%d%s", mnv.addr.ToString(), mnv.nonce, blockHash.ToString());
        std::string strMessage2 = strprintf("%s%d%s%s%s", mnv.addr.ToString(), mnv.nonce, blockHash.ToString(),
                                mnv.vin1.prevout.ToStringShort(), mnv.vin2.prevout.ToStringShort());

        CVnode* pmn1 = Find(mnv.vin1);
        if(!pmn1) {
            LogPrintf("CVnodeMan::ProcessVerifyBroadcast -- can't find vnode1 %s\n", mnv.vin1.prevout.ToStringShort());
            return;
        }

        CVnode* pmn2 = Find(mnv.vin2);
        if(!pmn2) {
            LogPrintf("CVnodeMan::ProcessVerifyBroadcast -- can't find vnode2 %s\n", mnv.vin2.prevout.ToStringShort());
            return;
        }

        if(pmn1->addr != mnv.addr) {
            LogPrintf("CVnodeMan::ProcessVerifyBroadcast -- addr %s do not match %s\n", mnv.addr.ToString(), pnode->addr.ToString());
            return;
        }

        if(darkSendSigner.VerifyMessage(pmn1->pubKeyVnode, mnv.vchSig1, strMessage1, strError)) {
            LogPrintf("VnodeMan::ProcessVerifyBroadcast -- VerifyMessage() for vnode1 failed, error: %s\n", strError);
            return;
        }

        if(darkSendSigner.VerifyMessage(pmn2->pubKeyVnode, mnv.vchSig2, strMessage2, strError)) {
            LogPrintf("VnodeMan::ProcessVerifyBroadcast -- VerifyMessage() for vnode2 failed, error: %s\n", strError);
            return;
        }

        if(!pmn1->IsPoSeVerified()) {
            pmn1->DecreasePoSeBanScore();
        }
        mnv.Relay();

        LogPrintf("CVnodeMan::ProcessVerifyBroadcast -- verified vnode %s for addr %s\n",
                    pmn1->vin.prevout.ToStringShort(), pnode->addr.ToString());

        // increase ban score for everyone else with the same addr
        int nCount = 0;
        BOOST_FOREACH(CVnode& mn, vVnodes) {
            if(mn.addr != mnv.addr || mn.vin.prevout == mnv.vin1.prevout) continue;
            mn.IncreasePoSeBanScore();
            nCount++;
            LogPrint("vnode", "CVnodeMan::ProcessVerifyBroadcast -- increased PoSe ban score for %s addr %s, new score %d\n",
                        mn.vin.prevout.ToStringShort(), mn.addr.ToString(), mn.nPoSeBanScore);
        }
        LogPrintf("CVnodeMan::ProcessVerifyBroadcast -- PoSe score incresed for %d fake vnodes, addr %s\n",
                    nCount, pnode->addr.ToString());
    }
}

std::string CVnodeMan::ToString() const
{
    std::ostringstream info;

    info << "Vnodes: " << (int)vVnodes.size() <<
            ", peers who asked us for Vnode list: " << (int)mAskedUsForVnodeList.size() <<
            ", peers we asked for Vnode list: " << (int)mWeAskedForVnodeList.size() <<
            ", entries in Vnode list we asked for: " << (int)mWeAskedForVnodeListEntry.size() <<
            ", vnode index size: " << indexVnodes.GetSize() <<
            ", nDsqCount: " << (int)nDsqCount;

    return info.str();
}

void CVnodeMan::UpdateVnodeList(CVnodeBroadcast mnb)
{
    try {
        LogPrintf("CVnodeMan::UpdateVnodeList\n");
        LOCK2(cs_main, cs);
        mapSeenVnodePing.insert(std::make_pair(mnb.lastPing.GetHash(), mnb.lastPing));
        mapSeenVnodeBroadcast.insert(std::make_pair(mnb.GetHash(), std::make_pair(GetTime(), mnb)));

        LogPrintf("CVnodeMan::UpdateVnodeList -- vnode=%s  addr=%s\n", mnb.vin.prevout.ToStringShort(), mnb.addr.ToString());

        CVnode *pmn = Find(mnb.vin);
        if (pmn == NULL) {
            CVnode mn(mnb);
            if (Add(mn)) {
                vnodeSync.AddedVnodeList();
            }
        } else {
            CVnodeBroadcast mnbOld = mapSeenVnodeBroadcast[CVnodeBroadcast(*pmn).GetHash()].second;
            if (pmn->UpdateFromNewBroadcast(mnb)) {
                vnodeSync.AddedVnodeList();
                mapSeenVnodeBroadcast.erase(mnbOld.GetHash());
            }
        }
    } catch (const std::exception &e) {
        PrintExceptionContinue(&e, "UpdateVnodeList");
    }
}

bool CVnodeMan::CheckMnbAndUpdateVnodeList(CNode* pfrom, CVnodeBroadcast mnb, int& nDos)
{
    // Need LOCK2 here to ensure consistent locking order because the SimpleCheck call below locks cs_main
    LOCK(cs_main);

    {
        LOCK(cs);
        nDos = 0;
        LogPrint("vnode", "CVnodeMan::CheckMnbAndUpdateVnodeList -- vnode=%s\n", mnb.vin.prevout.ToStringShort());

        uint256 hash = mnb.GetHash();
        if (mapSeenVnodeBroadcast.count(hash) && !mnb.fRecovery) { //seen
            LogPrint("vnode", "CVnodeMan::CheckMnbAndUpdateVnodeList -- vnode=%s seen\n", mnb.vin.prevout.ToStringShort());
            // less then 2 pings left before this MN goes into non-recoverable state, bump sync timeout
            if (GetTime() - mapSeenVnodeBroadcast[hash].first > ZNODE_NEW_START_REQUIRED_SECONDS - ZNODE_MIN_MNP_SECONDS * 2) {
                LogPrint("vnode", "CVnodeMan::CheckMnbAndUpdateVnodeList -- vnode=%s seen update\n", mnb.vin.prevout.ToStringShort());
                mapSeenVnodeBroadcast[hash].first = GetTime();
                vnodeSync.AddedVnodeList();
            }
            // did we ask this node for it?
            if (pfrom && IsMnbRecoveryRequested(hash) && GetTime() < mMnbRecoveryRequests[hash].first) {
                LogPrint("vnode", "CVnodeMan::CheckMnbAndUpdateVnodeList -- mnb=%s seen request\n", hash.ToString());
                if (mMnbRecoveryRequests[hash].second.count(pfrom->addr)) {
                    LogPrint("vnode", "CVnodeMan::CheckMnbAndUpdateVnodeList -- mnb=%s seen request, addr=%s\n", hash.ToString(), pfrom->addr.ToString());
                    // do not allow node to send same mnb multiple times in recovery mode
                    mMnbRecoveryRequests[hash].second.erase(pfrom->addr);
                    // does it have newer lastPing?
                    if (mnb.lastPing.sigTime > mapSeenVnodeBroadcast[hash].second.lastPing.sigTime) {
                        // simulate Check
                        CVnode mnTemp = CVnode(mnb);
                        mnTemp.Check();
                        LogPrint("vnode", "CVnodeMan::CheckMnbAndUpdateVnodeList -- mnb=%s seen request, addr=%s, better lastPing: %d min ago, projected mn state: %s\n", hash.ToString(), pfrom->addr.ToString(), (GetTime() - mnb.lastPing.sigTime) / 60, mnTemp.GetStateString());
                        if (mnTemp.IsValidStateForAutoStart(mnTemp.nActiveState)) {
                            // this node thinks it's a good one
                            LogPrint("vnode", "CVnodeMan::CheckMnbAndUpdateVnodeList -- vnode=%s seen good\n", mnb.vin.prevout.ToStringShort());
                            mMnbRecoveryGoodReplies[hash].push_back(mnb);
                        }
                    }
                }
            }
            return true;
        }
        mapSeenVnodeBroadcast.insert(std::make_pair(hash, std::make_pair(GetTime(), mnb)));

        LogPrint("vnode", "CVnodeMan::CheckMnbAndUpdateVnodeList -- vnode=%s new\n", mnb.vin.prevout.ToStringShort());

        if (!mnb.SimpleCheck(nDos)) {
            LogPrint("vnode", "CVnodeMan::CheckMnbAndUpdateVnodeList -- SimpleCheck() failed, vnode=%s\n", mnb.vin.prevout.ToStringShort());
            return false;
        }

        // search Vnode list
        CVnode *pmn = Find(mnb.vin);
        if (pmn) {
            CVnodeBroadcast mnbOld = mapSeenVnodeBroadcast[CVnodeBroadcast(*pmn).GetHash()].second;
            if (!mnb.Update(pmn, nDos)) {
                LogPrint("vnode", "CVnodeMan::CheckMnbAndUpdateVnodeList -- Update() failed, vnode=%s\n", mnb.vin.prevout.ToStringShort());
                return false;
            }
            if (hash != mnbOld.GetHash()) {
                mapSeenVnodeBroadcast.erase(mnbOld.GetHash());
            }
        }
    } // end of LOCK(cs);

    if(mnb.CheckOutpoint(nDos)) {
        Add(mnb);
        vnodeSync.AddedVnodeList();
        // if it matches our Vnode privkey...
        if(fVNode && mnb.pubKeyVnode == activeVnode.pubKeyVnode) {
            mnb.nPoSeBanScore = -ZNODE_POSE_BAN_MAX_SCORE;
            if(mnb.nProtocolVersion == PROTOCOL_VERSION) {
                // ... and PROTOCOL_VERSION, then we've been remotely activated ...
                LogPrintf("CVnodeMan::CheckMnbAndUpdateVnodeList -- Got NEW Vnode entry: vnode=%s  sigTime=%lld  addr=%s\n",
                            mnb.vin.prevout.ToStringShort(), mnb.sigTime, mnb.addr.ToString());
                activeVnode.ManageState();
            } else {
                // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
                // but also do not ban the node we get this message from
                LogPrintf("CVnodeMan::CheckMnbAndUpdateVnodeList -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", mnb.nProtocolVersion, PROTOCOL_VERSION);
                return false;
            }
        }
        mnb.RelayVNode();
    } else {
        LogPrintf("CVnodeMan::CheckMnbAndUpdateVnodeList -- Rejected Vnode entry: %s  addr=%s\n", mnb.vin.prevout.ToStringShort(), mnb.addr.ToString());
        return false;
    }

    return true;
}

void CVnodeMan::UpdateLastPaid()
{
    LOCK(cs);
    if(fLiteMode) return;
    if(!pCurrentBlockIndex) {
        // LogPrintf("CVnodeMan::UpdateLastPaid, pCurrentBlockIndex=NULL\n");
        return;
    }

    static bool IsFirstRun = true;
    // Do full scan on first run or if we are not a vnode
    // (MNs should update this info on every block, so limited scan should be enough for them)
    int nMaxBlocksToScanBack = (IsFirstRun || !fVNode) ? mnpayments.GetStorageLimit() : LAST_PAID_SCAN_BLOCKS;

    LogPrint("mnpayments", "CVnodeMan::UpdateLastPaid -- nHeight=%d, nMaxBlocksToScanBack=%d, IsFirstRun=%s\n",
                             pCurrentBlockIndex->nHeight, nMaxBlocksToScanBack, IsFirstRun ? "true" : "false");

    BOOST_FOREACH(CVnode& mn, vVnodes) {
        mn.UpdateLastPaid(pCurrentBlockIndex, nMaxBlocksToScanBack);
    }

    // every time is like the first time if winners list is not synced
    IsFirstRun = !vnodeSync.IsWinnersListSynced();
}

void CVnodeMan::CheckAndRebuildVnodeIndex()
{
    LOCK(cs);

    if(GetTime() - nLastIndexRebuildTime < MIN_INDEX_REBUILD_TIME) {
        return;
    }

    if(indexVnodes.GetSize() <= MAX_EXPECTED_INDEX_SIZE) {
        return;
    }

    if(indexVnodes.GetSize() <= int(vVnodes.size())) {
        return;
    }

    indexVnodesOld = indexVnodes;
    indexVnodes.Clear();
    for(size_t i = 0; i < vVnodes.size(); ++i) {
        indexVnodes.AddVnodeVIN(vVnodes[i].vin);
    }

    fIndexRebuilt = true;
    nLastIndexRebuildTime = GetTime();
}

void CVnodeMan::UpdateWatchdogVoteTime(const CTxIn& vin)
{
    LOCK(cs);
    CVnode* pMN = Find(vin);
    if(!pMN)  {
        return;
    }
    pMN->UpdateWatchdogVoteTime();
    nLastWatchdogVoteTime = GetTime();
}

bool CVnodeMan::IsWatchdogActive()
{
    LOCK(cs);
    // Check if any vnodes have voted recently, otherwise return false
    return (GetTime() - nLastWatchdogVoteTime) <= ZNODE_WATCHDOG_MAX_SECONDS;
}

void CVnodeMan::CheckVnode(const CTxIn& vin, bool fForce)
{
    LOCK(cs);
    CVnode* pMN = Find(vin);
    if(!pMN)  {
        return;
    }
    pMN->Check(fForce);
}

void CVnodeMan::CheckVnode(const CPubKey& pubKeyVnode, bool fForce)
{
    LOCK(cs);
    CVnode* pMN = Find(pubKeyVnode);
    if(!pMN)  {
        return;
    }
    pMN->Check(fForce);
}

int CVnodeMan::GetVnodeState(const CTxIn& vin)
{
    LOCK(cs);
    CVnode* pMN = Find(vin);
    if(!pMN)  {
        return CVnode::ZNODE_NEW_START_REQUIRED;
    }
    return pMN->nActiveState;
}

int CVnodeMan::GetVnodeState(const CPubKey& pubKeyVnode)
{
    LOCK(cs);
    CVnode* pMN = Find(pubKeyVnode);
    if(!pMN)  {
        return CVnode::ZNODE_NEW_START_REQUIRED;
    }
    return pMN->nActiveState;
}

bool CVnodeMan::IsVnodePingedWithin(const CTxIn& vin, int nSeconds, int64_t nTimeToCheckAt)
{
    LOCK(cs);
    CVnode* pMN = Find(vin);
    if(!pMN) {
        return false;
    }
    return pMN->IsPingedWithin(nSeconds, nTimeToCheckAt);
}

void CVnodeMan::SetVnodeLastPing(const CTxIn& vin, const CVnodePing& mnp)
{
    LOCK(cs);
    CVnode* pMN = Find(vin);
    if(!pMN)  {
        return;
    }
    pMN->lastPing = mnp;
    mapSeenVnodePing.insert(std::make_pair(mnp.GetHash(), mnp));

    CVnodeBroadcast mnb(*pMN);
    uint256 hash = mnb.GetHash();
    if(mapSeenVnodeBroadcast.count(hash)) {
        mapSeenVnodeBroadcast[hash].second.lastPing = mnp;
    }
}

void CVnodeMan::UpdatedBlockTip(const CBlockIndex *pindex)
{
    pCurrentBlockIndex = pindex;
    LogPrint("vnode", "CVnodeMan::UpdatedBlockTip -- pCurrentBlockIndex->nHeight=%d\n", pCurrentBlockIndex->nHeight);

    CheckSameAddr();

    if(fVNode) {
        // normal wallet does not need to update this every block, doing update on rpc call should be enough
        UpdateLastPaid();
    }
}

void CVnodeMan::NotifyVnodeUpdates()
{
    // Avoid double locking
    bool fVnodesAddedLocal = false;
    bool fVnodesRemovedLocal = false;
    {
        LOCK(cs);
        fVnodesAddedLocal = fVnodesAdded;
        fVnodesRemovedLocal = fVnodesRemoved;
    }

    if(fVnodesAddedLocal) {
//        governance.CheckVnodeOrphanObjects();
//        governance.CheckVnodeOrphanVotes();
    }
    if(fVnodesRemovedLocal) {
//        governance.UpdateCachesAndClean();
    }

    LOCK(cs);
    fVnodesAdded = false;
    fVnodesRemoved = false;
}
