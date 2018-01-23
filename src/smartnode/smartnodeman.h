// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SMARTNODEMAN_H
#define SMARTNODEMAN_H

#include "smartnode.h"
#include "../sync.h"

using namespace std;

class CSmartnodeMan;
class CConnman;

extern CSmartnodeMan mnodeman;

class CSmartnodeMan
{
public:
    typedef std::pair<arith_uint256, CSmartnode*> score_pair_t;
    typedef std::vector<score_pair_t> score_pair_vec_t;
    typedef std::pair<int, CSmartnode> rank_pair_t;
    typedef std::vector<rank_pair_t> rank_pair_vec_t;

private:
    static const std::string SERIALIZATION_VERSION_STRING;

    static const int DSEG_UPDATE_SECONDS        = 3 * 60 * 60;

    static const int LAST_PAID_SCAN_BLOCKS      = 100;

    static const int MIN_POSE_PROTO_VERSION     = 90023;
    static const int MAX_POSE_CONNECTIONS       = 10;
    static const int MAX_POSE_RANK              = 10;
    static const int MAX_POSE_BLOCKS            = 10;

    static const int MNB_RECOVERY_QUORUM_TOTAL      = 10;
    static const int MNB_RECOVERY_QUORUM_REQUIRED   = 6;
    static const int MNB_RECOVERY_MAX_ASK_ENTRIES   = 10;
    static const int MNB_RECOVERY_WAIT_SECONDS      = 60;
    static const int MNB_RECOVERY_RETRY_SECONDS     = 3 * 60 * 60;


    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    // Keep track of current block height
    int nCachedBlockHeight;

    // map to hold all MNs
    std::map<COutPoint, CSmartnode> mapSmartnodes;
    // who's asked for the Smartnode list and the last time
    std::map<CNetAddr, int64_t> mAskedUsForSmartnodeList;
    // who we asked for the Smartnode list and the last time
    std::map<CNetAddr, int64_t> mWeAskedForSmartnodeList;
    // which Smartnodes we've asked for
    std::map<COutPoint, std::map<CNetAddr, int64_t> > mWeAskedForSmartnodeListEntry;
    // who we asked for the smartnode verification
    std::map<CNetAddr, CSmartnodeVerification> mWeAskedForVerification;

    // these maps are used for smartnode recovery from SMARTNODE_NEW_START_REQUIRED state
    std::map<uint256, std::pair< int64_t, std::set<CNetAddr> > > mMnbRecoveryRequests;
    std::map<uint256, std::vector<CSmartnodeBroadcast> > mMnbRecoveryGoodReplies;
    std::list< std::pair<CService, uint256> > listScheduledMnbRequestConnections;

    /// Set when smartnodes are added, cleared when CGovernanceManager is notified
    bool fSmartnodesAdded;

    /// Set when smartnodes are removed, cleared when CGovernanceManager is notified
    bool fSmartnodesRemoved;

    std::vector<uint256> vecDirtyGovernanceObjectHashes;

    int64_t nLastWatchdogVoteTime;

    friend class CSmartnodeSync;
    /// Find an entry
    CSmartnode* Find(const COutPoint& outpoint);

    bool GetSmartnodeScores(const uint256& nBlockHash, score_pair_vec_t& vecSmartnodeScoresRet, int nMinProtocol = 0);

public:
    // Keep track of all broadcasts I've seen
    std::map<uint256, std::pair<int64_t, CSmartnodeBroadcast> > mapSeenSmartnodeBroadcast;
    // Keep track of all pings I've seen
    std::map<uint256, CSmartnodePing> mapSeenSmartnodePing;
    // Keep track of all verifications I've seen
    std::map<uint256, CSmartnodeVerification> mapSeenSmartnodeVerification;
    // keep track of dsq count to prevent smartnodes from gaming darksend queue
    int64_t nDsqCount;


    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        LOCK(cs);
        std::string strVersion;
        if(ser_action.ForRead()) {
            READWRITE(strVersion);
        }
        else {
            strVersion = SERIALIZATION_VERSION_STRING; 
            READWRITE(strVersion);
        }

        READWRITE(mapSmartnodes);
        READWRITE(mAskedUsForSmartnodeList);
        READWRITE(mWeAskedForSmartnodeList);
        READWRITE(mWeAskedForSmartnodeListEntry);
        READWRITE(mMnbRecoveryRequests);
        READWRITE(mMnbRecoveryGoodReplies);
        READWRITE(nLastWatchdogVoteTime);
        READWRITE(nDsqCount);

        READWRITE(mapSeenSmartnodeBroadcast);
        READWRITE(mapSeenSmartnodePing);
        if(ser_action.ForRead() && (strVersion != SERIALIZATION_VERSION_STRING)) {
            Clear();
        }
    }

    CSmartnodeMan();

    /// Add an entry
    bool Add(CSmartnode &mn);

    /// Ask (source) node for mnb
    void AskForMN(CNode *pnode, const COutPoint& outpoint, CConnman& connman);
    void AskForMnb(CNode *pnode, const uint256 &hash);

    bool PoSeBan(const COutPoint &outpoint);
    bool AllowMixing(const COutPoint &outpoint);
    bool DisallowMixing(const COutPoint &outpoint);

    /// Check all Smartnodes
    void Check();

    /// Check all Smartnodes and remove inactive
    void CheckAndRemove(CConnman& connman);
    /// This is dummy overload to be used for dumping/loading mncache.dat
    void CheckAndRemove() {}

    /// Clear Smartnode vector
    void Clear();

    /// Count Smartnodes filtered by nProtocolVersion.
    /// Smartnode nProtocolVersion should match or be above the one specified in param here.
    int CountSmartnodes(int nProtocolVersion = -1);
    /// Count enabled Smartnodes filtered by nProtocolVersion.
    /// Smartnode nProtocolVersion should match or be above the one specified in param here.
    int CountEnabled(int nProtocolVersion = -1);

    /// Count Smartnodes by network type - NET_IPV4, NET_IPV6, NET_TOR
    // int CountByIP(int nNetworkType);

    void DsegUpdate(CNode* pnode, CConnman& connman);

    /// Versions of Find that are safe to use from outside the class
    bool Get(const COutPoint& outpoint, CSmartnode& smartnodeRet);
    bool Has(const COutPoint& outpoint);

    bool GetSmartnodeInfo(const COutPoint& outpoint, smartnode_info_t& mnInfoRet);
    bool GetSmartnodeInfo(const CPubKey& pubKeySmartnode, smartnode_info_t& mnInfoRet);
    bool GetSmartnodeInfo(const CScript& payee, smartnode_info_t& mnInfoRet);

    /// Find an entry in the smartnode list that is next to be paid
    bool GetNextSmartnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCountRet, smartnode_info_t& mnInfoRet);
    /// Same as above but use current block height
    bool GetNextSmartnodeInQueueForPayment(bool fFilterSigTime, int& nCountRet, smartnode_info_t& mnInfoRet);

    /// Find a random entry
    smartnode_info_t FindRandomNotInVec(const std::vector<COutPoint> &vecToExclude, int nProtocolVersion = -1);

    std::map<COutPoint, CSmartnode> GetFullSmartnodeMap() { return mapSmartnodes; }

    bool GetSmartnodeRanks(rank_pair_vec_t& vecSmartnodeRanksRet, int nBlockHeight = -1, int nMinProtocol = 0);
    bool GetSmartnodeRank(const COutPoint &outpoint, int& nRankRet, int nBlockHeight = -1, int nMinProtocol = 0);

    void ProcessSmartnodeConnections(CConnman& connman);
    std::pair<CService, std::set<uint256> > PopScheduledMnbRequestConnection();

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv, CConnman& connman);

    void DoFullVerificationStep(CConnman& connman);
    void CheckSameAddr();
    bool SendVerifyRequest(const CAddress& addr, const std::vector<CSmartnode*>& vSortedByAddr, CConnman& connman);
    void SendVerifyReply(CNode* pnode, CSmartnodeVerification& mnv, CConnman& connman);
    void ProcessVerifyReply(CNode* pnode, CSmartnodeVerification& mnv);
    void ProcessVerifyBroadcast(CNode* pnode, const CSmartnodeVerification& mnv);

    /// Return the number of (unique) Smartnodes
    int size() { return mapSmartnodes.size(); }

    std::string ToString() const;

    /// Update smartnode list and maps using provided CSmartnodeBroadcast
    void UpdateSmartnodeList(CSmartnodeBroadcast mnb, CConnman& connman);
    /// Perform complete check and only then update list and maps
    bool CheckMnbAndUpdateSmartnodeList(CNode* pfrom, CSmartnodeBroadcast mnb, int& nDos, CConnman& connman);
    bool IsMnbRecoveryRequested(const uint256& hash) { return mMnbRecoveryRequests.count(hash); }

    void UpdateLastPaid(const CBlockIndex* pindex);

    void AddDirtyGovernanceObjectHash(const uint256& nHash)
    {
        LOCK(cs);
        vecDirtyGovernanceObjectHashes.push_back(nHash);
    }

    std::vector<uint256> GetAndClearDirtyGovernanceObjectHashes()
    {
        LOCK(cs);
        std::vector<uint256> vecTmp = vecDirtyGovernanceObjectHashes;
        vecDirtyGovernanceObjectHashes.clear();
        return vecTmp;;
    }

    bool IsWatchdogActive();
    void UpdateWatchdogVoteTime(const COutPoint& outpoint, uint64_t nVoteTime = 0);
    bool AddGovernanceVote(const COutPoint& outpoint, uint256 nGovernanceObjectHash);
    void RemoveGovernanceObject(uint256 nGovernanceObjectHash);

    void CheckSmartnode(const CPubKey& pubKeySmartnode, bool fForce);

    bool IsSmartnodePingedWithin(const COutPoint& outpoint, int nSeconds, int64_t nTimeToCheckAt = -1);
    void SetSmartnodeLastPing(const COutPoint& outpoint, const CSmartnodePing& mnp);

    void UpdatedBlockTip(const CBlockIndex *pindex);

    /**
     * Called to notify CGovernanceManager that the smartnode index has been updated.
     * Must be called while not holding the CSmartnodeMan::cs mutex
     */
    void NotifySmartnodeUpdates(CConnman& connman);

};

#endif
