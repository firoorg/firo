// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SMARTNODEMAN_H
#define SMARTNODEMAN_H

#include "smartnode.h"
#include "../sync.h"

using namespace std;

class CSmartnodeMan;

extern CSmartnodeMan mnodeman;

/**
 * Provides a forward and reverse index between MN vin's and integers.
 *
 * This mapping is normally add-only and is expected to be permanent
 * It is only rebuilt if the size of the index exceeds the expected maximum number
 * of MN's and the current number of known MN's.
 *
 * The external interface to this index is provided via delegation by CSmartnodeMan
 */
class CSmartnodeIndex
{
public: // Types
    typedef std::map<CTxIn,int> index_m_t;

    typedef index_m_t::iterator index_m_it;

    typedef index_m_t::const_iterator index_m_cit;

    typedef std::map<int,CTxIn> rindex_m_t;

    typedef rindex_m_t::iterator rindex_m_it;

    typedef rindex_m_t::const_iterator rindex_m_cit;

private:
    int                  nSize;

    index_m_t            mapIndex;

    rindex_m_t           mapReverseIndex;

public:
    CSmartnodeIndex();

    int GetSize() const {
        return nSize;
    }

    /// Retrieve smartnode vin by index
    bool Get(int nIndex, CTxIn& vinSmartnode) const;

    /// Get index of a smartnode vin
    int GetSmartnodeIndex(const CTxIn& vinSmartnode) const;

    void AddSmartnodeVIN(const CTxIn& vinSmartnode);

    void Clear();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(mapIndex);
        if(ser_action.ForRead()) {
            RebuildIndex();
        }
    }

private:
    void RebuildIndex();

};

class CSmartnodeMan
{
public:
    typedef std::map<CTxIn,int> index_m_t;

    typedef index_m_t::iterator index_m_it;

    typedef index_m_t::const_iterator index_m_cit;

private:
    static const int MAX_EXPECTED_INDEX_SIZE = 30000;

    /// Only allow 1 index rebuild per hour
    static const int64_t MIN_INDEX_REBUILD_TIME = 3600;

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

    // Keep track of current block index
    const CBlockIndex *pCurrentBlockIndex;

    // map to hold all MNs
    std::vector<CSmartnode> vSmartnodes;
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

    int64_t nLastIndexRebuildTime;

    CSmartnodeIndex indexSmartnodes;

    CSmartnodeIndex indexSmartnodesOld;

    /// Set when index has been rebuilt, clear when read
    bool fIndexRebuilt;

    /// Set when smartnodes are added, cleared when CGovernanceManager is notified
    bool fSmartnodesAdded;

    /// Set when smartnodes are removed, cleared when CGovernanceManager is notified
    bool fSmartnodesRemoved;

    std::vector<uint256> vecDirtyGovernanceObjectHashes;

    int64_t nLastWatchdogVoteTime;

    friend class CSmartnodeSync;

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

        READWRITE(vSmartnodes);
        READWRITE(mAskedUsForSmartnodeList);
        READWRITE(mWeAskedForSmartnodeList);
        READWRITE(mWeAskedForSmartnodeListEntry);
        READWRITE(mMnbRecoveryRequests);
        READWRITE(mMnbRecoveryGoodReplies);
        READWRITE(nLastWatchdogVoteTime);
        READWRITE(nDsqCount);

        READWRITE(mapSeenSmartnodeBroadcast);
        READWRITE(mapSeenSmartnodePing);
        READWRITE(indexSmartnodes);
        if(ser_action.ForRead() && (strVersion != SERIALIZATION_VERSION_STRING)) {
            Clear();
        }
    }

    CSmartnodeMan();

    /// Add an entry
    bool Add(CSmartnode &mn);

    /// Ask (source) node for mnb
    void AskForMN(CNode *pnode, const CTxIn &vin);
    void AskForMnb(CNode *pnode, const uint256 &hash);

    /// Check all Smartnodes
    void Check();

    /// Check all Smartnodes and remove inactive
    void CheckAndRemove();

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

    void DsegUpdate(CNode* pnode);

    /// Find an entry
    CSmartnode* Find(const CScript &payee);
    CSmartnode* Find(const CTxIn& vin);
    CSmartnode* Find(const CPubKey& pubKeySmartnode);

    /// Versions of Find that are safe to use from outside the class
    bool Get(const CPubKey& pubKeySmartnode, CSmartnode& smartnode);
    bool Get(const CTxIn& vin, CSmartnode& smartnode);

    /// Retrieve smartnode vin by index
    bool Get(int nIndex, CTxIn& vinSmartnode, bool& fIndexRebuiltOut) {
        LOCK(cs);
        fIndexRebuiltOut = fIndexRebuilt;
        return indexSmartnodes.Get(nIndex, vinSmartnode);
    }

    bool GetIndexRebuiltFlag() {
        LOCK(cs);
        return fIndexRebuilt;
    }

    /// Get index of a smartnode vin
    int GetSmartnodeIndex(const CTxIn& vinSmartnode) {
        LOCK(cs);
        return indexSmartnodes.GetSmartnodeIndex(vinSmartnode);
    }

    /// Get old index of a smartnode vin
    int GetSmartnodeIndexOld(const CTxIn& vinSmartnode) {
        LOCK(cs);
        return indexSmartnodesOld.GetSmartnodeIndex(vinSmartnode);
    }

    /// Get smartnode VIN for an old index value
    bool GetSmartnodeVinForIndexOld(int nSmartnodeIndex, CTxIn& vinSmartnodeOut) {
        LOCK(cs);
        return indexSmartnodesOld.Get(nSmartnodeIndex, vinSmartnodeOut);
    }

    /// Get index of a smartnode vin, returning rebuild flag
    int GetSmartnodeIndex(const CTxIn& vinSmartnode, bool& fIndexRebuiltOut) {
        LOCK(cs);
        fIndexRebuiltOut = fIndexRebuilt;
        return indexSmartnodes.GetSmartnodeIndex(vinSmartnode);
    }

    void ClearOldSmartnodeIndex() {
        LOCK(cs);
        indexSmartnodesOld.Clear();
        fIndexRebuilt = false;
    }

    bool Has(const CTxIn& vin);

    smartnode_info_t GetSmartnodeInfo(const CTxIn& vin);

    smartnode_info_t GetSmartnodeInfo(const CPubKey& pubKeySmartnode);

    /// Find an entry in the smartnode list that is next to be paid
    CSmartnode* GetNextSmartnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCount);
    /// Same as above but use current block height
    CSmartnode* GetNextSmartnodeInQueueForPayment(bool fFilterSigTime, int& nCount);

    /// Find a random entry
    CSmartnode* FindRandomNotInVec(const std::vector<CTxIn> &vecToExclude, int nProtocolVersion = -1);

    std::vector<CSmartnode> GetFullSmartnodeVector() { return vSmartnodes; }

    std::vector<std::pair<int, CSmartnode> > GetSmartnodeRanks(int nBlockHeight = -1, int nMinProtocol=0);
    int GetSmartnodeRank(const CTxIn &vin, int nBlockHeight, int nMinProtocol=0, bool fOnlyActive=true);
    CSmartnode* GetSmartnodeByRank(int nRank, int nBlockHeight, int nMinProtocol=0, bool fOnlyActive=true);

    void ProcessSmartnodeConnections();
    std::pair<CService, std::set<uint256> > PopScheduledMnbRequestConnection();

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

    void DoFullVerificationStep();
    void CheckSameAddr();
    bool SendVerifyRequest(const CAddress& addr, const std::vector<CSmartnode*>& vSortedByAddr);
    void SendVerifyReply(CNode* pnode, CSmartnodeVerification& mnv);
    void ProcessVerifyReply(CNode* pnode, CSmartnodeVerification& mnv);
    void ProcessVerifyBroadcast(CNode* pnode, const CSmartnodeVerification& mnv);

    /// Return the number of (unique) Smartnodes
    int size() { return vSmartnodes.size(); }

    std::string ToString() const;

    /// Update smartnode list and maps using provided CSmartnodeBroadcast
    void UpdateSmartnodeList(CSmartnodeBroadcast mnb);
    /// Perform complete check and only then update list and maps
    bool CheckMnbAndUpdateSmartnodeList(CNode* pfrom, CSmartnodeBroadcast mnb, int& nDos);
    bool IsMnbRecoveryRequested(const uint256& hash) { return mMnbRecoveryRequests.count(hash); }

    void UpdateLastPaid();

    void CheckAndRebuildSmartnodeIndex();

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
    void UpdateWatchdogVoteTime(const CTxIn& vin);
    bool AddGovernanceVote(const CTxIn& vin, uint256 nGovernanceObjectHash);
    void RemoveGovernanceObject(uint256 nGovernanceObjectHash);

    void CheckSmartnode(const CTxIn& vin, bool fForce = false);
    void CheckSmartnode(const CPubKey& pubKeySmartnode, bool fForce = false);

    int GetSmartnodeState(const CTxIn& vin);
    int GetSmartnodeState(const CPubKey& pubKeySmartnode);

    bool IsSmartnodePingedWithin(const CTxIn& vin, int nSeconds, int64_t nTimeToCheckAt = -1);
    void SetSmartnodeLastPing(const CTxIn& vin, const CSmartnodePing& mnp);

    void UpdatedBlockTip(const CBlockIndex *pindex);

    /**
     * Called to notify CGovernanceManager that the smartnode index has been updated.
     * Must be called while not holding the CSmartnodeMan::cs mutex
     */
    void NotifySmartnodeUpdates();

};

#endif
