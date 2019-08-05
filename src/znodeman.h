// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZNODEMAN_H
#define ZNODEMAN_H

#include "znode.h"
#include "sync.h"

using namespace std;

class CZnodeMan;

extern CZnodeMan mnodeman;

/**
 * Provides a forward and reverse index between MN vin's and integers.
 *
 * This mapping is normally add-only and is expected to be permanent
 * It is only rebuilt if the size of the index exceeds the expected maximum number
 * of MN's and the current number of known MN's.
 *
 * The external interface to this index is provided via delegation by CZnodeMan
 */
class CZnodeIndex
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
    CZnodeIndex();

    int GetSize() const {
        return nSize;
    }

    /// Retrieve znode vin by index
    bool Get(int nIndex, CTxIn& vinZnode) const;

    /// Get index of a znode vin
    int GetZnodeIndex(const CTxIn& vinZnode) const;

    void AddZnodeVIN(const CTxIn& vinZnode);

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

class CZnodeMan
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

    static const int MIN_POSE_PROTO_VERSION     = 70203;
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
    std::vector<CZnode> vZnodes;
    // who's asked for the Znode list and the last time
    std::map<CNetAddr, int64_t> mAskedUsForZnodeList;
    // who we asked for the Znode list and the last time
    std::map<CNetAddr, int64_t> mWeAskedForZnodeList;
    // which Znodes we've asked for
    std::map<COutPoint, std::map<CNetAddr, int64_t> > mWeAskedForZnodeListEntry;
    // who we asked for the znode verification
    std::map<CNetAddr, CZnodeVerification> mWeAskedForVerification;

    // these maps are used for znode recovery from ZNODE_NEW_START_REQUIRED state
    std::map<uint256, std::pair< int64_t, std::set<CNetAddr> > > mMnbRecoveryRequests;
    std::map<uint256, std::vector<CZnodeBroadcast> > mMnbRecoveryGoodReplies;
    std::list< std::pair<CService, uint256> > listScheduledMnbRequestConnections;

    int64_t nLastIndexRebuildTime;

    CZnodeIndex indexZnodes;

    CZnodeIndex indexZnodesOld;

    /// Set when index has been rebuilt, clear when read
    bool fIndexRebuilt;

    /// Set when znodes are added, cleared when CGovernanceManager is notified
    bool fZnodesAdded;

    /// Set when znodes are removed, cleared when CGovernanceManager is notified
    bool fZnodesRemoved;

    std::vector<uint256> vecDirtyGovernanceObjectHashes;

    int64_t nLastWatchdogVoteTime;

    friend class CZnodeSync;

public:
    // Keep track of all broadcasts I've seen
    std::map<uint256, std::pair<int64_t, CZnodeBroadcast> > mapSeenZnodeBroadcast;
    // Keep track of all pings I've seen
    std::map<uint256, CZnodePing> mapSeenZnodePing;
    // Keep track of all verifications I've seen
    std::map<uint256, CZnodeVerification> mapSeenZnodeVerification;
    // keep track of dsq count to prevent znodes from gaming darksend queue
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

        READWRITE(vZnodes);
        READWRITE(mAskedUsForZnodeList);
        READWRITE(mWeAskedForZnodeList);
        READWRITE(mWeAskedForZnodeListEntry);
        READWRITE(mMnbRecoveryRequests);
        READWRITE(mMnbRecoveryGoodReplies);
        READWRITE(nLastWatchdogVoteTime);
        READWRITE(nDsqCount);

        READWRITE(mapSeenZnodeBroadcast);
        READWRITE(mapSeenZnodePing);
        READWRITE(indexZnodes);
        if(ser_action.ForRead() && (strVersion != SERIALIZATION_VERSION_STRING)) {
            Clear();
        }
    }

    CZnodeMan();

    /// Add an entry
    bool Add(CZnode &mn);

    /// Ask (source) node for mnb
    void AskForMN(CNode *pnode, const CTxIn &vin);
    void AskForMnb(CNode *pnode, const uint256 &hash);

    /// Check all Znodes
    void Check();

    /// Check all Znodes and remove inactive
    void CheckAndRemove();

    /// Clear Znode vector
    void Clear();

    /// Count Znodes filtered by nProtocolVersion.
    /// Znode nProtocolVersion should match or be above the one specified in param here.
    int CountZnodes(int nProtocolVersion = -1);
    /// Count enabled Znodes filtered by nProtocolVersion.
    /// Znode nProtocolVersion should match or be above the one specified in param here.
    int CountEnabled(int nProtocolVersion = -1);

    /// Count Znodes by network type - NET_IPV4, NET_IPV6, NET_TOR
    // int CountByIP(int nNetworkType);

    void DsegUpdate(CNode* pnode);

    /// Find an entry
    CZnode* Find(const std::string &txHash, const std::string outputIndex);
    CZnode* Find(const CScript &payee);
    CZnode* Find(const CTxIn& vin);
    CZnode* Find(const CPubKey& pubKeyZnode);

    /// Versions of Find that are safe to use from outside the class
    bool Get(const CPubKey& pubKeyZnode, CZnode& znode);
    bool Get(const CTxIn& vin, CZnode& znode);

    /// Retrieve znode vin by index
    bool Get(int nIndex, CTxIn& vinZnode, bool& fIndexRebuiltOut) {
        LOCK(cs);
        fIndexRebuiltOut = fIndexRebuilt;
        return indexZnodes.Get(nIndex, vinZnode);
    }

    bool GetIndexRebuiltFlag() {
        LOCK(cs);
        return fIndexRebuilt;
    }

    /// Get index of a znode vin
    int GetZnodeIndex(const CTxIn& vinZnode) {
        LOCK(cs);
        return indexZnodes.GetZnodeIndex(vinZnode);
    }

    /// Get old index of a znode vin
    int GetZnodeIndexOld(const CTxIn& vinZnode) {
        LOCK(cs);
        return indexZnodesOld.GetZnodeIndex(vinZnode);
    }

    /// Get znode VIN for an old index value
    bool GetZnodeVinForIndexOld(int nZnodeIndex, CTxIn& vinZnodeOut) {
        LOCK(cs);
        return indexZnodesOld.Get(nZnodeIndex, vinZnodeOut);
    }

    /// Get index of a znode vin, returning rebuild flag
    int GetZnodeIndex(const CTxIn& vinZnode, bool& fIndexRebuiltOut) {
        LOCK(cs);
        fIndexRebuiltOut = fIndexRebuilt;
        return indexZnodes.GetZnodeIndex(vinZnode);
    }

    void ClearOldZnodeIndex() {
        LOCK(cs);
        indexZnodesOld.Clear();
        fIndexRebuilt = false;
    }

    bool Has(const CTxIn& vin);

    znode_info_t GetZnodeInfo(const CTxIn& vin);

    znode_info_t GetZnodeInfo(const CPubKey& pubKeyZnode);

    char* GetNotQualifyReason(CZnode& mn, int nBlockHeight, bool fFilterSigTime, int nMnCount);

    UniValue GetNotQualifyReasonToUniValue(CZnode& mn, int nBlockHeight, bool fFilterSigTime, int nMnCount);

    /// Find an entry in the znode list that is next to be paid
    CZnode* GetNextZnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCount);
    /// Same as above but use current block height
    CZnode* GetNextZnodeInQueueForPayment(bool fFilterSigTime, int& nCount);

    /// Find a random entry
    CZnode* FindRandomNotInVec(const std::vector<CTxIn> &vecToExclude, int nProtocolVersion = -1);

    std::vector<CZnode> GetFullZnodeVector() { LOCK(cs); return vZnodes; }

    std::vector<std::pair<int, CZnode> > GetZnodeRanks(int nBlockHeight = -1, int nMinProtocol=0, bool nPublish=false);
    int GetZnodeRank(const CTxIn &vin, int nBlockHeight, int nMinProtocol=0, bool fOnlyActive=true);
    CZnode* GetZnodeByRank(int nRank, int nBlockHeight, int nMinProtocol=0, bool fOnlyActive=true);

    void ProcessZnodeConnections();
    std::pair<CService, std::set<uint256> > PopScheduledMnbRequestConnection();

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

    void DoFullVerificationStep();
    void CheckSameAddr();
    bool SendVerifyRequest(const CAddress& addr, const std::vector<CZnode*>& vSortedByAddr);
    void SendVerifyReply(CNode* pnode, CZnodeVerification& mnv);
    void ProcessVerifyReply(CNode* pnode, CZnodeVerification& mnv);
    void ProcessVerifyBroadcast(CNode* pnode, const CZnodeVerification& mnv);

    /// Return the number of (unique) Znodes
    int size() { LOCK(cs); return vZnodes.size(); }

    std::string ToString() const;

    /// Update znode list and maps using provided CZnodeBroadcast
    void UpdateZnodeList(CZnodeBroadcast mnb);
    /// Perform complete check and only then update list and maps
    bool CheckMnbAndUpdateZnodeList(CNode* pfrom, CZnodeBroadcast mnb, int& nDos);
    bool IsMnbRecoveryRequested(const uint256& hash) { return mMnbRecoveryRequests.count(hash); }

    void UpdateLastPaid();

    void CheckAndRebuildZnodeIndex();

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

    void CheckZnode(const CTxIn& vin, bool fForce = false);
    void CheckZnode(const CPubKey& pubKeyZnode, bool fForce = false);

    int GetZnodeState(const CTxIn& vin);
    int GetZnodeState(const CPubKey& pubKeyZnode);

    bool IsZnodePingedWithin(const CTxIn& vin, int nSeconds, int64_t nTimeToCheckAt = -1);
    void SetZnodeLastPing(const CTxIn& vin, const CZnodePing& mnp);

    void UpdatedBlockTip(const CBlockIndex *pindex);

    /**
     * Called to notify CGovernanceManager that the znode index has been updated.
     * Must be called while not holding the CZnodeMan::cs mutex
     */
    void NotifyZnodeUpdates();

};

#endif
