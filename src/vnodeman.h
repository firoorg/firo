// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VNODEMAN_H
#define VNODEMAN_H

#include "vnode.h"
#include "sync.h"

using namespace std;

class CVnodeMan;

extern CVnodeMan mnodeman;

/**
 * Provides a forward and reverse index between MN vin's and integers.
 *
 * This mapping is normally add-only and is expected to be permanent
 * It is only rebuilt if the size of the index exceeds the expected maximum number
 * of MN's and the current number of known MN's.
 *
 * The external interface to this index is provided via delegation by CVnodeMan
 */
class CVnodeIndex
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
    CVnodeIndex();

    int GetSize() const {
        return nSize;
    }

    /// Retrieve vnode vin by index
    bool Get(int nIndex, CTxIn& vinVnode) const;

    /// Get index of a vnode vin
    int GetVnodeIndex(const CTxIn& vinVnode) const;

    void AddVnodeVIN(const CTxIn& vinVnode);

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

class CVnodeMan
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
    std::vector<CVnode> vVnodes;
    // who's asked for the Vnode list and the last time
    std::map<CNetAddr, int64_t> mAskedUsForVnodeList;
    // who we asked for the Vnode list and the last time
    std::map<CNetAddr, int64_t> mWeAskedForVnodeList;
    // which Vnodes we've asked for
    std::map<COutPoint, std::map<CNetAddr, int64_t> > mWeAskedForVnodeListEntry;
    // who we asked for the vnode verification
    std::map<CNetAddr, CVnodeVerification> mWeAskedForVerification;

    // these maps are used for vnode recovery from VNODE_NEW_START_REQUIRED state
    std::map<uint256, std::pair< int64_t, std::set<CNetAddr> > > mMnbRecoveryRequests;
    std::map<uint256, std::vector<CVnodeBroadcast> > mMnbRecoveryGoodReplies;
    std::list< std::pair<CService, uint256> > listScheduledMnbRequestConnections;

    int64_t nLastIndexRebuildTime;

    CVnodeIndex indexVnodes;

    CVnodeIndex indexVnodesOld;

    /// Set when index has been rebuilt, clear when read
    bool fIndexRebuilt;

    /// Set when vnodes are added, cleared when CGovernanceManager is notified
    bool fVnodesAdded;

    /// Set when vnodes are removed, cleared when CGovernanceManager is notified
    bool fVnodesRemoved;

    std::vector<uint256> vecDirtyGovernanceObjectHashes;

    int64_t nLastWatchdogVoteTime;

    friend class CVnodeSync;

public:
    // Keep track of all broadcasts I've seen
    std::map<uint256, std::pair<int64_t, CVnodeBroadcast> > mapSeenVnodeBroadcast;
    // Keep track of all pings I've seen
    std::map<uint256, CVnodePing> mapSeenVnodePing;
    // Keep track of all verifications I've seen
    std::map<uint256, CVnodeVerification> mapSeenVnodeVerification;
    // keep track of dsq count to prevent vnodes from gaming darksend queue
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

        READWRITE(vVnodes);
        READWRITE(mAskedUsForVnodeList);
        READWRITE(mWeAskedForVnodeList);
        READWRITE(mWeAskedForVnodeListEntry);
        READWRITE(mMnbRecoveryRequests);
        READWRITE(mMnbRecoveryGoodReplies);
        READWRITE(nLastWatchdogVoteTime);
        READWRITE(nDsqCount);

        READWRITE(mapSeenVnodeBroadcast);
        READWRITE(mapSeenVnodePing);
        READWRITE(indexVnodes);
        if(ser_action.ForRead() && (strVersion != SERIALIZATION_VERSION_STRING)) {
            Clear();
        }
    }

    CVnodeMan();

    /// Add an entry
    bool Add(CVnode &mn);

    /// Ask (source) node for mnb
    void AskForMN(CNode *pnode, const CTxIn &vin);
    void AskForMnb(CNode *pnode, const uint256 &hash);

    /// Check all Vnodes
    void Check();

    /// Check all Vnodes and remove inactive
    void CheckAndRemove();

    /// Clear Vnode vector
    void Clear();

    /// Count Vnodes filtered by nProtocolVersion.
    /// Vnode nProtocolVersion should match or be above the one specified in param here.
    int CountVnodes(int nProtocolVersion = -1);
    /// Count enabled Vnodes filtered by nProtocolVersion.
    /// Vnode nProtocolVersion should match or be above the one specified in param here.
    int CountEnabled(int nProtocolVersion = -1);

    /// Count Vnodes by network type - NET_IPV4, NET_IPV6, NET_TOR
    // int CountByIP(int nNetworkType);

    void DsegUpdate(CNode* pnode);

    /// Find an entry
    CVnode* Find(const CScript &payee);
    CVnode* Find(const CTxIn& vin);
    CVnode* Find(const CPubKey& pubKeyVnode);

    /// Versions of Find that are safe to use from outside the class
    bool Get(const CPubKey& pubKeyVnode, CVnode& vnode);
    bool Get(const CTxIn& vin, CVnode& vnode);

    /// Retrieve vnode vin by index
    bool Get(int nIndex, CTxIn& vinVnode, bool& fIndexRebuiltOut) {
        LOCK(cs);
        fIndexRebuiltOut = fIndexRebuilt;
        return indexVnodes.Get(nIndex, vinVnode);
    }

    bool GetIndexRebuiltFlag() {
        LOCK(cs);
        return fIndexRebuilt;
    }

    /// Get index of a vnode vin
    int GetVnodeIndex(const CTxIn& vinVnode) {
        LOCK(cs);
        return indexVnodes.GetVnodeIndex(vinVnode);
    }

    /// Get old index of a vnode vin
    int GetVnodeIndexOld(const CTxIn& vinVnode) {
        LOCK(cs);
        return indexVnodesOld.GetVnodeIndex(vinVnode);
    }

    /// Get vnode VIN for an old index value
    bool GetVnodeVinForIndexOld(int nVnodeIndex, CTxIn& vinVnodeOut) {
        LOCK(cs);
        return indexVnodesOld.Get(nVnodeIndex, vinVnodeOut);
    }

    /// Get index of a vnode vin, returning rebuild flag
    int GetVnodeIndex(const CTxIn& vinVnode, bool& fIndexRebuiltOut) {
        LOCK(cs);
        fIndexRebuiltOut = fIndexRebuilt;
        return indexVnodes.GetVnodeIndex(vinVnode);
    }

    void ClearOldVnodeIndex() {
        LOCK(cs);
        indexVnodesOld.Clear();
        fIndexRebuilt = false;
    }

    bool Has(const CTxIn& vin);

    vnode_info_t GetVnodeInfo(const CTxIn& vin);

    vnode_info_t GetVnodeInfo(const CPubKey& pubKeyVnode);

    char* GetNotQualifyReason(CVnode& mn, int nBlockHeight, bool fFilterSigTime, int nMnCount);

    /// Find an entry in the vnode list that is next to be paid
    CVnode* GetNextVnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCount);
    /// Same as above but use current block height
    CVnode* GetNextVnodeInQueueForPayment(bool fFilterSigTime, int& nCount);

    /// Find a random entry
    CVnode* FindRandomNotInVec(const std::vector<CTxIn> &vecToExclude, int nProtocolVersion = -1);

    std::vector<CVnode> GetFullVnodeVector() { return vVnodes; }

    std::vector<std::pair<int, CVnode> > GetVnodeRanks(int nBlockHeight = -1, int nMinProtocol=0);
    int GetVnodeRank(const CTxIn &vin, int nBlockHeight, int nMinProtocol=0, bool fOnlyActive=true);
    CVnode* GetVnodeByRank(int nRank, int nBlockHeight, int nMinProtocol=0, bool fOnlyActive=true);

    void ProcessVnodeConnections();
    std::pair<CService, std::set<uint256> > PopScheduledMnbRequestConnection();

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

    void DoFullVerificationStep();
    void CheckSameAddr();
    bool SendVerifyRequest(const CAddress& addr, const std::vector<CVnode*>& vSortedByAddr);
    void SendVerifyReply(CNode* pnode, CVnodeVerification& mnv);
    void ProcessVerifyReply(CNode* pnode, CVnodeVerification& mnv);
    void ProcessVerifyBroadcast(CNode* pnode, const CVnodeVerification& mnv);

    /// Return the number of (unique) Vnodes
    int size() { return vVnodes.size(); }

    std::string ToString() const;

    /// Update vnode list and maps using provided CVnodeBroadcast
    void UpdateVnodeList(CVnodeBroadcast mnb);
    /// Perform complete check and only then update list and maps
    bool CheckMnbAndUpdateVnodeList(CNode* pfrom, CVnodeBroadcast mnb, int& nDos);
    bool IsMnbRecoveryRequested(const uint256& hash) { return mMnbRecoveryRequests.count(hash); }

    void UpdateLastPaid();

    void CheckAndRebuildVnodeIndex();

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

    void CheckVnode(const CTxIn& vin, bool fForce = false);
    void CheckVnode(const CPubKey& pubKeyVnode, bool fForce = false);

    int GetVnodeState(const CTxIn& vin);
    int GetVnodeState(const CPubKey& pubKeyVnode);

    bool IsVnodePingedWithin(const CTxIn& vin, int nSeconds, int64_t nTimeToCheckAt = -1);
    void SetVnodeLastPing(const CTxIn& vin, const CVnodePing& mnp);

    void UpdatedBlockTip(const CBlockIndex *pindex);

    /**
     * Called to notify CGovernanceManager that the vnode index has been updated.
     * Must be called while not holding the CVnodeMan::cs mutex
     */
    void NotifyVnodeUpdates();

};

#endif
