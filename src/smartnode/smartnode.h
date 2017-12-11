// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SMARTNODE_H
#define SMARTNODE_H

#include "../key.h"
#include "../main.h"
#include "../net.h"
#include "spork.h"
#include "../timedata.h"
#include "../utiltime.h"

class CSmartnode;
class CSmartnodeBroadcast;
class CSmartnodePing;

static const int SMARTNODE_CHECK_SECONDS               =   5;
static const int SMARTNODE_MIN_MNB_SECONDS             =   5 * 60; //BROADCAST_TIME
static const int SMARTNODE_MIN_MNP_SECONDS             =  10 * 60; //PRE_ENABLE_TIME
static const int SMARTNODE_EXPIRATION_SECONDS          =  65 * 60;
static const int SMARTNODE_WATCHDOG_MAX_SECONDS        = 120 * 60;
static const int SMARTNODE_NEW_START_REQUIRED_SECONDS  = 180 * 60;
static const int SMARTNODE_COIN_REQUIRED  = 10000;

static const int SMARTNODE_POSE_BAN_MAX_SCORE          = 5;
//
// The Smartnode Ping Class : Contains a different serialize method for sending pings from smartnodes throughout the network
//

class CSmartnodePing
{
public:
    CTxIn vin;
    uint256 blockHash;
    int64_t sigTime; //mnb message times
    std::vector<unsigned char> vchSig;
    //removed stop

    CSmartnodePing() :
        vin(),
        blockHash(),
        sigTime(0),
        vchSig()
        {}

    CSmartnodePing(CTxIn& vinNew);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vin);
        READWRITE(blockHash);
        READWRITE(sigTime);
        READWRITE(vchSig);
    }

    void swap(CSmartnodePing& first, CSmartnodePing& second) // nothrow
    {
        // enable ADL (not necessary in our case, but good practice)
        using std::swap;

        // by swapping the members of two classes,
        // the two classes are effectively swapped
        swap(first.vin, second.vin);
        swap(first.blockHash, second.blockHash);
        swap(first.sigTime, second.sigTime);
        swap(first.vchSig, second.vchSig);
    }

    uint256 GetHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << vin;
        ss << sigTime;
        return ss.GetHash();
    }

    bool IsExpired() { return GetTime() - sigTime > SMARTNODE_NEW_START_REQUIRED_SECONDS; }

    bool Sign(CKey& keySmartnode, CPubKey& pubKeySmartnode);
    bool CheckSignature(CPubKey& pubKeySmartnode, int &nDos);
    bool SimpleCheck(int& nDos);
    bool CheckAndUpdate(CSmartnode* pmn, bool fFromNewBroadcast, int& nDos);
    void Relay();

    CSmartnodePing& operator=(CSmartnodePing from)
    {
        swap(*this, from);
        return *this;
    }
    friend bool operator==(const CSmartnodePing& a, const CSmartnodePing& b)
    {
        return a.vin == b.vin && a.blockHash == b.blockHash;
    }
    friend bool operator!=(const CSmartnodePing& a, const CSmartnodePing& b)
    {
        return !(a == b);
    }

};

struct smartnode_info_t
{
    smartnode_info_t()
        : vin(),
          addr(),
          pubKeyCollateralAddress(),
          pubKeySmartnode(),
          sigTime(0),
          nLastDsq(0),
          nTimeLastChecked(0),
          nTimeLastPaid(0),
          nTimeLastWatchdogVote(0),
          nTimeLastPing(0),
          nActiveState(0),
          nProtocolVersion(0),
          fInfoValid(false)
        {}

    CTxIn vin;
    CService addr;
    CPubKey pubKeyCollateralAddress;
    CPubKey pubKeySmartnode;
    int64_t sigTime; //mnb message time
    int64_t nLastDsq; //the dsq count from the last dsq broadcast of this node
    int64_t nTimeLastChecked;
    int64_t nTimeLastPaid;
    int64_t nTimeLastWatchdogVote;
    int64_t nTimeLastPing;
    int nActiveState;
    int nProtocolVersion;
    bool fInfoValid;
};

//
// The Smartnode Class. For managing the Darksend process. It contains the input of the 10000 SMART, signature to prove
// it's the one who own that ip address and code for calculating the payment election.
//
class CSmartnode
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

public:
    enum state {
        SMARTNODE_PRE_ENABLED,
        SMARTNODE_ENABLED,
        SMARTNODE_EXPIRED,
        SMARTNODE_OUTPOINT_SPENT,
        SMARTNODE_UPDATE_REQUIRED,
        SMARTNODE_WATCHDOG_EXPIRED,
        SMARTNODE_NEW_START_REQUIRED,
        SMARTNODE_POSE_BAN
    };

    CTxIn vin;
    CService addr;
    CPubKey pubKeyCollateralAddress;
    CPubKey pubKeySmartnode;
    CSmartnodePing lastPing;
    std::vector<unsigned char> vchSig;
    int64_t sigTime; //mnb message time
    int64_t nLastDsq; //the dsq count from the last dsq broadcast of this node
    int64_t nTimeLastChecked;
    int64_t nTimeLastPaid;
    int64_t nTimeLastWatchdogVote;
    int nActiveState;
    int nCacheCollateralBlock;
    int nBlockLastPaid;
    int nProtocolVersion;
    int nPoSeBanScore;
    int nPoSeBanHeight;
    bool fAllowMixingTx;
    bool fUnitTest;

    // KEEP TRACK OF GOVERNANCE ITEMS EACH SMARTNODE HAS VOTE UPON FOR RECALCULATION
    std::map<uint256, int> mapGovernanceObjectsVotedOn;

    CSmartnode();
    CSmartnode(const CSmartnode& other);
    CSmartnode(const CSmartnodeBroadcast& mnb);
    CSmartnode(CService addrNew, CTxIn vinNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeySmartnodeNew, int nProtocolVersionIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        LOCK(cs);
        READWRITE(vin);
        READWRITE(addr);
        READWRITE(pubKeyCollateralAddress);
        READWRITE(pubKeySmartnode);
        READWRITE(lastPing);
        READWRITE(vchSig);
        READWRITE(sigTime);
        READWRITE(nLastDsq);
        READWRITE(nTimeLastChecked);
        READWRITE(nTimeLastPaid);
        READWRITE(nTimeLastWatchdogVote);
        READWRITE(nActiveState);
        READWRITE(nCacheCollateralBlock);
        READWRITE(nBlockLastPaid);
        READWRITE(nProtocolVersion);
        READWRITE(nPoSeBanScore);
        READWRITE(nPoSeBanHeight);
        READWRITE(fAllowMixingTx);
        READWRITE(fUnitTest);
        READWRITE(mapGovernanceObjectsVotedOn);
    }

    void swap(CSmartnode& first, CSmartnode& second) // nothrow
    {
        // enable ADL (not necessary in our case, but good practice)
        using std::swap;

        // by swapping the members of two classes,
        // the two classes are effectively swapped
        swap(first.vin, second.vin);
        swap(first.addr, second.addr);
        swap(first.pubKeyCollateralAddress, second.pubKeyCollateralAddress);
        swap(first.pubKeySmartnode, second.pubKeySmartnode);
        swap(first.lastPing, second.lastPing);
        swap(first.vchSig, second.vchSig);
        swap(first.sigTime, second.sigTime);
        swap(first.nLastDsq, second.nLastDsq);
        swap(first.nTimeLastChecked, second.nTimeLastChecked);
        swap(first.nTimeLastPaid, second.nTimeLastPaid);
        swap(first.nTimeLastWatchdogVote, second.nTimeLastWatchdogVote);
        swap(first.nActiveState, second.nActiveState);
        swap(first.nCacheCollateralBlock, second.nCacheCollateralBlock);
        swap(first.nBlockLastPaid, second.nBlockLastPaid);
        swap(first.nProtocolVersion, second.nProtocolVersion);
        swap(first.nPoSeBanScore, second.nPoSeBanScore);
        swap(first.nPoSeBanHeight, second.nPoSeBanHeight);
        swap(first.fAllowMixingTx, second.fAllowMixingTx);
        swap(first.fUnitTest, second.fUnitTest);
        swap(first.mapGovernanceObjectsVotedOn, second.mapGovernanceObjectsVotedOn);
    }

    // CALCULATE A RANK AGAINST OF GIVEN BLOCK
    arith_uint256 CalculateScore(const uint256& blockHash);

    bool UpdateFromNewBroadcast(CSmartnodeBroadcast& mnb);

    void Check(bool fForce = false);

    bool IsBroadcastedWithin(int nSeconds) { return GetAdjustedTime() - sigTime < nSeconds; }

    bool IsPingedWithin(int nSeconds, int64_t nTimeToCheckAt = -1)
    {
        if(lastPing == CSmartnodePing()) return false;

        if(nTimeToCheckAt == -1) {
            nTimeToCheckAt = GetAdjustedTime();
        }
        return nTimeToCheckAt - lastPing.sigTime < nSeconds;
    }

    bool IsEnabled() { return nActiveState == SMARTNODE_ENABLED; }
    bool IsPreEnabled() { return nActiveState == SMARTNODE_PRE_ENABLED; }
    bool IsPoSeBanned() { return nActiveState == SMARTNODE_POSE_BAN; }
    // NOTE: this one relies on nPoSeBanScore, not on nActiveState as everything else here
    bool IsPoSeVerified() { return nPoSeBanScore <= -SMARTNODE_POSE_BAN_MAX_SCORE; }
    bool IsExpired() { return nActiveState == SMARTNODE_EXPIRED; }
    bool IsOutpointSpent() { return nActiveState == SMARTNODE_OUTPOINT_SPENT; }
    bool IsUpdateRequired() { return nActiveState == SMARTNODE_UPDATE_REQUIRED; }
    bool IsWatchdogExpired() { return nActiveState == SMARTNODE_WATCHDOG_EXPIRED; }
    bool IsNewStartRequired() { return nActiveState == SMARTNODE_NEW_START_REQUIRED; }

    static bool IsValidStateForAutoStart(int nActiveStateIn)
    {
        return  nActiveStateIn == SMARTNODE_ENABLED ||
                nActiveStateIn == SMARTNODE_PRE_ENABLED ||
                nActiveStateIn == SMARTNODE_EXPIRED ||
                nActiveStateIn == SMARTNODE_WATCHDOG_EXPIRED;
    }

    bool IsValidForPayment();

    bool IsValidNetAddr();
    static bool IsValidNetAddr(CService addrIn);

    void IncreasePoSeBanScore() { if(nPoSeBanScore < SMARTNODE_POSE_BAN_MAX_SCORE) nPoSeBanScore++; }
    void DecreasePoSeBanScore() { if(nPoSeBanScore > -SMARTNODE_POSE_BAN_MAX_SCORE) nPoSeBanScore--; }

    smartnode_info_t GetInfo();

    static std::string StateToString(int nStateIn);
    std::string GetStateString() const;
    std::string GetStatus() const;
    std::string ToString() const;

    int GetCollateralAge();

    int GetLastPaidTime() { return nTimeLastPaid; }
    int GetLastPaidBlock() { return nBlockLastPaid; }
    void UpdateLastPaid(const CBlockIndex *pindex, int nMaxBlocksToScanBack);

    // KEEP TRACK OF EACH GOVERNANCE ITEM INCASE THIS NODE GOES OFFLINE, SO WE CAN RECALC THEIR STATUS
    void AddGovernanceVote(uint256 nGovernanceObjectHash);
    // RECALCULATE CACHED STATUS FLAGS FOR ALL AFFECTED OBJECTS
    void FlagGovernanceItemsAsDirty();

    void RemoveGovernanceObject(uint256 nGovernanceObjectHash);

    void UpdateWatchdogVoteTime();

    CSmartnode& operator=(CSmartnode from)
    {
        swap(*this, from);
        return *this;
    }
    friend bool operator==(const CSmartnode& a, const CSmartnode& b)
    {
        return a.vin == b.vin;
    }
    friend bool operator!=(const CSmartnode& a, const CSmartnode& b)
    {
        return !(a.vin == b.vin);
    }

};


//
// The Smartnode Broadcast Class : Contains a different serialize method for sending smartnodes through the network
//

class CSmartnodeBroadcast : public CSmartnode
{
public:

    bool fRecovery;

    CSmartnodeBroadcast() : CSmartnode(), fRecovery(false) {}
    CSmartnodeBroadcast(const CSmartnode& mn) : CSmartnode(mn), fRecovery(false) {}
    CSmartnodeBroadcast(CService addrNew, CTxIn vinNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeySmartnodeNew, int nProtocolVersionIn) :
        CSmartnode(addrNew, vinNew, pubKeyCollateralAddressNew, pubKeySmartnodeNew, nProtocolVersionIn), fRecovery(false) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vin);
        READWRITE(addr);
        READWRITE(pubKeyCollateralAddress);
        READWRITE(pubKeySmartnode);
        READWRITE(vchSig);
        READWRITE(sigTime);
        READWRITE(nProtocolVersion);
        READWRITE(lastPing);
    }

    uint256 GetHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << vin;
        ss << pubKeyCollateralAddress;
        ss << sigTime;
        return ss.GetHash();
    }

    /// Create Smartnode broadcast, needs to be relayed manually after that
    static bool Create(CTxIn vin, CService service, CKey keyCollateralAddressNew, CPubKey pubKeyCollateralAddressNew, CKey keySmartnodeNew, CPubKey pubKeySmartnodeNew, std::string &strErrorRet, CSmartnodeBroadcast &mnbRet);
    static bool Create(std::string strService, std::string strKey, std::string strTxHash, std::string strOutputIndex, std::string& strErrorRet, CSmartnodeBroadcast &mnbRet, bool fOffline = false);

    bool SimpleCheck(int& nDos);
    bool Update(CSmartnode* pmn, int& nDos);
    bool CheckOutpoint(int& nDos);

    bool Sign(CKey& keyCollateralAddress);
    bool CheckSignature(int& nDos);
    void RelaySmartNode();
};

class CSmartnodeVerification
{
public:
    CTxIn vin1;
    CTxIn vin2;
    CService addr;
    int nonce;
    int nBlockHeight;
    std::vector<unsigned char> vchSig1;
    std::vector<unsigned char> vchSig2;

    CSmartnodeVerification() :
        vin1(),
        vin2(),
        addr(),
        nonce(0),
        nBlockHeight(0),
        vchSig1(),
        vchSig2()
        {}

    CSmartnodeVerification(CService addr, int nonce, int nBlockHeight) :
        vin1(),
        vin2(),
        addr(addr),
        nonce(nonce),
        nBlockHeight(nBlockHeight),
        vchSig1(),
        vchSig2()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vin1);
        READWRITE(vin2);
        READWRITE(addr);
        READWRITE(nonce);
        READWRITE(nBlockHeight);
        READWRITE(vchSig1);
        READWRITE(vchSig2);
    }

    uint256 GetHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << vin1;
        ss << vin2;
        ss << addr;
        ss << nonce;
        ss << nBlockHeight;
        return ss.GetHash();
    }

    void Relay() const
    {
        CInv inv(MSG_SMARTNODE_VERIFY, GetHash());
        RelayInv(inv);
    }
};

#endif
