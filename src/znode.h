// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZNODE_H
#define ZNODE_H

#include "key.h"
#include "validation.h"
#include "net.h"
#include "spork.h"
#include "timedata.h"
#include "utiltime.h"

class CZnode;
class CZnodeBroadcast;
class CZnodePing;

static const int ZNODE_CHECK_SECONDS               =   5;
static const int ZNODE_MIN_MNB_SECONDS             =   5 * 60; //BROADCAST_TIME
static const int ZNODE_EXPIRATION_SECONDS          =  65 * 60;
static const int ZNODE_WATCHDOG_MAX_SECONDS        = 120 * 60;
static const int ZNODE_COIN_REQUIRED  = 1000;

static const int ZNODE_POSE_BAN_MAX_SCORE          = 5;

class CZnodeTimings {
    struct Mainnet {
        static const int ZnodeMinMnpSeconds                =  10 * 60; //PRE_ENABLE_TIME
        static const int ZnodeNewStartRequiredSeconds      = 180 * 60;
    };
    struct Regtest {
        static const int ZnodeMinMnpSeconds                = 30;
        static const int ZnodeNewStartRequiredSeconds      = 60;
    };
public:
    static int MinMnpSeconds();
    static int NewStartRequiredSeconds();
private:
    static CZnodeTimings & Inst();
    CZnodeTimings();
    CZnodeTimings(CZnodeTimings const &)=delete;
    void operator=(CZnodeTimings const &)=delete;
    int minMnp, newStartRequired;
};

#define ZNODE_MIN_MNP_SECONDS CZnodeTimings::MinMnpSeconds()
#define ZNODE_NEW_START_REQUIRED_SECONDS CZnodeTimings::NewStartRequiredSeconds()

//
// The Znode Ping Class : Contains a different serialize method for sending pings from znodes throughout the network
//

class CZnodePing
{
public:
    CTxIn vin;
    uint256 blockHash;
    int64_t sigTime; //mnb message times
    std::vector<unsigned char> vchSig;
    //removed stop

    CZnodePing() :
        vin(),
        blockHash(),
        sigTime(0),
        vchSig()
        {}

    CZnodePing(CTxIn& vinNew);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vin);
        READWRITE(blockHash);
        READWRITE(sigTime);
        READWRITE(vchSig);
    }

    void swap(CZnodePing& first, CZnodePing& second) // nothrow
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

    bool IsExpired() { return GetTime() - sigTime > ZNODE_NEW_START_REQUIRED_SECONDS; }

    bool Sign(CKey& keyZnode, CPubKey& pubKeyZnode);
    bool CheckSignature(CPubKey& pubKeyZnode, int &nDos);
    bool SimpleCheck(int& nDos);
    bool CheckAndUpdate(CZnode* pmn, bool fFromNewBroadcast, int& nDos);
    void Relay();

    CZnodePing& operator=(CZnodePing from)
    {
        swap(*this, from);
        return *this;
    }
    friend bool operator==(const CZnodePing& a, const CZnodePing& b)
    {
        return a.vin == b.vin && a.blockHash == b.blockHash;
    }
    friend bool operator!=(const CZnodePing& a, const CZnodePing& b)
    {
        return !(a == b);
    }

};

struct znode_info_t
{
    znode_info_t()
        : vin(),
          addr(),
          pubKeyCollateralAddress(),
          pubKeyZnode(),
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
    CPubKey pubKeyZnode;
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
// The Znode Class. For managing the Darksend process. It contains the input of the 1000DRK, signature to prove
// it's the one who own that ip address and code for calculating the payment election.
//
class CZnode
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

public:
    enum state {
        ZNODE_PRE_ENABLED,
        ZNODE_ENABLED,
        ZNODE_EXPIRED,
        ZNODE_OUTPOINT_SPENT,
        ZNODE_UPDATE_REQUIRED,
        ZNODE_WATCHDOG_EXPIRED,
        ZNODE_NEW_START_REQUIRED,
        ZNODE_POSE_BAN
    };

    CTxIn vin;
    CService addr;
    CPubKey pubKeyCollateralAddress;
    CPubKey pubKeyZnode;
    CZnodePing lastPing;
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

    // KEEP TRACK OF GOVERNANCE ITEMS EACH ZNODE HAS VOTE UPON FOR RECALCULATION
    std::map<uint256, int> mapGovernanceObjectsVotedOn;

    CZnode();
    CZnode(const CZnode& other);
    CZnode(const CZnodeBroadcast& mnb);
    CZnode(CService addrNew, CTxIn vinNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyZnodeNew, int nProtocolVersionIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        LOCK(cs);
        READWRITE(vin);
        READWRITE(addr);
        READWRITE(pubKeyCollateralAddress);
        READWRITE(pubKeyZnode);
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

    void swap(CZnode& first, CZnode& second) // nothrow
    {
        // enable ADL (not necessary in our case, but good practice)
        using std::swap;

        // by swapping the members of two classes,
        // the two classes are effectively swapped
        swap(first.vin, second.vin);
        swap(first.addr, second.addr);
        swap(first.pubKeyCollateralAddress, second.pubKeyCollateralAddress);
        swap(first.pubKeyZnode, second.pubKeyZnode);
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

    bool UpdateFromNewBroadcast(CZnodeBroadcast& mnb);

    void Check(bool fForce = false);

    bool IsBroadcastedWithin(int nSeconds) { return GetAdjustedTime() - sigTime < nSeconds; }

    bool IsPingedWithin(int nSeconds, int64_t nTimeToCheckAt = -1)
    {
        if(lastPing == CZnodePing()) return false;

        if(nTimeToCheckAt == -1) {
            nTimeToCheckAt = GetAdjustedTime();
        }
        return nTimeToCheckAt - lastPing.sigTime < nSeconds;
    }

    bool IsEnabled() { return nActiveState == ZNODE_ENABLED; }
    bool IsPreEnabled() { return nActiveState == ZNODE_PRE_ENABLED; }
    bool IsPoSeBanned() { return nActiveState == ZNODE_POSE_BAN; }
    // NOTE: this one relies on nPoSeBanScore, not on nActiveState as everything else here
    bool IsPoSeVerified() { return nPoSeBanScore <= -ZNODE_POSE_BAN_MAX_SCORE; }
    bool IsExpired() { return nActiveState == ZNODE_EXPIRED; }
    bool IsOutpointSpent() { return nActiveState == ZNODE_OUTPOINT_SPENT; }
    bool IsUpdateRequired() { return nActiveState == ZNODE_UPDATE_REQUIRED; }
    bool IsWatchdogExpired() { return nActiveState == ZNODE_WATCHDOG_EXPIRED; }
    bool IsNewStartRequired() { return nActiveState == ZNODE_NEW_START_REQUIRED; }

    static bool IsValidStateForAutoStart(int nActiveStateIn)
    {
        return  nActiveStateIn == ZNODE_ENABLED ||
                nActiveStateIn == ZNODE_PRE_ENABLED ||
                nActiveStateIn == ZNODE_EXPIRED ||
                nActiveStateIn == ZNODE_WATCHDOG_EXPIRED;
    }

    bool IsValidForPayment();

    static bool IsLegacyWindow(int height);

    bool IsValidNetAddr();
    static bool IsValidNetAddr(CService addrIn);

    void IncreasePoSeBanScore() { if(nPoSeBanScore < ZNODE_POSE_BAN_MAX_SCORE) nPoSeBanScore++; }
    void DecreasePoSeBanScore() { if(nPoSeBanScore > -ZNODE_POSE_BAN_MAX_SCORE) nPoSeBanScore--; }

    znode_info_t GetInfo();

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

    CZnode& operator=(CZnode from)
    {
        swap(*this, from);
        return *this;
    }
    friend bool operator==(const CZnode& a, const CZnode& b)
    {
        return a.vin == b.vin;
    }
    friend bool operator!=(const CZnode& a, const CZnode& b)
    {
        return !(a.vin == b.vin);
    }

};


//
// The Znode Broadcast Class : Contains a different serialize method for sending znodes through the network
//

class CZnodeBroadcast : public CZnode
{
public:

    bool fRecovery;

    CZnodeBroadcast() : CZnode(), fRecovery(false) {}
    CZnodeBroadcast(const CZnode& mn) : CZnode(mn), fRecovery(false) {}
    CZnodeBroadcast(CService addrNew, CTxIn vinNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyZnodeNew, int nProtocolVersionIn) :
        CZnode(addrNew, vinNew, pubKeyCollateralAddressNew, pubKeyZnodeNew, nProtocolVersionIn), fRecovery(false) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vin);
        READWRITE(addr);
        READWRITE(pubKeyCollateralAddress);
        READWRITE(pubKeyZnode);
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

    /// Create Znode broadcast, needs to be relayed manually after that
    static bool Create(CTxIn vin, CService service, CKey keyCollateralAddressNew, CPubKey pubKeyCollateralAddressNew, CKey keyZnodeNew, CPubKey pubKeyZnodeNew, std::string &strErrorRet, CZnodeBroadcast &mnbRet);
    static bool Create(std::string strService, std::string strKey, std::string strTxHash, std::string strOutputIndex, std::string& strErrorRet, CZnodeBroadcast &mnbRet, bool fOffline = false);

    bool SimpleCheck(int& nDos);
    bool Update(CZnode* pmn, int& nDos);
    bool CheckOutpoint(int& nDos);

    bool Sign(CKey& keyCollateralAddress);
    bool CheckSignature(int& nDos);
    void RelayZNode();
};

class CZnodeVerification
{
public:
    CTxIn vin1;
    CTxIn vin2;
    CService addr;
    int nonce;
    int nBlockHeight;
    std::vector<unsigned char> vchSig1;
    std::vector<unsigned char> vchSig2;

    CZnodeVerification() :
        vin1(),
        vin2(),
        addr(),
        nonce(0),
        nBlockHeight(0),
        vchSig1(),
        vchSig2()
        {}

    CZnodeVerification(CService addr, int nonce, int nBlockHeight) :
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
    inline void SerializationOp(Stream& s, Operation ser_action) {
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
        CInv inv(MSG_ZNODE_VERIFY, GetHash());
        g_connman->RelayInv(inv);
    }
};

#endif
