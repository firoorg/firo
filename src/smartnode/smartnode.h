// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SMARTNODE_H
#define SMARTNODE_H

#include "../key.h"
#include "../main.h"
#include "spork.h"

class CSmartnode;
class CSmartnodeBroadcast;
class CConnman;

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

// sentinel version before sentinel ping implementation
#define DEFAULT_SENTINEL_VERSION 0x010001

class CSmartnodePing
{
public:
    CTxIn vin{};
    uint256 blockHash{};
    int64_t sigTime{}; //mnb message times
    std::vector<unsigned char> vchSig{};
    bool fSentinelIsCurrent = false; // true if last sentinel ping was actual
    // MSB is always 0, other 3 bits corresponds to x.x.x version scheme
    uint32_t nSentinelVersion{DEFAULT_SENTINEL_VERSION};

    CSmartnodePing() = default;

    CSmartnodePing(const COutPoint& outpoint);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vin);
        READWRITE(blockHash);
        READWRITE(sigTime);
        READWRITE(vchSig);
        if(ser_action.ForRead() && (s.size() == 0))
        {
            fSentinelIsCurrent = false;
            nSentinelVersion = DEFAULT_SENTINEL_VERSION;
            return;
        }
        READWRITE(fSentinelIsCurrent);
        READWRITE(nSentinelVersion);
    }

    uint256 GetHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << vin;
        ss << sigTime;
        return ss.GetHash();
    }

    bool IsExpired() const { return GetAdjustedTime() - sigTime > SMARTNODE_NEW_START_REQUIRED_SECONDS; }

    bool Sign(const CKey& keySmartnode, const CPubKey& pubKeySmartnode);
    bool CheckSignature(CPubKey& pubKeySmartnode, int &nDos);
    bool SimpleCheck(int& nDos);
    bool CheckAndUpdate(CSmartnode* pmn, bool fFromNewBroadcast, int& nDos, CConnman& connman);
    void Relay(CConnman& connman);
};

inline bool operator==(const CSmartnodePing& a, const CSmartnodePing& b)
{
    return a.vin == b.vin && a.blockHash == b.blockHash;
}
inline bool operator!=(const CSmartnodePing& a, const CSmartnodePing& b)
{
    return !(a == b);
}

struct smartnode_info_t
{
    // Note: all these constructors can be removed once C++14 is enabled.
    // (in C++11 the member initializers wrongly disqualify this as an aggregate)
    smartnode_info_t() = default;
    smartnode_info_t(smartnode_info_t const&) = default;

    smartnode_info_t(int activeState, int protoVer, int64_t sTime) :
        nActiveState{activeState}, nProtocolVersion{protoVer}, sigTime{sTime} {}

    smartnode_info_t(int activeState, int protoVer, int64_t sTime,
                      COutPoint const& outpoint, CService const& addr,
                      CPubKey const& pkCollAddr, CPubKey const& pkMN,
                      int64_t tWatchdogV = 0) :
        nActiveState{activeState}, nProtocolVersion{protoVer}, sigTime{sTime},
        vin{outpoint}, addr{addr},
        pubKeyCollateralAddress{pkCollAddr}, pubKeySmartnode{pkMN},
        nTimeLastWatchdogVote{tWatchdogV} {}

    int nActiveState = 0;
    int nProtocolVersion = 0;
    int64_t sigTime = 0; //mnb message time

    CTxIn vin{};
    CService addr{};
    CPubKey pubKeyCollateralAddress{};
    CPubKey pubKeySmartnode{};
    int64_t nTimeLastWatchdogVote = 0;

    int64_t nLastDsq = 0; //the dsq count from the last dsq broadcast of this node
    int64_t nTimeLastChecked = 0;
    int64_t nTimeLastPaid = 0;
    int64_t nTimeLastPing = 0; //* not in CMN
    bool fInfoValid = false; //* not in CMN
};

//
// The Smartnode Class. For managing the Darksend process. It contains the input of the 1000DRK, signature to prove
// it's the one who own that ip address and code for calculating the payment election.
//
class CSmartnode : public smartnode_info_t
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

    enum CollateralStatus {
        COLLATERAL_OK,
        COLLATERAL_UTXO_NOT_FOUND,
        COLLATERAL_INVALID_AMOUNT
    };


    CSmartnodePing lastPing{};
    std::vector<unsigned char> vchSig{};

    uint256 nCollateralMinConfBlockHash{};
    int nBlockLastPaid{};
    int nPoSeBanScore{};
    int nPoSeBanHeight{};
    bool fAllowMixingTx{};
    bool fUnitTest = false;

    // KEEP TRACK OF GOVERNANCE ITEMS EACH SMARTNODE HAS VOTE UPON FOR RECALCULATION
    std::map<uint256, int> mapGovernanceObjectsVotedOn;

    CSmartnode();
    CSmartnode(const CSmartnode& other);
    CSmartnode(const CSmartnodeBroadcast& mnb);
    CSmartnode(CService addrNew, COutPoint outpointNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeySmartnodeNew, int nProtocolVersionIn);

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
        READWRITE(nCollateralMinConfBlockHash);
        READWRITE(nBlockLastPaid);
        READWRITE(nProtocolVersion);
        READWRITE(nPoSeBanScore);
        READWRITE(nPoSeBanHeight);
        READWRITE(fAllowMixingTx);
        READWRITE(fUnitTest);
        READWRITE(mapGovernanceObjectsVotedOn);
    }

    // CALCULATE A RANK AGAINST OF GIVEN BLOCK
    arith_uint256 CalculateScore(const uint256& blockHash);

    bool UpdateFromNewBroadcast(CSmartnodeBroadcast& mnb, CConnman& connman);

    static CollateralStatus CheckCollateral(const COutPoint& outpoint);
    static CollateralStatus CheckCollateral(const COutPoint& outpoint, int& nHeightRet);
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

    bool IsValidForPayment()
    {
        if(nActiveState == SMARTNODE_ENABLED) {
            return true;
        }
        if(!sporkManager.IsSporkActive(SPORK_14_REQUIRE_SENTINEL_FLAG) &&
           (nActiveState == SMARTNODE_WATCHDOG_EXPIRED)) {
            return true;
        }

        return false;
    }

    /// Is the input associated with collateral public key? (and there is 1000 DASH - checking if valid smartnode)
    bool IsInputAssociatedWithPubkey();

    bool IsValidNetAddr();
    static bool IsValidNetAddr(CService addrIn);

    void IncreasePoSeBanScore() { if(nPoSeBanScore < SMARTNODE_POSE_BAN_MAX_SCORE) nPoSeBanScore++; }
    void DecreasePoSeBanScore() { if(nPoSeBanScore > -SMARTNODE_POSE_BAN_MAX_SCORE) nPoSeBanScore--; }
    void PoSeBan() { nPoSeBanScore = SMARTNODE_POSE_BAN_MAX_SCORE; }

    smartnode_info_t GetInfo();

    static std::string StateToString(int nStateIn);
    std::string GetStateString() const;
    std::string GetStatus() const;

    int GetLastPaidTime() { return nTimeLastPaid; }
    int GetLastPaidBlock() { return nBlockLastPaid; }
    void UpdateLastPaid(const CBlockIndex *pindex, int nMaxBlocksToScanBack);

    // KEEP TRACK OF EACH GOVERNANCE ITEM INCASE THIS NODE GOES OFFLINE, SO WE CAN RECALC THEIR STATUS
    void AddGovernanceVote(uint256 nGovernanceObjectHash);
    // RECALCULATE CACHED STATUS FLAGS FOR ALL AFFECTED OBJECTS
    void FlagGovernanceItemsAsDirty();

    void RemoveGovernanceObject(uint256 nGovernanceObjectHash);

    void UpdateWatchdogVoteTime(uint64_t nVoteTime = 0);

    CSmartnode& operator=(CSmartnode const& from)
    {
        static_cast<smartnode_info_t&>(*this)=from;
        lastPing = from.lastPing;
        vchSig = from.vchSig;
        nCollateralMinConfBlockHash = from.nCollateralMinConfBlockHash;
        nBlockLastPaid = from.nBlockLastPaid;
        nPoSeBanScore = from.nPoSeBanScore;
        nPoSeBanHeight = from.nPoSeBanHeight;
        fAllowMixingTx = from.fAllowMixingTx;
        fUnitTest = from.fUnitTest;
        mapGovernanceObjectsVotedOn = from.mapGovernanceObjectsVotedOn;
        return *this;
    }
};

inline bool operator==(const CSmartnode& a, const CSmartnode& b)
{
    return a.vin == b.vin;
}
inline bool operator!=(const CSmartnode& a, const CSmartnode& b)
{
    return !(a.vin == b.vin);
}


//
// The Smartnode Broadcast Class : Contains a different serialize method for sending smartnodes through the network
//

class CSmartnodeBroadcast : public CSmartnode
{
public:

    bool fRecovery;

    CSmartnodeBroadcast() : CSmartnode(), fRecovery(false) {}
    CSmartnodeBroadcast(const CSmartnode& mn) : CSmartnode(mn), fRecovery(false) {}
    CSmartnodeBroadcast(CService addrNew, COutPoint outpointNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeySmartnodeNew, int nProtocolVersionIn) :
        CSmartnode(addrNew, outpointNew, pubKeyCollateralAddressNew, pubKeySmartnodeNew, nProtocolVersionIn), fRecovery(false) {}

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
    static bool Create(const COutPoint& outpoint, const CService& service, const CKey& keyCollateralAddressNew, const CPubKey& pubKeyCollateralAddressNew, const CKey& keySmartnodeNew, const CPubKey& pubKeySmartnodeNew, std::string &strErrorRet, CSmartnodeBroadcast &mnbRet);
    static bool Create(std::string strService, std::string strKey, std::string strTxHash, std::string strOutputIndex, std::string& strErrorRet, CSmartnodeBroadcast &mnbRet, bool fOffline = false);

    bool SimpleCheck(int& nDos);
    bool Update(CSmartnode* pmn, int& nDos, CConnman& connman);
    bool CheckOutpoint(int& nDos);

    bool Sign(const CKey& keyCollateralAddress);
    bool CheckSignature(int& nDos);
    void Relay(CConnman& connman);
};

class CSmartnodeVerification
{
public:
    CTxIn vin1{};
    CTxIn vin2{};
    CService addr{};
    int nonce{};
    int nBlockHeight{};
    std::vector<unsigned char> vchSig1{};
    std::vector<unsigned char> vchSig2{};

    CSmartnodeVerification() = default;

    CSmartnodeVerification(CService addr, int nonce, int nBlockHeight) :
        addr(addr),
        nonce(nonce),
        nBlockHeight(nBlockHeight)
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
        g_connman->RelayInv(inv);
    }
};

#endif
