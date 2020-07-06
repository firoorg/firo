// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "init.h"
#include "znode.h"
#include "util.h"
#include "net.h"
#include "netbase.h"
#include "base58.h"

#include <boost/lexical_cast.hpp>

CZnodeTimings::CZnodeTimings()
{
    if(Params().GetConsensus().IsRegtest()) {
        minMnp = Regtest::ZnodeMinMnpSeconds;
        newStartRequired = Regtest::ZnodeNewStartRequiredSeconds;
    } else {
        minMnp = Mainnet::ZnodeMinMnpSeconds;
        newStartRequired = Mainnet::ZnodeNewStartRequiredSeconds;
    }
}

CZnodeTimings & CZnodeTimings::Inst() {
    static CZnodeTimings inst;
    return inst;
}

int CZnodeTimings::MinMnpSeconds() {
    return Inst().minMnp;
}

int CZnodeTimings::NewStartRequiredSeconds() {
    return Inst().newStartRequired;
}


CZnode::CZnode() :
        vin(),
        addr(),
        pubKeyCollateralAddress(),
        pubKeyZnode(),
        vchSig(),
        sigTime(GetAdjustedTime()),
        nLastDsq(0),
        nTimeLastChecked(0),
        nTimeLastPaid(0),
        nTimeLastWatchdogVote(0),
        nActiveState(ZNODE_ENABLED),
        nCacheCollateralBlock(0),
        nBlockLastPaid(0),
        nProtocolVersion(LEGACY_ZNODES_PROTOCOL_VERSION),
        nPoSeBanScore(0),
        nPoSeBanHeight(0),
        fAllowMixingTx(true),
        fUnitTest(false) {}

CZnode::CZnode(CService addrNew, CTxIn vinNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyZnodeNew, int nProtocolVersionIn) :
        vin(vinNew),
        addr(addrNew),
        pubKeyCollateralAddress(pubKeyCollateralAddressNew),
        pubKeyZnode(pubKeyZnodeNew),
        vchSig(),
        sigTime(GetAdjustedTime()),
        nLastDsq(0),
        nTimeLastChecked(0),
        nTimeLastPaid(0),
        nTimeLastWatchdogVote(0),
        nActiveState(ZNODE_ENABLED),
        nCacheCollateralBlock(0),
        nBlockLastPaid(0),
        nProtocolVersion(nProtocolVersionIn),
        nPoSeBanScore(0),
        nPoSeBanHeight(0),
        fAllowMixingTx(true),
        fUnitTest(false) {}

CZnode::CZnode(const CZnode &other) :
        vin(other.vin),
        addr(other.addr),
        pubKeyCollateralAddress(other.pubKeyCollateralAddress),
        pubKeyZnode(other.pubKeyZnode),
        vchSig(other.vchSig),
        sigTime(other.sigTime),
        nLastDsq(other.nLastDsq),
        nTimeLastChecked(other.nTimeLastChecked),
        nTimeLastPaid(other.nTimeLastPaid),
        nTimeLastWatchdogVote(other.nTimeLastWatchdogVote),
        nActiveState(other.nActiveState),
        nCacheCollateralBlock(other.nCacheCollateralBlock),
        nBlockLastPaid(other.nBlockLastPaid),
        nProtocolVersion(other.nProtocolVersion),
        nPoSeBanScore(other.nPoSeBanScore),
        nPoSeBanHeight(other.nPoSeBanHeight),
        fAllowMixingTx(other.fAllowMixingTx),
        fUnitTest(other.fUnitTest) {}

//
// Deterministically calculate a given "score" for a Znode depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
arith_uint256 CZnode::CalculateScore(const uint256 &blockHash) {
    return arith_uint256();
}

void CZnode::Check(bool fForce) {
}

bool CZnode::IsLegacyWindow(int height) {
    const Consensus::Params& params = ::Params().GetConsensus();
    return height >= params.DIP0003Height && height < params.DIP0003EnforcementHeight;
}

bool CZnode::IsValidNetAddr() {
    return IsValidNetAddr(addr);
}

bool CZnode::IsValidForPayment() {
    if (nActiveState == ZNODE_ENABLED) {
        return true;
    }
//    if(!sporkManager.IsSporkActive(SPORK_14_REQUIRE_SENTINEL_FLAG) &&
//       (nActiveState == ZNODE_WATCHDOG_EXPIRED)) {
//        return true;
//    }

    return false;
}

bool CZnode::IsValidNetAddr(CService addrIn) {
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return Params().NetworkIDString() == CBaseChainParams::REGTEST ||
           (addrIn.IsIPv4() && IsReachable(addrIn) && addrIn.IsRoutable());
}

znode_info_t CZnode::GetInfo() {
    znode_info_t info;
    info.vin = vin;
    info.addr = addr;
    info.pubKeyCollateralAddress = pubKeyCollateralAddress;
    info.pubKeyZnode = pubKeyZnode;
    info.sigTime = sigTime;
    info.nLastDsq = nLastDsq;
    info.nTimeLastChecked = nTimeLastChecked;
    info.nTimeLastPaid = nTimeLastPaid;
    info.nTimeLastWatchdogVote = nTimeLastWatchdogVote;
    info.nActiveState = nActiveState;
    info.nProtocolVersion = nProtocolVersion;
    info.fInfoValid = true;
    return info;
}

std::string CZnode::StateToString(int nStateIn) {
    switch (nStateIn) {
        case ZNODE_PRE_ENABLED:
            return "PRE_ENABLED";
        case ZNODE_ENABLED:
            return "ENABLED";
        case ZNODE_EXPIRED:
            return "EXPIRED";
        case ZNODE_OUTPOINT_SPENT:
            return "OUTPOINT_SPENT";
        case ZNODE_UPDATE_REQUIRED:
            return "UPDATE_REQUIRED";
        case ZNODE_WATCHDOG_EXPIRED:
            return "WATCHDOG_EXPIRED";
        case ZNODE_NEW_START_REQUIRED:
            return "NEW_START_REQUIRED";
        case ZNODE_POSE_BAN:
            return "POSE_BAN";
        default:
            return "UNKNOWN";
    }
}

std::string CZnode::GetStateString() const {
    return StateToString(nActiveState);
}

std::string CZnode::GetStatus() const {
    // TODO: return smth a bit more human readable here
    return GetStateString();
}

std::string CZnode::ToString() const {
    std::string str;
    str += "znode{";
    str += addr.ToString();
    str += " ";
    str += std::to_string(nProtocolVersion);
    str += " ";
    str += vin.prevout.ToStringShort();
    str += " ";
    str += CBitcoinAddress(pubKeyCollateralAddress.GetID()).ToString();
    str += " ";
    str += std::to_string(nBlockLastPaid);
    str += "}\n";
    return str;
}

int CZnode::GetCollateralAge() {
    int nHeight;
    {
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain || !chainActive.Tip()) return -1;
        nHeight = chainActive.Height();
    }

    if (nCacheCollateralBlock == 0) {
        int nInputAge = GetInputAge(vin);
        if (nInputAge > 0) {
            nCacheCollateralBlock = nHeight - nInputAge;
        } else {
            return nInputAge;
        }
    }

    return nHeight - nCacheCollateralBlock;
}

void CZnode::UpdateLastPaid(const CBlockIndex *pindex, int nMaxBlocksToScanBack) {
}

void CZnode::UpdateWatchdogVoteTime() {
    LOCK(cs);
    nTimeLastWatchdogVote = GetTime();
}

/**
*   FLAG GOVERNANCE ITEMS AS DIRTY
*
*   - When znode come and go on the network, we must flag the items they voted on to recalc it's cached flags
*
*/
//void CZnode::FlagGovernanceItemsAsDirty()
//{
//    std::vector<uint256> vecDirty;
//    {
//        std::map<uint256, int>::iterator it = mapGovernanceObjectsVotedOn.begin();
//        while(it != mapGovernanceObjectsVotedOn.end()) {
//            vecDirty.push_back(it->first);
//            ++it;
//        }
//    }
//    for(size_t i = 0; i < vecDirty.size(); ++i) {
//        mnodeman.AddDirtyGovernanceObjectHash(vecDirty[i]);
//    }
//}
