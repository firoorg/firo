// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activesmartnode.h"
#include "consensus/validation.h"
#include "darksend.h"
#include "init.h"
//#include "governance.h"
#include "smartnode.h"
#include "smartnodepayments.h"
#include "smartnodesync.h"
#include "smartnodeman.h"
#include "util.h"

#include <boost/lexical_cast.hpp>


CSmartnode::CSmartnode() :
        vin(),
        addr(),
        pubKeyCollateralAddress(),
        pubKeySmartnode(),
        lastPing(),
        vchSig(),
        sigTime(GetAdjustedTime()),
        nLastDsq(0),
        nTimeLastChecked(0),
        nTimeLastPaid(0),
        nTimeLastWatchdogVote(0),
        nActiveState(SMARTNODE_ENABLED),
        nCacheCollateralBlock(0),
        nBlockLastPaid(0),
        nProtocolVersion(PROTOCOL_VERSION),
        nPoSeBanScore(0),
        nPoSeBanHeight(0),
        fAllowMixingTx(true),
        fUnitTest(false) {}

CSmartnode::CSmartnode(CService addrNew, CTxIn vinNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeySmartnodeNew, int nProtocolVersionIn) :
        vin(vinNew),
        addr(addrNew),
        pubKeyCollateralAddress(pubKeyCollateralAddressNew),
        pubKeySmartnode(pubKeySmartnodeNew),
        lastPing(),
        vchSig(),
        sigTime(GetAdjustedTime()),
        nLastDsq(0),
        nTimeLastChecked(0),
        nTimeLastPaid(0),
        nTimeLastWatchdogVote(0),
        nActiveState(SMARTNODE_ENABLED),
        nCacheCollateralBlock(0),
        nBlockLastPaid(0),
        nProtocolVersion(nProtocolVersionIn),
        nPoSeBanScore(0),
        nPoSeBanHeight(0),
        fAllowMixingTx(true),
        fUnitTest(false) {}

CSmartnode::CSmartnode(const CSmartnode &other) :
        vin(other.vin),
        addr(other.addr),
        pubKeyCollateralAddress(other.pubKeyCollateralAddress),
        pubKeySmartnode(other.pubKeySmartnode),
        lastPing(other.lastPing),
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

CSmartnode::CSmartnode(const CSmartnodeBroadcast &mnb) :
        vin(mnb.vin),
        addr(mnb.addr),
        pubKeyCollateralAddress(mnb.pubKeyCollateralAddress),
        pubKeySmartnode(mnb.pubKeySmartnode),
        lastPing(mnb.lastPing),
        vchSig(mnb.vchSig),
        sigTime(mnb.sigTime),
        nLastDsq(0),
        nTimeLastChecked(0),
        nTimeLastPaid(0),
        nTimeLastWatchdogVote(mnb.sigTime),
        nActiveState(mnb.nActiveState),
        nCacheCollateralBlock(0),
        nBlockLastPaid(0),
        nProtocolVersion(mnb.nProtocolVersion),
        nPoSeBanScore(0),
        nPoSeBanHeight(0),
        fAllowMixingTx(true),
        fUnitTest(false) {}

//CSporkManager sporkManager;
//
// When a new smartnode broadcast is sent, update our information
//
bool CSmartnode::UpdateFromNewBroadcast(CSmartnodeBroadcast &mnb) {
    if (mnb.sigTime <= sigTime && !mnb.fRecovery) return false;

    pubKeySmartnode = mnb.pubKeySmartnode;
    sigTime = mnb.sigTime;
    vchSig = mnb.vchSig;
    nProtocolVersion = mnb.nProtocolVersion;
    addr = mnb.addr;
    nPoSeBanScore = 0;
    nPoSeBanHeight = 0;
    nTimeLastChecked = 0;
    int nDos = 0;
    if (mnb.lastPing == CSmartnodePing() || (mnb.lastPing != CSmartnodePing() && mnb.lastPing.CheckAndUpdate(this, true, nDos))) {
        lastPing = mnb.lastPing;
        mnodeman.mapSeenSmartnodePing.insert(std::make_pair(lastPing.GetHash(), lastPing));
    }
    // if it matches our Smartnode privkey...
    if (fSmartNode && pubKeySmartnode == activeSmartnode.pubKeySmartnode) {
        nPoSeBanScore = -SMARTNODE_POSE_BAN_MAX_SCORE;
        if (nProtocolVersion == PROTOCOL_VERSION) {
            // ... and PROTOCOL_VERSION, then we've been remotely activated ...
            activeSmartnode.ManageState();
        } else {
            // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
            // but also do not ban the node we get this message from
            LogPrintf("CSmartnode::UpdateFromNewBroadcast -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", nProtocolVersion, PROTOCOL_VERSION);
            return false;
        }
    }
    return true;
}

//
// Deterministically calculate a given "score" for a Smartnode depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
arith_uint256 CSmartnode::CalculateScore(const uint256 &blockHash) {
    uint256 aux = ArithToUint256(UintToArith256(vin.prevout.hash) + vin.prevout.n);

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << blockHash;
    arith_uint256 hash2 = UintToArith256(ss.GetHash());

    CHashWriter ss2(SER_GETHASH, PROTOCOL_VERSION);
    ss2 << blockHash;
    ss2 << aux;
    arith_uint256 hash3 = UintToArith256(ss2.GetHash());

    return (hash3 > hash2 ? hash3 - hash2 : hash2 - hash3);
}

void CSmartnode::Check(bool fForce) {
    LOCK(cs);

    if (ShutdownRequested()) return;

    if (!fForce && (GetTime() - nTimeLastChecked < SMARTNODE_CHECK_SECONDS)) return;
    nTimeLastChecked = GetTime();

    LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state\n", vin.prevout.ToStringShort(), GetStateString());

    //once spent, stop doing the checks
    if (IsOutpointSpent()) return;

    int nHeight = 0;
    if (!fUnitTest) {
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain) return;

        CCoins coins;
        if (!pcoinsTip->GetCoins(vin.prevout.hash, coins) ||
            (unsigned int) vin.prevout.n >= coins.vout.size() ||
            coins.vout[vin.prevout.n].IsNull()) {
            nActiveState = SMARTNODE_OUTPOINT_SPENT;
            LogPrint("smartnode", "CSmartnode::Check -- Failed to find Smartnode UTXO, smartnode=%s\n", vin.prevout.ToStringShort());
            return;
        }

        nHeight = chainActive.Height();
    }

    if (IsPoSeBanned()) {
        if (nHeight < nPoSeBanHeight) return; // too early?
        // Otherwise give it a chance to proceed further to do all the usual checks and to change its state.
        // Smartnode still will be on the edge and can be banned back easily if it keeps ignoring mnverify
        // or connect attempts. Will require few mnverify messages to strengthen its position in mn list.
        LogPrintf("CSmartnode::Check -- Smartnode %s is unbanned and back in list now\n", vin.prevout.ToStringShort());
        DecreasePoSeBanScore();
    } else if (nPoSeBanScore >= SMARTNODE_POSE_BAN_MAX_SCORE) {
        nActiveState = SMARTNODE_POSE_BAN;
        // ban for the whole payment cycle
        nPoSeBanHeight = nHeight + mnodeman.size();
        LogPrintf("CSmartnode::Check -- Smartnode %s is banned till block %d now\n", vin.prevout.ToStringShort(), nPoSeBanHeight);
        return;
    }

    int nActiveStatePrev = nActiveState;
    bool fOurSmartnode = fSmartNode && activeSmartnode.pubKeySmartnode == pubKeySmartnode;

    // smartnode doesn't meet payment protocol requirements ...
    bool fRequireUpdate = nProtocolVersion < mnpayments.GetMinSmartnodePaymentsProto() ||
                          // or it's our own node and we just updated it to the new protocol but we are still waiting for activation ...
                          (fOurSmartnode && nProtocolVersion < PROTOCOL_VERSION);

    if (fRequireUpdate) {
        nActiveState = SMARTNODE_UPDATE_REQUIRED;
        if (nActiveStatePrev != nActiveState) {
            LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
        }
        return;
    }

    // keep old smartnodes on start, give them a chance to receive updates...
    bool fWaitForPing = !smartnodeSync.IsSmartnodeListSynced() && !IsPingedWithin(SMARTNODE_MIN_MNP_SECONDS);

    if (fWaitForPing && !fOurSmartnode) {
        // ...but if it was already expired before the initial check - return right away
        if (IsExpired() || IsWatchdogExpired() || IsNewStartRequired()) {
            LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state, waiting for ping\n", vin.prevout.ToStringShort(), GetStateString());
            return;
        }
    }

    // don't expire if we are still in "waiting for ping" mode unless it's our own smartnode
    if (!fWaitForPing || fOurSmartnode) {

        if (!IsPingedWithin(SMARTNODE_NEW_START_REQUIRED_SECONDS)) {
            nActiveState = SMARTNODE_NEW_START_REQUIRED;
            if (nActiveStatePrev != nActiveState) {
                LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
            }
            return;
        }

        bool fWatchdogActive = smartnodeSync.IsSynced() && mnodeman.IsWatchdogActive();
        bool fWatchdogExpired = (fWatchdogActive && ((GetTime() - nTimeLastWatchdogVote) > SMARTNODE_WATCHDOG_MAX_SECONDS));

//        LogPrint("smartnode", "CSmartnode::Check -- outpoint=%s, nTimeLastWatchdogVote=%d, GetTime()=%d, fWatchdogExpired=%d\n",
//                vin.prevout.ToStringShort(), nTimeLastWatchdogVote, GetTime(), fWatchdogExpired);

        if (fWatchdogExpired) {
            nActiveState = SMARTNODE_WATCHDOG_EXPIRED;
            if (nActiveStatePrev != nActiveState) {
                LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
            }
            return;
        }

        if (!IsPingedWithin(SMARTNODE_EXPIRATION_SECONDS)) {
            nActiveState = SMARTNODE_EXPIRED;
            if (nActiveStatePrev != nActiveState) {
                LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
            }
            return;
        }
    }

    if (lastPing.sigTime - sigTime < SMARTNODE_MIN_MNP_SECONDS) {
        nActiveState = SMARTNODE_PRE_ENABLED;
        if (nActiveStatePrev != nActiveState) {
            LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
        }
        return;
    }

    nActiveState = SMARTNODE_ENABLED; // OK
    if (nActiveStatePrev != nActiveState) {
        LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
    }
}

bool CSmartnode::IsValidNetAddr() {
    return IsValidNetAddr(addr);
}

bool CSmartnode::IsValidForPayment() {
    if (nActiveState == SMARTNODE_ENABLED) {
        return true;
    }
//    if(!sporkManager.IsSporkActive(SPORK_14_REQUIRE_SENTINEL_FLAG) &&
//       (nActiveState == SMARTNODE_WATCHDOG_EXPIRED)) {
//        return true;
//    }

    return false;
}

bool CSmartnode::IsValidNetAddr(CService addrIn) {
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return Params().NetworkIDString() == CBaseChainParams::REGTEST ||
           (addrIn.IsIPv4() && IsReachable(addrIn) && addrIn.IsRoutable());
}

smartnode_info_t CSmartnode::GetInfo() {
    smartnode_info_t info;
    info.vin = vin;
    info.addr = addr;
    info.pubKeyCollateralAddress = pubKeyCollateralAddress;
    info.pubKeySmartnode = pubKeySmartnode;
    info.sigTime = sigTime;
    info.nLastDsq = nLastDsq;
    info.nTimeLastChecked = nTimeLastChecked;
    info.nTimeLastPaid = nTimeLastPaid;
    info.nTimeLastWatchdogVote = nTimeLastWatchdogVote;
    info.nTimeLastPing = lastPing.sigTime;
    info.nActiveState = nActiveState;
    info.nProtocolVersion = nProtocolVersion;
    info.fInfoValid = true;
    return info;
}

std::string CSmartnode::StateToString(int nStateIn) {
    switch (nStateIn) {
        case SMARTNODE_PRE_ENABLED:
            return "PRE_ENABLED";
        case SMARTNODE_ENABLED:
            return "ENABLED";
        case SMARTNODE_EXPIRED:
            return "EXPIRED";
        case SMARTNODE_OUTPOINT_SPENT:
            return "OUTPOINT_SPENT";
        case SMARTNODE_UPDATE_REQUIRED:
            return "UPDATE_REQUIRED";
        case SMARTNODE_WATCHDOG_EXPIRED:
            return "WATCHDOG_EXPIRED";
        case SMARTNODE_NEW_START_REQUIRED:
            return "NEW_START_REQUIRED";
        case SMARTNODE_POSE_BAN:
            return "POSE_BAN";
        default:
            return "UNKNOWN";
    }
}

std::string CSmartnode::GetStateString() const {
    return StateToString(nActiveState);
}

std::string CSmartnode::GetStatus() const {
    // TODO: return smth a bit more human readable here
    return GetStateString();
}

std::string CSmartnode::ToString() const {
    std::string str;
    str += "smartnode{";
    str += addr.ToString();
    str += " ";
    str += std::to_string(nProtocolVersion);
    str += " ";
    str += vin.prevout.ToStringShort();
    str += " ";
    str += CBitcoinAddress(pubKeyCollateralAddress.GetID()).ToString();
    str += " ";
    str += std::to_string(lastPing == CSmartnodePing() ? sigTime : lastPing.sigTime);
    str += " ";
    str += std::to_string(lastPing == CSmartnodePing() ? 0 : lastPing.sigTime - sigTime);
    str += " ";
    str += std::to_string(nBlockLastPaid);
    str += "}\n";
    return str;
}

int CSmartnode::GetCollateralAge() {
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

void CSmartnode::UpdateLastPaid(const CBlockIndex *pindex, int nMaxBlocksToScanBack) {
    if (!pindex) {
        LogPrintf("CSmartnode::UpdateLastPaid pindex is NULL\n");
        return;
    }

    const CBlockIndex *BlockReading = pindex;

    CScript mnpayee = GetScriptForDestination(pubKeyCollateralAddress.GetID());
    LogPrint("smartnode", "CSmartnode::UpdateLastPaidBlock -- searching for block with payment to %s\n", vin.prevout.ToStringShort());

    LOCK(cs_mapSmartnodeBlocks);

    for (int i = 0; BlockReading && BlockReading->nHeight > nBlockLastPaid && i < nMaxBlocksToScanBack; i++) {
//        LogPrintf("mnpayments.mapSmartnodeBlocks.count(BlockReading->nHeight)=%s\n", mnpayments.mapSmartnodeBlocks.count(BlockReading->nHeight));
//        LogPrintf("mnpayments.mapSmartnodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(mnpayee, 2)=%s\n", mnpayments.mapSmartnodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(mnpayee, 2));
        if (mnpayments.mapSmartnodeBlocks.count(BlockReading->nHeight) &&
            mnpayments.mapSmartnodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(mnpayee, 2)) {
            LogPrintf("i=%s, BlockReading->nHeight=%s\n", i, BlockReading->nHeight);
            CBlock block;
            if (!ReadBlockFromDisk(block, BlockReading, Params().GetConsensus())) // shouldn't really happen
            {
                LogPrintf("ReadBlockFromDisk failed\n");
                continue;
            }

            CAmount nSmartnodePayment = GetSmartnodePayment(BlockReading->nHeight, block.vtx[0].GetValueOut());

            BOOST_FOREACH(CTxOut
            txout, block.vtx[0].vout)
            if (mnpayee == txout.scriptPubKey && nSmartnodePayment == txout.nValue) {
                nBlockLastPaid = BlockReading->nHeight;
                nTimeLastPaid = BlockReading->nTime;
                LogPrint("smartnode", "CSmartnode::UpdateLastPaidBlock -- searching for block with payment to %s -- found new %d\n", vin.prevout.ToStringShort(), nBlockLastPaid);
                return;
            }
        }

        if (BlockReading->pprev == NULL) {
            assert(BlockReading);
            break;
        }
        BlockReading = BlockReading->pprev;
    }

    // Last payment for this smartnode wasn't found in latest mnpayments blocks
    // or it was found in mnpayments blocks but wasn't found in the blockchain.
    // LogPrint("smartnode", "CSmartnode::UpdateLastPaidBlock -- searching for block with payment to %s -- keeping old %d\n", vin.prevout.ToStringShort(), nBlockLastPaid);
}

bool CSmartnodeBroadcast::Create(std::string strService, std::string strKeySmartnode, std::string strTxHash, std::string strOutputIndex, std::string &strErrorRet, CSmartnodeBroadcast &mnbRet, bool fOffline) {
    LogPrintf("CSmartnodeBroadcast::Create\n");
    CTxIn txin;
    CPubKey pubKeyCollateralAddressNew;
    CKey keyCollateralAddressNew;
    CPubKey pubKeySmartnodeNew;
    CKey keySmartnodeNew;
    //need correct blocks to send ping
    if (!fOffline && !smartnodeSync.IsBlockchainSynced()) {
        strErrorRet = "Sync in progress. Must wait until sync is complete to start Smartnode";
        LogPrintf("CSmartnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    //TODO
    if (!darkSendSigner.GetKeysFromSecret(strKeySmartnode, keySmartnodeNew, pubKeySmartnodeNew)) {
        strErrorRet = strprintf("Invalid smartnode key %s", strKeySmartnode);
        LogPrintf("CSmartnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    if (!pwalletMain->GetSmartnodeVinAndKeys(txin, pubKeyCollateralAddressNew, keyCollateralAddressNew, strTxHash, strOutputIndex)) {
        strErrorRet = strprintf("Could not allocate txin %s:%s for smartnode %s", strTxHash, strOutputIndex, strService);
        LogPrintf("CSmartnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    CService service = CService(strService);
    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (service.GetPort() != mainnetDefaultPort) {
            strErrorRet = strprintf("Invalid port %u for smartnode %s, only %d is supported on mainnet.", service.GetPort(), strService, mainnetDefaultPort);
            LogPrintf("CSmartnodeBroadcast::Create -- %s\n", strErrorRet);
            return false;
        }
    } else if (service.GetPort() == mainnetDefaultPort) {
        strErrorRet = strprintf("Invalid port %u for smartnode %s, %d is the only supported on mainnet.", service.GetPort(), strService, mainnetDefaultPort);
        LogPrintf("CSmartnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    return Create(txin, CService(strService), keyCollateralAddressNew, pubKeyCollateralAddressNew, keySmartnodeNew, pubKeySmartnodeNew, strErrorRet, mnbRet);
}

bool CSmartnodeBroadcast::Create(CTxIn txin, CService service, CKey keyCollateralAddressNew, CPubKey pubKeyCollateralAddressNew, CKey keySmartnodeNew, CPubKey pubKeySmartnodeNew, std::string &strErrorRet, CSmartnodeBroadcast &mnbRet) {
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    LogPrint("smartnode", "CSmartnodeBroadcast::Create -- pubKeyCollateralAddressNew = %s, pubKeySmartnodeNew.GetID() = %s\n",
             CBitcoinAddress(pubKeyCollateralAddressNew.GetID()).ToString(),
             pubKeySmartnodeNew.GetID().ToString());


    CSmartnodePing mnp(txin);
    if (!mnp.Sign(keySmartnodeNew, pubKeySmartnodeNew)) {
        strErrorRet = strprintf("Failed to sign ping, smartnode=%s", txin.prevout.ToStringShort());
        LogPrintf("CSmartnodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CSmartnodeBroadcast();
        return false;
    }

    mnbRet = CSmartnodeBroadcast(service, txin, pubKeyCollateralAddressNew, pubKeySmartnodeNew, PROTOCOL_VERSION);

    if (!mnbRet.IsValidNetAddr()) {
        strErrorRet = strprintf("Invalid IP address, smartnode=%s", txin.prevout.ToStringShort());
        LogPrintf("CSmartnodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CSmartnodeBroadcast();
        return false;
    }

    mnbRet.lastPing = mnp;
    if (!mnbRet.Sign(keyCollateralAddressNew)) {
        strErrorRet = strprintf("Failed to sign broadcast, smartnode=%s", txin.prevout.ToStringShort());
        LogPrintf("CSmartnodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CSmartnodeBroadcast();
        return false;
    }

    return true;
}

bool CSmartnodeBroadcast::SimpleCheck(int &nDos) {
    nDos = 0;

    // make sure addr is valid
    if (!IsValidNetAddr()) {
        LogPrintf("CSmartnodeBroadcast::SimpleCheck -- Invalid addr, rejected: smartnode=%s  addr=%s\n",
                  vin.prevout.ToStringShort(), addr.ToString());
        return false;
    }

    // make sure signature isn't in the future (past is OK)
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintf("CSmartnodeBroadcast::SimpleCheck -- Signature rejected, too far into the future: smartnode=%s\n", vin.prevout.ToStringShort());
        nDos = 1;
        return false;
    }

    // empty ping or incorrect sigTime/unknown blockhash
    if (lastPing == CSmartnodePing() || !lastPing.SimpleCheck(nDos)) {
        // one of us is probably forked or smth, just mark it as expired and check the rest of the rules
        nActiveState = SMARTNODE_EXPIRED;
    }

    if (nProtocolVersion < mnpayments.GetMinSmartnodePaymentsProto()) {
        LogPrintf("CSmartnodeBroadcast::SimpleCheck -- ignoring outdated Smartnode: smartnode=%s  nProtocolVersion=%d\n", vin.prevout.ToStringShort(), nProtocolVersion);
        return false;
    }

    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    if (pubkeyScript.size() != 25) {
        LogPrintf("CSmartnodeBroadcast::SimpleCheck -- pubKeyCollateralAddress has the wrong size\n");
        nDos = 100;
        return false;
    }

    CScript pubkeyScript2;
    pubkeyScript2 = GetScriptForDestination(pubKeySmartnode.GetID());

    if (pubkeyScript2.size() != 25) {
        LogPrintf("CSmartnodeBroadcast::SimpleCheck -- pubKeySmartnode has the wrong size\n");
        nDos = 100;
        return false;
    }

    if (!vin.scriptSig.empty()) {
        LogPrintf("CSmartnodeBroadcast::SimpleCheck -- Ignore Not Empty ScriptSig %s\n", vin.ToString());
        nDos = 100;
        return false;
    }

    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (addr.GetPort() != mainnetDefaultPort) return false;
    } else if (addr.GetPort() == mainnetDefaultPort) return false;

    return true;
}

bool CSmartnodeBroadcast::Update(CSmartnode *pmn, int &nDos) {
    nDos = 0;

    if (pmn->sigTime == sigTime && !fRecovery) {
        // mapSeenSmartnodeBroadcast in CSmartnodeMan::CheckMnbAndUpdateSmartnodeList should filter legit duplicates
        // but this still can happen if we just started, which is ok, just do nothing here.
        return false;
    }

    // this broadcast is older than the one that we already have - it's bad and should never happen
    // unless someone is doing something fishy
    if (pmn->sigTime > sigTime) {
        LogPrintf("CSmartnodeBroadcast::Update -- Bad sigTime %d (existing broadcast is at %d) for Smartnode %s %s\n",
                  sigTime, pmn->sigTime, vin.prevout.ToStringShort(), addr.ToString());
        return false;
    }

    pmn->Check();

    // smartnode is banned by PoSe
    if (pmn->IsPoSeBanned()) {
        LogPrintf("CSmartnodeBroadcast::Update -- Banned by PoSe, smartnode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    // IsVnAssociatedWithPubkey is validated once in CheckOutpoint, after that they just need to match
    if (pmn->pubKeyCollateralAddress != pubKeyCollateralAddress) {
        LogPrintf("CSmartnodeBroadcast::Update -- Got mismatched pubKeyCollateralAddress and vin\n");
        nDos = 33;
        return false;
    }

    if (!CheckSignature(nDos)) {
        LogPrintf("CSmartnodeBroadcast::Update -- CheckSignature() failed, smartnode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    // if ther was no smartnode broadcast recently or if it matches our Smartnode privkey...
    if (!pmn->IsBroadcastedWithin(SMARTNODE_MIN_MNB_SECONDS) || (fSmartNode && pubKeySmartnode == activeSmartnode.pubKeySmartnode)) {
        // take the newest entry
        LogPrintf("CSmartnodeBroadcast::Update -- Got UPDATED Smartnode entry: addr=%s\n", addr.ToString());
        if (pmn->UpdateFromNewBroadcast((*this))) {
            pmn->Check();
            RelaySmartNode();
        }
        smartnodeSync.AddedSmartnodeList();
    }

    return true;
}

bool CSmartnodeBroadcast::CheckOutpoint(int &nDos) {
    // we are a smartnode with the same vin (i.e. already activated) and this mnb is ours (matches our Smartnode privkey)
    // so nothing to do here for us
    if (fSmartNode && vin.prevout == activeSmartnode.vin.prevout && pubKeySmartnode == activeSmartnode.pubKeySmartnode) {
        return false;
    }

    if (!CheckSignature(nDos)) {
        LogPrintf("CSmartnodeBroadcast::CheckOutpoint -- CheckSignature() failed, smartnode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    {
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain) {
            // not mnb fault, let it to be checked again later
            LogPrint("smartnode", "CSmartnodeBroadcast::CheckOutpoint -- Failed to aquire lock, addr=%s", addr.ToString());
            mnodeman.mapSeenSmartnodeBroadcast.erase(GetHash());
            return false;
        }

        CCoins coins;
        if (!pcoinsTip->GetCoins(vin.prevout.hash, coins) ||
            (unsigned int) vin.prevout.n >= coins.vout.size() ||
            coins.vout[vin.prevout.n].IsNull()) {
            LogPrint("smartnode", "CSmartnodeBroadcast::CheckOutpoint -- Failed to find Smartnode UTXO, smartnode=%s\n", vin.prevout.ToStringShort());
            return false;
        }
        if (coins.vout[vin.prevout.n].nValue != SMARTNODE_COIN_REQUIRED * COIN) {
            LogPrint("smartnode", "CSmartnodeBroadcast::CheckOutpoint -- Smartnode UTXO should have 1000 Smartcash, smartnode=%s\n", vin.prevout.ToStringShort());
            return false;
        }
        if (chainActive.Height() - coins.nHeight + 1 < Params().GetConsensus().nSmartnodeMinimumConfirmations) {
            LogPrintf("CSmartnodeBroadcast::CheckOutpoint -- Smartnode UTXO must have at least %d confirmations, smartnode=%s\n",
                      Params().GetConsensus().nSmartnodeMinimumConfirmations, vin.prevout.ToStringShort());
            // maybe we miss few blocks, let this mnb to be checked again later
            mnodeman.mapSeenSmartnodeBroadcast.erase(GetHash());
            return false;
        }
    }

    LogPrint("smartnode", "CSmartnodeBroadcast::CheckOutpoint -- Smartnode UTXO verified\n");

    // make sure the vout that was signed is related to the transaction that spawned the Smartnode
    //  - this is expensive, so it's only done once per Smartnode
    if (!darkSendSigner.IsVinAssociatedWithPubkey(vin, pubKeyCollateralAddress)) {
        LogPrintf("CSmartnodeMan::CheckOutpoint -- Got mismatched pubKeyCollateralAddress and vin\n");
        nDos = 33;
        return false;
    }

    // verify that sig time is legit in past
    // should be at least not earlier than block when 1000 DASH tx got nSmartnodeMinimumConfirmations
    uint256 hashBlock = uint256();
    CTransaction tx2;
    GetTransaction(vin.prevout.hash, tx2, Params().GetConsensus(), hashBlock, true);
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex *pMNIndex = (*mi).second; // block for 1000 DASH tx -> 1 confirmation
            CBlockIndex *pConfIndex = chainActive[pMNIndex->nHeight + Params().GetConsensus().nSmartnodeMinimumConfirmations - 1]; // block where tx got nSmartnodeMinimumConfirmations
            if (pConfIndex->GetBlockTime() > sigTime) {
                LogPrintf("CSmartnodeBroadcast::CheckOutpoint -- Bad sigTime %d (%d conf block is at %d) for Smartnode %s %s\n",
                          sigTime, Params().GetConsensus().nSmartnodeMinimumConfirmations, pConfIndex->GetBlockTime(), vin.prevout.ToStringShort(), addr.ToString());
                return false;
            }
        }
    }

    return true;
}

bool CSmartnodeBroadcast::Sign(CKey &keyCollateralAddress) {
    std::string strError;
    std::string strMessage;

    sigTime = GetAdjustedTime();

    strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) +
                 pubKeyCollateralAddress.GetID().ToString() + pubKeySmartnode.GetID().ToString() +
                 boost::lexical_cast<std::string>(nProtocolVersion);

    if (!darkSendSigner.SignMessage(strMessage, vchSig, keyCollateralAddress)) {
        LogPrintf("CSmartnodeBroadcast::Sign -- SignMessage() failed\n");
        return false;
    }

    if (!darkSendSigner.VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)) {
        LogPrintf("CSmartnodeBroadcast::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CSmartnodeBroadcast::CheckSignature(int &nDos) {
    std::string strMessage;
    std::string strError = "";
    nDos = 0;

    strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) +
                 pubKeyCollateralAddress.GetID().ToString() + pubKeySmartnode.GetID().ToString() +
                 boost::lexical_cast<std::string>(nProtocolVersion);

    LogPrint("smartnode", "CSmartnodeBroadcast::CheckSignature -- strMessage: %s  pubKeyCollateralAddress address: %s  sig: %s\n", strMessage, CBitcoinAddress(pubKeyCollateralAddress.GetID()).ToString(), EncodeBase64(&vchSig[0], vchSig.size()));

    if (!darkSendSigner.VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)) {
        LogPrintf("CSmartnodeBroadcast::CheckSignature -- Got bad Smartnode announce signature, error: %s\n", strError);
        nDos = 100;
        return false;
    }

    return true;
}

void CSmartnodeBroadcast::RelaySmartNode() {
    LogPrintf("CSmartnodeBroadcast::RelaySmartNode\n");
    CInv inv(MSG_SMARTNODE_ANNOUNCE, GetHash());
    RelayInv(inv);
}

CSmartnodePing::CSmartnodePing(CTxIn &vinNew) {
    LOCK(cs_main);
    if (!chainActive.Tip() || chainActive.Height() < 12) return;

    vin = vinNew;
    blockHash = chainActive[chainActive.Height() - 12]->GetBlockHash();
    sigTime = GetAdjustedTime();
    vchSig = std::vector < unsigned
    char > ();
}

bool CSmartnodePing::Sign(CKey &keySmartnode, CPubKey &pubKeySmartnode) {
    std::string strError;
    std::string strSmartNodeSignMessage;

    sigTime = GetAdjustedTime();
    std::string strMessage = vin.ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);

    if (!darkSendSigner.SignMessage(strMessage, vchSig, keySmartnode)) {
        LogPrintf("CSmartnodePing::Sign -- SignMessage() failed\n");
        return false;
    }

    if (!darkSendSigner.VerifyMessage(pubKeySmartnode, vchSig, strMessage, strError)) {
        LogPrintf("CSmartnodePing::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CSmartnodePing::CheckSignature(CPubKey &pubKeySmartnode, int &nDos) {
    std::string strMessage = vin.ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);
    std::string strError = "";
    nDos = 0;

    if (!darkSendSigner.VerifyMessage(pubKeySmartnode, vchSig, strMessage, strError)) {
        LogPrintf("CSmartnodePing::CheckSignature -- Got bad Smartnode ping signature, smartnode=%s, error: %s\n", vin.prevout.ToStringShort(), strError);
        nDos = 33;
        return false;
    }
    return true;
}

bool CSmartnodePing::SimpleCheck(int &nDos) {
    // don't ban by default
    nDos = 0;

    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintf("CSmartnodePing::SimpleCheck -- Signature rejected, too far into the future, smartnode=%s\n", vin.prevout.ToStringShort());
        nDos = 1;
        return false;
    }

    {
//        LOCK(cs_main);
        AssertLockHeld(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if (mi == mapBlockIndex.end()) {
            LogPrint("smartnode", "CSmartnodePing::SimpleCheck -- Smartnode ping is invalid, unknown block hash: smartnode=%s blockHash=%s\n", vin.prevout.ToStringShort(), blockHash.ToString());
            // maybe we stuck or forked so we shouldn't ban this node, just fail to accept this ping
            // TODO: or should we also request this block?
            return false;
        }
    }
    LogPrint("smartnode", "CSmartnodePing::SimpleCheck -- Smartnode ping verified: smartnode=%s  blockHash=%s  sigTime=%d\n", vin.prevout.ToStringShort(), blockHash.ToString(), sigTime);
    return true;
}

bool CSmartnodePing::CheckAndUpdate(CSmartnode *pmn, bool fFromNewBroadcast, int &nDos) {
    // don't ban by default
    nDos = 0;

    if (!SimpleCheck(nDos)) {
        return false;
    }

    if (pmn == NULL) {
        LogPrint("smartnode", "CSmartnodePing::CheckAndUpdate -- Couldn't find Smartnode entry, smartnode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    if (!fFromNewBroadcast) {
        if (pmn->IsUpdateRequired()) {
            LogPrint("smartnode", "CSmartnodePing::CheckAndUpdate -- smartnode protocol is outdated, smartnode=%s\n", vin.prevout.ToStringShort());
            return false;
        }

        if (pmn->IsNewStartRequired()) {
            LogPrint("smartnode", "CSmartnodePing::CheckAndUpdate -- smartnode is completely expired, new start is required, smartnode=%s\n", vin.prevout.ToStringShort());
            return false;
        }
    }

    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if ((*mi).second && (*mi).second->nHeight < chainActive.Height() - 24) {
            LogPrintf("CSmartnodePing::CheckAndUpdate -- Smartnode ping is invalid, block hash is too old: smartnode=%s  blockHash=%s\n", vin.prevout.ToStringShort(), blockHash.ToString());
            // nDos = 1;
            return false;
        }
    }

    LogPrint("smartnode", "CSmartnodePing::CheckAndUpdate -- New ping: smartnode=%s  blockHash=%s  sigTime=%d\n", vin.prevout.ToStringShort(), blockHash.ToString(), sigTime);

    // LogPrintf("mnping - Found corresponding mn for vin: %s\n", vin.prevout.ToStringShort());
    // update only if there is no known ping for this smartnode or
    // last ping was more then SMARTNODE_MIN_MNP_SECONDS-60 ago comparing to this one
    if (pmn->IsPingedWithin(SMARTNODE_MIN_MNP_SECONDS - 60, sigTime)) {
        LogPrint("smartnode", "CSmartnodePing::CheckAndUpdate -- Smartnode ping arrived too early, smartnode=%s\n", vin.prevout.ToStringShort());
        //nDos = 1; //disable, this is happening frequently and causing banned peers
        return false;
    }

    if (!CheckSignature(pmn->pubKeySmartnode, nDos)) return false;

    // so, ping seems to be ok

    // if we are still syncing and there was no known ping for this mn for quite a while
    // (NOTE: assuming that SMARTNODE_EXPIRATION_SECONDS/2 should be enough to finish mn list sync)
    if (!smartnodeSync.IsSmartnodeListSynced() && !pmn->IsPingedWithin(SMARTNODE_EXPIRATION_SECONDS / 2)) {
        // let's bump sync timeout
        LogPrint("smartnode", "CSmartnodePing::CheckAndUpdate -- bumping sync timeout, smartnode=%s\n", vin.prevout.ToStringShort());
        smartnodeSync.AddedSmartnodeList();
    }

    // let's store this ping as the last one
    LogPrint("smartnode", "CSmartnodePing::CheckAndUpdate -- Smartnode ping accepted, smartnode=%s\n", vin.prevout.ToStringShort());
    pmn->lastPing = *this;

    // and update mnodeman.mapSeenSmartnodeBroadcast.lastPing which is probably outdated
    CSmartnodeBroadcast mnb(*pmn);
    uint256 hash = mnb.GetHash();
    if (mnodeman.mapSeenSmartnodeBroadcast.count(hash)) {
        mnodeman.mapSeenSmartnodeBroadcast[hash].second.lastPing = *this;
    }

    pmn->Check(true); // force update, ignoring cache
    if (!pmn->IsEnabled()) return false;

    LogPrint("smartnode", "CSmartnodePing::CheckAndUpdate -- Smartnode ping acceepted and relayed, smartnode=%s\n", vin.prevout.ToStringShort());
    Relay();

    return true;
}

void CSmartnodePing::Relay() {
    CInv inv(MSG_SMARTNODE_PING, GetHash());
    RelayInv(inv);
}

//void CSmartnode::AddGovernanceVote(uint256 nGovernanceObjectHash)
//{
//    if(mapGovernanceObjectsVotedOn.count(nGovernanceObjectHash)) {
//        mapGovernanceObjectsVotedOn[nGovernanceObjectHash]++;
//    } else {
//        mapGovernanceObjectsVotedOn.insert(std::make_pair(nGovernanceObjectHash, 1));
//    }
//}

//void CSmartnode::RemoveGovernanceObject(uint256 nGovernanceObjectHash)
//{
//    std::map<uint256, int>::iterator it = mapGovernanceObjectsVotedOn.find(nGovernanceObjectHash);
//    if(it == mapGovernanceObjectsVotedOn.end()) {
//        return;
//    }
//    mapGovernanceObjectsVotedOn.erase(it);
//}

void CSmartnode::UpdateWatchdogVoteTime() {
    LOCK(cs);
    nTimeLastWatchdogVote = GetTime();
}

/**
*   FLAG GOVERNANCE ITEMS AS DIRTY
*
*   - When smartnode come and go on the network, we must flag the items they voted on to recalc it's cached flags
*
*/
//void CSmartnode::FlagGovernanceItemsAsDirty()
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
