// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activesmartnode.h"
#include "consensus/validation.h"
#include "../init.h"
#include "../messagesigner.h"
//#include "governance.h"
#include "smartnode.h"
#include "smartnodepayments.h"
#include "smartnodesync.h"
#include "smartnodeman.h"
#include "../util.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif // ENABLE_WALLET

#include <boost/lexical_cast.hpp>


CSmartnode::CSmartnode() :
    smartnode_info_t{ SMARTNODE_ENABLED, PROTOCOL_VERSION, GetAdjustedTime()},
    fAllowMixingTx(true)
{}

CSmartnode::CSmartnode(CService addr, COutPoint outpoint, CPubKey pubKeyCollateralAddress, CPubKey pubKeySmartnode, int nProtocolVersionIn) :
    smartnode_info_t{ SMARTNODE_ENABLED, nProtocolVersionIn, GetAdjustedTime(),
                       outpoint, addr, pubKeyCollateralAddress, pubKeySmartnode},
    fAllowMixingTx(true)
{}

CSmartnode::CSmartnode(const CSmartnode& other) :
    smartnode_info_t{other},
    lastPing(other.lastPing),
    vchSig(other.vchSig),
    nCollateralMinConfBlockHash(other.nCollateralMinConfBlockHash),
    nBlockLastPaid(other.nBlockLastPaid),
    nPoSeBanScore(other.nPoSeBanScore),
    nPoSeBanHeight(other.nPoSeBanHeight),
    fAllowMixingTx(other.fAllowMixingTx),
    fUnitTest(other.fUnitTest)
{}

CSmartnode::CSmartnode(const CSmartnodeBroadcast& mnb) :
    smartnode_info_t{ mnb.nActiveState, mnb.nProtocolVersion, mnb.sigTime,
                       mnb.vin.prevout, mnb.addr, mnb.pubKeyCollateralAddress, mnb.pubKeySmartnode,
                       mnb.sigTime /*nTimeLastWatchdogVote*/},
    lastPing(mnb.lastPing),
    vchSig(mnb.vchSig),
    fAllowMixingTx(true)
{}

//
// When a new smartnode broadcast is sent, update our information
//
bool CSmartnode::UpdateFromNewBroadcast(CSmartnodeBroadcast& mnb, CConnman& connman)
{
    if(mnb.sigTime <= sigTime && !mnb.fRecovery) return false;

    pubKeySmartnode = mnb.pubKeySmartnode;
    sigTime = mnb.sigTime;
    vchSig = mnb.vchSig;
    nProtocolVersion = mnb.nProtocolVersion;
    addr = mnb.addr;
    nPoSeBanScore = 0;
    nPoSeBanHeight = 0;
    nTimeLastChecked = 0;
    int nDos = 0;
    if(mnb.lastPing == CSmartnodePing() || (mnb.lastPing != CSmartnodePing() && mnb.lastPing.CheckAndUpdate(this, true, nDos, connman))) {
        lastPing = mnb.lastPing;
        mnodeman.mapSeenSmartnodePing.insert(std::make_pair(lastPing.GetHash(), lastPing));
    }
    // if it matches our Smartnode privkey...
    if(fSmartNode && pubKeySmartnode == activeSmartnode.pubKeySmartnode) {
        nPoSeBanScore = -SMARTNODE_POSE_BAN_MAX_SCORE;
        if(nProtocolVersion == PROTOCOL_VERSION) {
            // ... and PROTOCOL_VERSION, then we've been remotely activated ...
            activeSmartnode.ManageState(connman);
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
arith_uint256 CSmartnode::CalculateScore(const uint256& blockHash)
{
    // Deterministically calculate a "score" for a Smartnode based on any given (block)hash
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << vin.prevout << nCollateralMinConfBlockHash << blockHash;
    return UintToArith256(ss.GetHash());
}

CSmartnode::CollateralStatus CSmartnode::CheckCollateral(const COutPoint& outpoint)
{
    int nHeight;
    return CheckCollateral(outpoint, nHeight);
}

CSmartnode::CollateralStatus CSmartnode::CheckCollateral(const COutPoint& outpoint, int& nHeightRet)
{
    AssertLockHeld(cs_main);

    Coin coin;
    if(!GetUTXOCoin(outpoint, coin)) {
        return COLLATERAL_UTXO_NOT_FOUND;
    }

    if(coin.out.nValue != 1000 * COIN) {
        return COLLATERAL_INVALID_AMOUNT;
    }

    nHeightRet = coin.nHeight;
    return COLLATERAL_OK;
}

void CSmartnode::Check(bool fForce)
{
    LOCK(cs);

    if(ShutdownRequested()) return;

    if(!fForce && (GetTime() - nTimeLastChecked < SMARTNODE_CHECK_SECONDS)) return;
    nTimeLastChecked = GetTime();

    LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state\n", vin.prevout.ToStringShort(), GetStateString());

    //once spent, stop doing the checks
    if(IsOutpointSpent()) return;

    int nHeight = 0;
    if(!fUnitTest) {
        TRY_LOCK(cs_main, lockMain);
        if(!lockMain) return;

        CollateralStatus err = CheckCollateral(vin.prevout);
        if (err == COLLATERAL_UTXO_NOT_FOUND) {
            nActiveState = SMARTNODE_OUTPOINT_SPENT;
            LogPrint("smartnode", "CSmartnode::Check -- Failed to find Smartnode UTXO, smartnode=%s\n", vin.prevout.ToStringShort());
            return;
        }

        nHeight = chainActive.Height();
    }

    if(IsPoSeBanned()) {
        if(nHeight < nPoSeBanHeight) return; // too early?
        // Otherwise give it a chance to proceed further to do all the usual checks and to change its state.
        // Smartnode still will be on the edge and can be banned back easily if it keeps ignoring mnverify
        // or connect attempts. Will require few mnverify messages to strengthen its position in mn list.
        LogPrintf("CSmartnode::Check -- Smartnode %s is unbanned and back in list now\n", vin.prevout.ToStringShort());
        DecreasePoSeBanScore();
    } else if(nPoSeBanScore >= SMARTNODE_POSE_BAN_MAX_SCORE) {
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

    if(fRequireUpdate) {
        nActiveState = SMARTNODE_UPDATE_REQUIRED;
        if(nActiveStatePrev != nActiveState) {
            LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
        }
        return;
    }

    // keep old smartnodes on start, give them a chance to receive updates...
    bool fWaitForPing = !smartnodeSync.IsSmartnodeListSynced() && !IsPingedWithin(SMARTNODE_MIN_MNP_SECONDS);

    if(fWaitForPing && !fOurSmartnode) {
        // ...but if it was already expired before the initial check - return right away
        if(IsExpired() || IsWatchdogExpired() || IsNewStartRequired()) {
            LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state, waiting for ping\n", vin.prevout.ToStringShort(), GetStateString());
            return;
        }
    }

    // don't expire if we are still in "waiting for ping" mode unless it's our own smartnode
    if(!fWaitForPing || fOurSmartnode) {

        if(!IsPingedWithin(SMARTNODE_NEW_START_REQUIRED_SECONDS)) {
            nActiveState = SMARTNODE_NEW_START_REQUIRED;
            if(nActiveStatePrev != nActiveState) {
                LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
            }
            return;
        }

        bool fWatchdogActive = smartnodeSync.IsSynced() && mnodeman.IsWatchdogActive();
        bool fWatchdogExpired = (fWatchdogActive && ((GetAdjustedTime() - nTimeLastWatchdogVote) > SMARTNODE_WATCHDOG_MAX_SECONDS));

        LogPrint("smartnode", "CSmartnode::Check -- outpoint=%s, nTimeLastWatchdogVote=%d, GetAdjustedTime()=%d, fWatchdogExpired=%d\n",
                vin.prevout.ToStringShort(), nTimeLastWatchdogVote, GetAdjustedTime(), fWatchdogExpired);

        if(fWatchdogExpired) {
            nActiveState = SMARTNODE_WATCHDOG_EXPIRED;
            if(nActiveStatePrev != nActiveState) {
                LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
            }
            return;
        }

        if(!IsPingedWithin(SMARTNODE_EXPIRATION_SECONDS)) {
            nActiveState = SMARTNODE_EXPIRED;
            if(nActiveStatePrev != nActiveState) {
                LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
            }
            return;
        }
    }

    if(lastPing.sigTime - sigTime < SMARTNODE_MIN_MNP_SECONDS) {
        nActiveState = SMARTNODE_PRE_ENABLED;
        if(nActiveStatePrev != nActiveState) {
            LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
        }
        return;
    }

    nActiveState = SMARTNODE_ENABLED; // OK
    if(nActiveStatePrev != nActiveState) {
        LogPrint("smartnode", "CSmartnode::Check -- Smartnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
    }
}

bool CSmartnode::IsInputAssociatedWithPubkey()
{
    CScript payee;
    payee = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    CTransaction tx;
    uint256 hash;
    if(GetTransaction(vin.prevout.hash, tx, Params().GetConsensus(), hash, true)) {
        BOOST_FOREACH(CTxOut out, tx.vout)
            if(out.nValue == 1000*COIN && out.scriptPubKey == payee) return true;
    }

    return false;
}

bool CSmartnode::IsValidNetAddr()
{
    return IsValidNetAddr(addr);
}

bool CSmartnode::IsValidNetAddr(CService addrIn)
{
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return Params().NetworkIDString() == CBaseChainParams::REGTEST ||
            (addrIn.IsIPv4() && IsReachable(addrIn) && addrIn.IsRoutable());
}

smartnode_info_t CSmartnode::GetInfo()
{
    smartnode_info_t info{*this};
    info.nTimeLastPing = lastPing.sigTime;
    info.fInfoValid = true;
    return info;
}

std::string CSmartnode::StateToString(int nStateIn)
{
    switch(nStateIn) {
        case SMARTNODE_PRE_ENABLED:            return "PRE_ENABLED";
        case SMARTNODE_ENABLED:                return "ENABLED";
        case SMARTNODE_EXPIRED:                return "EXPIRED";
        case SMARTNODE_OUTPOINT_SPENT:         return "OUTPOINT_SPENT";
        case SMARTNODE_UPDATE_REQUIRED:        return "UPDATE_REQUIRED";
        case SMARTNODE_WATCHDOG_EXPIRED:       return "WATCHDOG_EXPIRED";
        case SMARTNODE_NEW_START_REQUIRED:     return "NEW_START_REQUIRED";
        case SMARTNODE_POSE_BAN:               return "POSE_BAN";
        default:                                return "UNKNOWN";
    }
}

std::string CSmartnode::GetStateString() const
{
    return StateToString(nActiveState);
}

std::string CSmartnode::GetStatus() const
{
    // TODO: return smth a bit more human readable here
    return GetStateString();
}

void CSmartnode::UpdateLastPaid(const CBlockIndex *pindex, int nMaxBlocksToScanBack)
{
    if(!pindex) return;

    const CBlockIndex *BlockReading = pindex;

    CScript mnpayee = GetScriptForDestination(pubKeyCollateralAddress.GetID());
    // LogPrint("smartnode", "CSmartnode::UpdateLastPaidBlock -- searching for block with payment to %s\n", vin.prevout.ToStringShort());

    LOCK(cs_mapSmartnodeBlocks);

    for (int i = 0; BlockReading && BlockReading->nHeight > nBlockLastPaid && i < nMaxBlocksToScanBack; i++) {
        if(mnpayments.mapSmartnodeBlocks.count(BlockReading->nHeight) &&
            mnpayments.mapSmartnodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(mnpayee, 2))
        {
            CBlock block;
            if(!ReadBlockFromDisk(block, BlockReading, Params().GetConsensus())) // shouldn't really happen
                continue;

            CAmount nSmartnodePayment = GetSmartnodePayment(BlockReading->nHeight, block.vtx[0].GetValueOut());

            BOOST_FOREACH(CTxOut txout, block.vtx[0].vout)
                if(mnpayee == txout.scriptPubKey && nSmartnodePayment == txout.nValue) {
                    nBlockLastPaid = BlockReading->nHeight;
                    nTimeLastPaid = BlockReading->nTime;
                    LogPrint("smartnode", "CSmartnode::UpdateLastPaidBlock -- searching for block with payment to %s -- found new %d\n", vin.prevout.ToStringShort(), nBlockLastPaid);
                    return;
                }
        }

        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
        BlockReading = BlockReading->pprev;
    }

    // Last payment for this smartnode wasn't found in latest mnpayments blocks
    // or it was found in mnpayments blocks but wasn't found in the blockchain.
    // LogPrint("smartnode", "CSmartnode::UpdateLastPaidBlock -- searching for block with payment to %s -- keeping old %d\n", vin.prevout.ToStringShort(), nBlockLastPaid);
}

#ifdef ENABLE_WALLET
bool CSmartnodeBroadcast::Create(std::string strService, std::string strKeySmartnode, std::string strTxHash, std::string strOutputIndex, std::string& strErrorRet, CSmartnodeBroadcast &mnbRet, bool fOffline)
{
    COutPoint outpoint;
    CPubKey pubKeyCollateralAddressNew;
    CKey keyCollateralAddressNew;
    CPubKey pubKeySmartnodeNew;
    CKey keySmartnodeNew;

    auto Log = [&strErrorRet](std::string sErr)->bool
    {
        strErrorRet = sErr;
        LogPrintf("CSmartnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    };

    //need correct blocks to send ping
    if (!fOffline && !smartnodeSync.IsBlockchainSynced())
        return Log("Sync in progress. Must wait until sync is complete to start Smartnode");

    if (!CMessageSigner::GetKeysFromSecret(strKeySmartnode, keySmartnodeNew, pubKeySmartnodeNew))
        return Log(strprintf("Invalid smartnode key %s", strKeySmartnode));

    if (!pwalletMain->GetSmartnodeOutpointAndKeys(outpoint, pubKeyCollateralAddressNew, keyCollateralAddressNew, strTxHash, strOutputIndex))
        return Log(strprintf("Could not allocate outpoint %s:%s for smartnode %s", strTxHash, strOutputIndex, strService));

    CService service;
    if (!Lookup(strService.c_str(), service, 0, false))
        return Log(strprintf("Invalid address %s for smartnode.", strService));
    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (service.GetPort() != mainnetDefaultPort)
            return Log(strprintf("Invalid port %u for smartnode %s, only %d is supported on mainnet.", service.GetPort(), strService, mainnetDefaultPort));
    } else if (service.GetPort() == mainnetDefaultPort)
        return Log(strprintf("Invalid port %u for smartnode %s, %d is the only supported on mainnet.", service.GetPort(), strService, mainnetDefaultPort));

    return Create(outpoint, service, keyCollateralAddressNew, pubKeyCollateralAddressNew, keySmartnodeNew, pubKeySmartnodeNew, strErrorRet, mnbRet);
}

bool CSmartnodeBroadcast::Create(const COutPoint& outpoint, const CService& service, const CKey& keyCollateralAddressNew, const CPubKey& pubKeyCollateralAddressNew, const CKey& keySmartnodeNew, const CPubKey& pubKeySmartnodeNew, std::string &strErrorRet, CSmartnodeBroadcast &mnbRet)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    LogPrint("smartnode", "CSmartnodeBroadcast::Create -- pubKeyCollateralAddressNew = %s, pubKeySmartnodeNew.GetID() = %s\n",
             CBitcoinAddress(pubKeyCollateralAddressNew.GetID()).ToString(),
             pubKeySmartnodeNew.GetID().ToString());

    auto Log = [&strErrorRet,&mnbRet](std::string sErr)->bool
    {
        strErrorRet = sErr;
        LogPrintf("CSmartnodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CSmartnodeBroadcast();
        return false;
    };

    CSmartnodePing mnp(outpoint);
    if (!mnp.Sign(keySmartnodeNew, pubKeySmartnodeNew))
        return Log(strprintf("Failed to sign ping, smartnode=%s", outpoint.ToStringShort()));

    mnbRet = CSmartnodeBroadcast(service, outpoint, pubKeyCollateralAddressNew, pubKeySmartnodeNew, PROTOCOL_VERSION);

    if (!mnbRet.IsValidNetAddr())
        return Log(strprintf("Invalid IP address, smartnode=%s", outpoint.ToStringShort()));

    mnbRet.lastPing = mnp;
    if (!mnbRet.Sign(keyCollateralAddressNew))
        return Log(strprintf("Failed to sign broadcast, smartnode=%s", outpoint.ToStringShort()));

    return true;
}
#endif // ENABLE_WALLET

bool CSmartnodeBroadcast::SimpleCheck(int& nDos)
{
    nDos = 0;

    // make sure addr is valid
    if(!IsValidNetAddr()) {
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
    if(lastPing == CSmartnodePing() || !lastPing.SimpleCheck(nDos)) {
        // one of us is probably forked or smth, just mark it as expired and check the rest of the rules
        nActiveState = SMARTNODE_EXPIRED;
    }

    if(nProtocolVersion < mnpayments.GetMinSmartnodePaymentsProto()) {
        LogPrintf("CSmartnodeBroadcast::SimpleCheck -- ignoring outdated Smartnode: smartnode=%s  nProtocolVersion=%d\n", vin.prevout.ToStringShort(), nProtocolVersion);
        return false;
    }

    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    if(pubkeyScript.size() != 25) {
        LogPrintf("CSmartnodeBroadcast::SimpleCheck -- pubKeyCollateralAddress has the wrong size\n");
        nDos = 100;
        return false;
    }

    CScript pubkeyScript2;
    pubkeyScript2 = GetScriptForDestination(pubKeySmartnode.GetID());

    if(pubkeyScript2.size() != 25) {
        LogPrintf("CSmartnodeBroadcast::SimpleCheck -- pubKeySmartnode has the wrong size\n");
        nDos = 100;
        return false;
    }

    if(!vin.scriptSig.empty()) {
        LogPrintf("CSmartnodeBroadcast::SimpleCheck -- Ignore Not Empty ScriptSig %s\n",vin.ToString());
        nDos = 100;
        return false;
    }

    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if(addr.GetPort() != mainnetDefaultPort) return false;
    } else if(addr.GetPort() == mainnetDefaultPort) return false;

    return true;
}

bool CSmartnodeBroadcast::Update(CSmartnode* pmn, int& nDos, CConnman& connman)
{
    nDos = 0;

    if(pmn->sigTime == sigTime && !fRecovery) {
        // mapSeenSmartnodeBroadcast in CSmartnodeMan::CheckMnbAndUpdateSmartnodeList should filter legit duplicates
        // but this still can happen if we just started, which is ok, just do nothing here.
        return false;
    }

    // this broadcast is older than the one that we already have - it's bad and should never happen
    // unless someone is doing something fishy
    if(pmn->sigTime > sigTime) {
        LogPrintf("CSmartnodeBroadcast::Update -- Bad sigTime %d (existing broadcast is at %d) for Smartnode %s %s\n",
                      sigTime, pmn->sigTime, vin.prevout.ToStringShort(), addr.ToString());
        return false;
    }

    pmn->Check();

    // smartnode is banned by PoSe
    if(pmn->IsPoSeBanned()) {
        LogPrintf("CSmartnodeBroadcast::Update -- Banned by PoSe, smartnode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    // IsVnAssociatedWithPubkey is validated once in CheckOutpoint, after that they just need to match
    if(pmn->pubKeyCollateralAddress != pubKeyCollateralAddress) {
        LogPrintf("CSmartnodeBroadcast::Update -- Got mismatched pubKeyCollateralAddress and vin\n");
        nDos = 33;
        return false;
    }

    if (!CheckSignature(nDos)) {
        LogPrintf("CSmartnodeBroadcast::Update -- CheckSignature() failed, smartnode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    // if ther was no smartnode broadcast recently or if it matches our Smartnode privkey...
    if(!pmn->IsBroadcastedWithin(SMARTNODE_MIN_MNB_SECONDS) || (fSmartNode && pubKeySmartnode == activeSmartnode.pubKeySmartnode)) {
        // take the newest entry
        LogPrintf("CSmartnodeBroadcast::Update -- Got UPDATED Smartnode entry: addr=%s\n", addr.ToString());
        if(pmn->UpdateFromNewBroadcast(*this, connman)) {
            pmn->Check();
            Relay(connman);
        }
        smartnodeSync.BumpAssetLastTime("CSmartnodeBroadcast::Update");
    }

    return true;
}

bool CSmartnodeBroadcast::CheckOutpoint(int& nDos)
{
    // we are a smartnode with the same vin (i.e. already activated) and this mnb is ours (matches our Smartnode privkey)
    // so nothing to do here for us
    if(fSmartNode && vin.prevout == activeSmartnode.outpoint && pubKeySmartnode == activeSmartnode.pubKeySmartnode) {
        return false;
    }

    if (!CheckSignature(nDos)) {
        LogPrintf("CSmartnodeBroadcast::CheckOutpoint -- CheckSignature() failed, smartnode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    {
        TRY_LOCK(cs_main, lockMain);
        if(!lockMain) {
            // not mnb fault, let it to be checked again later
            LogPrint("smartnode", "CSmartnodeBroadcast::CheckOutpoint -- Failed to aquire lock, addr=%s", addr.ToString());
            mnodeman.mapSeenSmartnodeBroadcast.erase(GetHash());
            return false;
        }

        int nHeight;
        CollateralStatus err = CheckCollateral(vin.prevout, nHeight);
        if (err == COLLATERAL_UTXO_NOT_FOUND) {
            LogPrint("smartnode", "CSmartnodeBroadcast::CheckOutpoint -- Failed to find Smartnode UTXO, smartnode=%s\n", vin.prevout.ToStringShort());
            return false;
        }

        if (err == COLLATERAL_INVALID_AMOUNT) {
            LogPrint("smartnode", "CSmartnodeBroadcast::CheckOutpoint -- Smartnode UTXO should have 10000 SMART, smartnode=%s\n", vin.prevout.ToStringShort());
            return false;
        }

        if(chainActive.Height() - nHeight + 1 < Params().GetConsensus().nSmartnodeMinimumConfirmations) {
            LogPrintf("CSmartnodeBroadcast::CheckOutpoint -- Smartnode UTXO must have at least %d confirmations, smartnode=%s\n",
                    Params().GetConsensus().nSmartnodeMinimumConfirmations, vin.prevout.ToStringShort());
            // maybe we miss few blocks, let this mnb to be checked again later
            mnodeman.mapSeenSmartnodeBroadcast.erase(GetHash());
            return false;
        }
        // remember the hash of the block where smartnode collateral had minimum required confirmations
        nCollateralMinConfBlockHash = chainActive[nHeight + Params().GetConsensus().nSmartnodeMinimumConfirmations - 1]->GetBlockHash();
    }

    LogPrint("smartnode", "CSmartnodeBroadcast::CheckOutpoint -- Smartnode UTXO verified\n");

    // make sure the input that was signed in smartnode broadcast message is related to the transaction
    // that spawned the Smartnode - this is expensive, so it's only done once per Smartnode
    if(!IsInputAssociatedWithPubkey()) {
        LogPrintf("CSmartnodeMan::CheckOutpoint -- Got mismatched pubKeyCollateralAddress and vin\n");
        nDos = 33;
        return false;
    }

    // verify that sig time is legit in past
    // should be at least not earlier than block when 10000 SMART tx got nSmartnodeMinimumConfirmations
    uint256 hashBlock = uint256();
    CTransaction tx2;
    GetTransaction(vin.prevout.hash, tx2, Params().GetConsensus(), hashBlock, true);
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex* pMNIndex = (*mi).second; // block for 10000 SMART tx -> 1 confirmation
            CBlockIndex* pConfIndex = chainActive[pMNIndex->nHeight + Params().GetConsensus().nSmartnodeMinimumConfirmations - 1]; // block where tx got nSmartnodeMinimumConfirmations
            if(pConfIndex->GetBlockTime() > sigTime) {
                LogPrintf("CSmartnodeBroadcast::CheckOutpoint -- Bad sigTime %d (%d conf block is at %d) for Smartnode %s %s\n",
                          sigTime, Params().GetConsensus().nSmartnodeMinimumConfirmations, pConfIndex->GetBlockTime(), vin.prevout.ToStringShort(), addr.ToString());
                return false;
            }
        }
    }

    return true;
}

bool CSmartnodeBroadcast::Sign(const CKey& keyCollateralAddress)
{
    std::string strError;
    std::string strMessage;

    sigTime = GetAdjustedTime();

    strMessage = addr.ToString(false) + boost::lexical_cast<std::string>(sigTime) +
                    pubKeyCollateralAddress.GetID().ToString() + pubKeySmartnode.GetID().ToString() +
                    boost::lexical_cast<std::string>(nProtocolVersion);

    if(!CMessageSigner::SignMessage(strMessage, vchSig, keyCollateralAddress)) {
        LogPrintf("CSmartnodeBroadcast::Sign -- SignMessage() failed\n");
        return false;
    }

    if(!CMessageSigner::VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)) {
        LogPrintf("CSmartnodeBroadcast::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CSmartnodeBroadcast::CheckSignature(int& nDos)
{
    std::string strMessage;
    std::string strError = "";
    nDos = 0;

    strMessage = addr.ToString(false) + boost::lexical_cast<std::string>(sigTime) +
                    pubKeyCollateralAddress.GetID().ToString() + pubKeySmartnode.GetID().ToString() +
                    boost::lexical_cast<std::string>(nProtocolVersion);

    LogPrint("smartnode", "CSmartnodeBroadcast::CheckSignature -- strMessage: %s  pubKeyCollateralAddress address: %s  sig: %s\n", strMessage, CBitcoinAddress(pubKeyCollateralAddress.GetID()).ToString(), EncodeBase64(&vchSig[0], vchSig.size()));

    if(!CMessageSigner::VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)){
        LogPrintf("CSmartnodeBroadcast::CheckSignature -- Got bad Smartnode announce signature, error: %s\n", strError);
        nDos = 100;
        return false;
    }

    return true;
}

void CSmartnodeBroadcast::Relay(CConnman& connman)
{
    // Do not relay until fully synced
    if(!smartnodeSync.IsSynced()) {
        LogPrint("smartnode", "CSmartnodeBroadcast::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_SMARTNODE_ANNOUNCE, GetHash());
    connman.RelayInv(inv);
}

CSmartnodePing::CSmartnodePing(const COutPoint& outpoint)
{
    LOCK(cs_main);
    if (!chainActive.Tip() || chainActive.Height() < 12) return;

    vin = CTxIn(outpoint);
    blockHash = chainActive[chainActive.Height() - 12]->GetBlockHash();
    sigTime = GetAdjustedTime();
}

bool CSmartnodePing::Sign(const CKey& keySmartnode, const CPubKey& pubKeySmartnode)
{
    std::string strError;
    std::string strSmartNodeSignMessage;

    // TODO: add sentinel data
    sigTime = GetAdjustedTime();
    std::string strMessage = vin.ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);

    if(!CMessageSigner::SignMessage(strMessage, vchSig, keySmartnode)) {
        LogPrintf("CSmartnodePing::Sign -- SignMessage() failed\n");
        return false;
    }

    if(!CMessageSigner::VerifyMessage(pubKeySmartnode, vchSig, strMessage, strError)) {
        LogPrintf("CSmartnodePing::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CSmartnodePing::CheckSignature(CPubKey& pubKeySmartnode, int &nDos)
{
    // TODO: add sentinel data
    std::string strMessage = vin.ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);
    std::string strError = "";
    nDos = 0;

    if(!CMessageSigner::VerifyMessage(pubKeySmartnode, vchSig, strMessage, strError)) {
        LogPrintf("CSmartnodePing::CheckSignature -- Got bad Smartnode ping signature, smartnode=%s, error: %s\n", vin.prevout.ToStringShort(), strError);
        nDos = 33;
        return false;
    }
    return true;
}

bool CSmartnodePing::SimpleCheck(int& nDos)
{
    // don't ban by default
    nDos = 0;

    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintf("CSmartnodePing::SimpleCheck -- Signature rejected, too far into the future, smartnode=%s\n", vin.prevout.ToStringShort());
        nDos = 1;
        return false;
    }

    {
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

bool CSmartnodePing::CheckAndUpdate(CSmartnode* pmn, bool fFromNewBroadcast, int& nDos, CConnman& connman)
{
    // don't ban by default
    nDos = 0;

    if (!SimpleCheck(nDos)) {
        return false;
    }

    if (pmn == NULL) {
        LogPrint("smartnode", "CSmartnodePing::CheckAndUpdate -- Couldn't find Smartnode entry, smartnode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    if(!fFromNewBroadcast) {
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
    if(!smartnodeSync.IsSmartnodeListSynced() && !pmn->IsPingedWithin(SMARTNODE_EXPIRATION_SECONDS/2)) {
        // let's bump sync timeout
        LogPrint("smartnode", "CSmartnodePing::CheckAndUpdate -- bumping sync timeout, smartnode=%s\n", vin.prevout.ToStringShort());
        smartnodeSync.BumpAssetLastTime("CSmartnodePing::CheckAndUpdate");
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

    // force update, ignoring cache
    pmn->Check(true);
    // relay ping for nodes in ENABLED/EXPIRED/WATCHDOG_EXPIRED state only, skip everyone else
    if (!pmn->IsEnabled() && !pmn->IsExpired() && !pmn->IsWatchdogExpired()) return false;

    LogPrint("smartnode", "CSmartnodePing::CheckAndUpdate -- Smartnode ping acceepted and relayed, smartnode=%s\n", vin.prevout.ToStringShort());
    Relay(connman);

    return true;
}

void CSmartnodePing::Relay(CConnman& connman)
{
    // Do not relay until fully synced
    if(!smartnodeSync.IsSynced()) {
        LogPrint("smartnode", "CSmartnodePing::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_SMARTNODE_PING, GetHash());
    connman.RelayInv(inv);
}

void CSmartnode::AddGovernanceVote(uint256 nGovernanceObjectHash)
{
    if(mapGovernanceObjectsVotedOn.count(nGovernanceObjectHash)) {
        mapGovernanceObjectsVotedOn[nGovernanceObjectHash]++;
    } else {
        mapGovernanceObjectsVotedOn.insert(std::make_pair(nGovernanceObjectHash, 1));
    }
}

void CSmartnode::RemoveGovernanceObject(uint256 nGovernanceObjectHash)
{
    std::map<uint256, int>::iterator it = mapGovernanceObjectsVotedOn.find(nGovernanceObjectHash);
    if(it == mapGovernanceObjectsVotedOn.end()) {
        return;
    }
    mapGovernanceObjectsVotedOn.erase(it);
}

void CSmartnode::UpdateWatchdogVoteTime(uint64_t nVoteTime)
{
    LOCK(cs);
    nTimeLastWatchdogVote = (nVoteTime == 0) ? GetAdjustedTime() : nVoteTime;
}

/**
*   FLAG GOVERNANCE ITEMS AS DIRTY
*
*   - When smartnode come and go on the network, we must flag the items they voted on to recalc it's cached flags
*
*/
void CSmartnode::FlagGovernanceItemsAsDirty()
{
    std::vector<uint256> vecDirty;
    {
        std::map<uint256, int>::iterator it = mapGovernanceObjectsVotedOn.begin();
        while(it != mapGovernanceObjectsVotedOn.end()) {
            vecDirty.push_back(it->first);
            ++it;
        }
    }
    for(size_t i = 0; i < vecDirty.size(); ++i) {
        mnodeman.AddDirtyGovernanceObjectHash(vecDirty[i]);
    }
}