// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activesmartnode.h"
#include "base58.h"
#include "smartnodepayments.h"
#include "smartnodesync.h"
#include "smartnodeman.h"
#include "../messagesigner.h"
#include "netfulfilledman.h" 
#include "script/standard.h" 
#include "spork.h"
#include "../util.h"

#include <boost/lexical_cast.hpp>

/** Object for who's going to get paid on which blocks */
CSmartnodePayments mnpayments;

CCriticalSection cs_vecPayees;
CCriticalSection cs_mapSmartnodeBlocks;
CCriticalSection cs_mapSmartnodePaymentVotes;

/**
* IsBlockValueValid
*
*   Determine if coinbase outgoing created money is the correct value
*
*   Why is this needed?
*   - In Dash some blocks are superblocks, which output much higher amounts of coins
*   - Otherblocks are 10% lower in outgoing value, so in total, no extra coins are created
*   - When non-superblocks are detected, the normal schedule should be maintained
*/

bool IsBlockValueValid(const CBlock& block, int nBlockHeight, CAmount blockReward, std::string &strErrorRet)
{
    strErrorRet = "";

    bool isBlockRewardValueMet = (block.vtx[0].GetValueOut() <= blockReward);
    if(fDebug) LogPrintf("block.vtx[0].GetValueOut() %lld <= blockReward %lld\n", block.vtx[0].GetValueOut(), blockReward);

    // we are still using budgets, but we have no data about them anymore,
    // all we know is predefined budget cycle and window

    const Consensus::Params& consensusParams = Params().GetConsensus();

    if(nBlockHeight < consensusParams.nSuperblockStartBlock) {
        int nOffset = nBlockHeight % consensusParams.nBudgetPaymentsCycleBlocks;
        if(nBlockHeight >= consensusParams.nBudgetPaymentsStartBlock &&
            nOffset < consensusParams.nBudgetPaymentsWindowBlocks) {
            // NOTE: make sure SPORK_13_OLD_SUPERBLOCK_FLAG is disabled when 12.1 starts to go live
            if(smartnodeSync.IsSynced() && !sporkManager.IsSporkActive(SPORK_13_OLD_SUPERBLOCK_FLAG)) {
                // no budget blocks should be accepted here, if SPORK_13_OLD_SUPERBLOCK_FLAG is disabled
                LogPrint("gobject", "IsBlockValueValid -- Client synced but budget spork is disabled, checking block value against block reward\n");
                if(!isBlockRewardValueMet) {
                    strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, budgets are disabled",
                                            nBlockHeight, block.vtx[0].GetValueOut(), blockReward);
                }
                return isBlockRewardValueMet;
            }
            LogPrint("gobject", "IsBlockValueValid -- WARNING: Skipping budget block value checks, accepting block\n");
            // TODO: reprocess blocks to make sure they are legit?
            return true;
        }
        // LogPrint("gobject", "IsBlockValueValid -- Block is not in budget cycle window, checking block value against block reward\n");
        if(!isBlockRewardValueMet) {
            strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, block is not in budget cycle window",
                                    nBlockHeight, block.vtx[0].GetValueOut(), blockReward);
        }
        return isBlockRewardValueMet;
    }

    // superblocks started

    // CAmount nSuperblockMaxValue =  blockReward + CSuperblock::GetPaymentsLimit(nBlockHeight);
    // bool isSuperblockMaxValueMet = (block.vtx[0].GetValueOut() <= nSuperblockMaxValue);

    // LogPrint("gobject", "block.vtx[0].GetValueOut() %lld <= nSuperblockMaxValue %lld\n", block.vtx[0].GetValueOut(), nSuperblockMaxValue);

    // if(!smartnodeSync.IsSynced()) {
    //     //not enough data but at least it must NOT exceed superblock max value
    //     if(CSuperblock::IsValidBlockHeight(nBlockHeight)) {
    //         if(fDebug) LogPrintf("IsBlockPayeeValid -- WARNING: Client not synced, checking superblock max bounds only\n");
    //         if(!isSuperblockMaxValueMet) {
    //             strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded superblock max value",
    //                                     nBlockHeight, block.vtx[0].GetValueOut(), nSuperblockMaxValue);
    //         }
    //         return isSuperblockMaxValueMet;
    //     }
    //     if(!isBlockRewardValueMet) {
    //         strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, only regular blocks are allowed at this height",
    //                                 nBlockHeight, block.vtx[0].GetValueOut(), blockReward);
    //     }
    //     // it MUST be a regular block otherwise
    //     return isBlockRewardValueMet;
    // }

    // // we are synced, let's try to check as much data as we can

    // if(sporkManager.IsSporkActive(SPORK_9_SUPERBLOCKS_ENABLED)) {
    //     if(CSuperblockManager::IsSuperblockTriggered(nBlockHeight)) {
    //         if(CSuperblockManager::IsValid(block.vtx[0], nBlockHeight, blockReward)) {
    //             LogPrint("gobject", "IsBlockValueValid -- Valid superblock at height %d: %s", nBlockHeight, block.vtx[0].ToString());
    //             // all checks are done in CSuperblock::IsValid, nothing to do here
    //             return true;
    //         }

    //         // triggered but invalid? that's weird
    //         LogPrintf("IsBlockValueValid -- ERROR: Invalid superblock detected at height %d: %s", nBlockHeight, block.vtx[0].ToString());
    //         // should NOT allow invalid superblocks, when superblocks are enabled
    //         strErrorRet = strprintf("invalid superblock detected at height %d", nBlockHeight);
    //         return false;
    //     }
    //     LogPrint("gobject", "IsBlockValueValid -- No triggered superblock detected at height %d\n", nBlockHeight);
    //     if(!isBlockRewardValueMet) {
    //         strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, no triggered superblock detected",
    //                                 nBlockHeight, block.vtx[0].GetValueOut(), blockReward);
    //     }
    // } else {
    //     // should NOT allow superblocks at all, when superblocks are disabled
    //     LogPrint("gobject", "IsBlockValueValid -- Superblocks are disabled, no superblocks allowed\n");
    //     if(!isBlockRewardValueMet) {
    //         strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, superblocks are disabled",
    //                                 nBlockHeight, block.vtx[0].GetValueOut(), blockReward);
    //     }
    // }

    // it MUST be a regular block
    return isBlockRewardValueMet;
}

bool IsBlockPayeeValid(const CTransaction& txNew, int nBlockHeight, CAmount blockReward)
{
    if(!smartnodeSync.IsSynced()) {
        //there is no budget data to use to check anything, let's just accept the longest chain
        if(fDebug) LogPrintf("IsBlockPayeeValid -- WARNING: Client not synced, skipping block payee checks\n");
        return true;
    }

    // we are still using budgets, but we have no data about them anymore,
    // we can only check smartnode payments

    const Consensus::Params& consensusParams = Params().GetConsensus();

    if(nBlockHeight < consensusParams.nSuperblockStartBlock) {
        if(mnpayments.IsTransactionValid(txNew, nBlockHeight)) {
            LogPrint("mnpayments", "IsBlockPayeeValid -- Valid smartnode payment at height %d: %s", nBlockHeight, txNew.ToString());
            return true;
        }

        int nOffset = nBlockHeight % consensusParams.nBudgetPaymentsCycleBlocks;
        if(nBlockHeight >= consensusParams.nBudgetPaymentsStartBlock &&
            nOffset < consensusParams.nBudgetPaymentsWindowBlocks) {
            if(!sporkManager.IsSporkActive(SPORK_13_OLD_SUPERBLOCK_FLAG)) {
                // no budget blocks should be accepted here, if SPORK_13_OLD_SUPERBLOCK_FLAG is disabled
                LogPrint("gobject", "IsBlockPayeeValid -- ERROR: Client synced but budget spork is disabled and smartnode payment is invalid\n");
                return false;
            }
            // NOTE: this should never happen in real, SPORK_13_OLD_SUPERBLOCK_FLAG MUST be disabled when 12.1 starts to go live
            LogPrint("gobject", "IsBlockPayeeValid -- WARNING: Probably valid budget block, have no data, accepting\n");
            // TODO: reprocess blocks to make sure they are legit?
            return true;
        }

        if(sporkManager.IsSporkActive(SPORK_8_SMARTNODE_PAYMENT_ENFORCEMENT)) {
            LogPrintf("IsBlockPayeeValid -- ERROR: Invalid smartnode payment detected at height %d: %s", nBlockHeight, txNew.ToString());
            return false;
        }

        LogPrintf("IsBlockPayeeValid -- WARNING: Smartnode payment enforcement is disabled, accepting any payee\n");
        return true;
    }

    // superblocks started
    // SEE IF THIS IS A VALID SUPERBLOCK

    // if(sporkManager.IsSporkActive(SPORK_9_SUPERBLOCKS_ENABLED)) {
    //     if(CSuperblockManager::IsSuperblockTriggered(nBlockHeight)) {
    //         if(CSuperblockManager::IsValid(txNew, nBlockHeight, blockReward)) {
    //             LogPrint("gobject", "IsBlockPayeeValid -- Valid superblock at height %d: %s", nBlockHeight, txNew.ToString());
    //             return true;
    //         }

    //         LogPrintf("IsBlockPayeeValid -- ERROR: Invalid superblock detected at height %d: %s", nBlockHeight, txNew.ToString());
    //         // should NOT allow such superblocks, when superblocks are enabled
    //         return false;
    //     }
    //     // continue validation, should pay MN
    //     LogPrint("gobject", "IsBlockPayeeValid -- No triggered superblock detected at height %d\n", nBlockHeight);
    // } else {
    //     // should NOT allow superblocks at all, when superblocks are disabled
    //     LogPrint("gobject", "IsBlockPayeeValid -- Superblocks are disabled, no superblocks allowed\n");
    // }

    // IF THIS ISN'T A SUPERBLOCK OR SUPERBLOCK IS INVALID, IT SHOULD PAY A SMARTNODE DIRECTLY
    if(mnpayments.IsTransactionValid(txNew, nBlockHeight)) {
        LogPrint("mnpayments", "IsBlockPayeeValid -- Valid smartnode payment at height %d: %s", nBlockHeight, txNew.ToString());
        return true;
    }

    if(sporkManager.IsSporkActive(SPORK_8_SMARTNODE_PAYMENT_ENFORCEMENT)) {
        LogPrintf("IsBlockPayeeValid -- ERROR: Invalid smartnode payment detected at height %d: %s", nBlockHeight, txNew.ToString());
        return false;
    }

    LogPrintf("IsBlockPayeeValid -- WARNING: Smartnode payment enforcement is disabled, accepting any payee\n");
    return true;
}

void FillBlockPayments(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, CTxOut& txoutSmartnodeRet, std::vector<CTxOut>& voutSuperblockRet)
{
    // only create superblocks if spork is enabled AND if superblock is actually triggered
    // (height should be validated inside)
    // if(sporkManager.IsSporkActive(SPORK_9_SUPERBLOCKS_ENABLED) &&
    //     CSuperblockManager::IsSuperblockTriggered(nBlockHeight)) {
    //         LogPrint("gobject", "FillBlockPayments -- triggered superblock creation at height %d\n", nBlockHeight);
    //         CSuperblockManager::CreateSuperblock(txNew, nBlockHeight, voutSuperblockRet);
    //         return;
    // }

    // FILL BLOCK PAYEE WITH SMARTNODE PAYMENT OTHERWISE
    mnpayments.FillBlockPayee(txNew, nBlockHeight, blockReward, txoutSmartnodeRet);
    LogPrint("mnpayments", "FillBlockPayments -- nBlockHeight %d blockReward %lld txoutSmartnodeRet %s txNew %s",
                            nBlockHeight, blockReward, txoutSmartnodeRet.ToString(), txNew.ToString());
}

std::string GetRequiredPaymentsString(int nBlockHeight)
{
    // IF WE HAVE A ACTIVATED TRIGGER FOR THIS HEIGHT - IT IS A SUPERBLOCK, GET THE REQUIRED PAYEES
    // if(CSuperblockManager::IsSuperblockTriggered(nBlockHeight)) {
    //     return CSuperblockManager::GetRequiredPaymentsString(nBlockHeight);
    // }

    // OTHERWISE, PAY SMARTNODE
    return mnpayments.GetRequiredPaymentsString(nBlockHeight);
}

void CSmartnodePayments::Clear()
{
    LOCK2(cs_mapSmartnodeBlocks, cs_mapSmartnodePaymentVotes);
    mapSmartnodeBlocks.clear();
    mapSmartnodePaymentVotes.clear();
}

bool CSmartnodePayments::CanVote(COutPoint outSmartnode, int nBlockHeight)
{
    LOCK(cs_mapSmartnodePaymentVotes);

    if (mapSmartnodesLastVote.count(outSmartnode) && mapSmartnodesLastVote[outSmartnode] == nBlockHeight) {
        return false;
    }

    //record this smartnode voted
    mapSmartnodesLastVote[outSmartnode] = nBlockHeight;
    return true;
}

/**
*   FillBlockPayee
*
*   Fill Smartnode ONLY payment block
*/

void CSmartnodePayments::FillBlockPayee(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, CTxOut& txoutSmartnodeRet)
{
    // make sure it's not filled yet
    txoutSmartnodeRet = CTxOut();

    CScript payee;

    if(!mnpayments.GetBlockPayee(nBlockHeight, payee)) {
        // no smartnode detected...
        int nCount = 0;
        smartnode_info_t mnInfo;
        if(!mnodeman.GetNextSmartnodeInQueueForPayment(nBlockHeight, true, nCount, mnInfo)) {
            // ...and we can't calculate it on our own
            LogPrintf("CSmartnodePayments::FillBlockPayee -- Failed to detect smartnode to pay\n");
            return;
        }
        // fill payee with locally calculated winner and hope for the best
        payee = GetScriptForDestination(mnInfo.pubKeyCollateralAddress.GetID());
    }

    // GET SMARTNODE PAYMENT VARIABLES SETUP
    CAmount smartnodePayment = GetSmartnodePayment(nBlockHeight, blockReward);

    // split reward between miner ...
    txNew.vout[0].nValue -= smartnodePayment;
    // ... and smartnode
    txoutSmartnodeRet = CTxOut(smartnodePayment, payee);
    txNew.vout.push_back(txoutSmartnodeRet);

    CTxDestination address1;
    ExtractDestination(payee, address1);
    CBitcoinAddress address2(address1);

    LogPrintf("CSmartnodePayments::FillBlockPayee -- Smartnode payment %lld to %s\n", smartnodePayment, address2.ToString());
}

int CSmartnodePayments::GetMinSmartnodePaymentsProto() {
    return sporkManager.IsSporkActive(SPORK_10_SMARTNODE_PAY_UPDATED_NODES)
            ? MIN_SMARTNODE_PAYMENT_PROTO_VERSION_2
            : MIN_SMARTNODE_PAYMENT_PROTO_VERSION_1;
}

void CSmartnodePayments::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv, CConnman& connman)
{
    if(fLiteMode) return; // disable all Dash specific functionality

    if (strCommand == NetMsgType::SMARTNODEPAYMENTSYNC) { //Smartnode Payments Request Sync

        // Ignore such requests until we are fully synced.
        // We could start processing this after smartnode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!smartnodeSync.IsSynced()) return;

        int nCountNeeded;
        vRecv >> nCountNeeded;

        if(netfulfilledman.HasFulfilledRequest(pfrom->addr, NetMsgType::SMARTNODEPAYMENTSYNC)) {
            // Asking for the payments list multiple times in a short period of time is no good
            LogPrintf("SMARTNODEPAYMENTSYNC -- peer already asked me for the list, peer=%d\n", pfrom->id);
            Misbehaving(pfrom->GetId(), 20);
            return;
        }
        netfulfilledman.AddFulfilledRequest(pfrom->addr, NetMsgType::SMARTNODEPAYMENTSYNC);

        Sync(pfrom, connman);
        LogPrintf("SMARTNODEPAYMENTSYNC -- Sent Smartnode payment votes to peer %d\n", pfrom->id);

    } else if (strCommand == NetMsgType::SMARTNODEPAYMENTVOTE) { // Smartnode Payments Vote for the Winner

        CSmartnodePaymentVote vote;
        vRecv >> vote;

        if(pfrom->nVersion < GetMinSmartnodePaymentsProto()) return;

        uint256 nHash = vote.GetHash();

        pfrom->setAskFor.erase(nHash);

        // TODO: clear setAskFor for MSG_SMARTNODE_PAYMENT_BLOCK too

        // Ignore any payments messages until smartnode list is synced
        if(!smartnodeSync.IsSmartnodeListSynced()) return;

        {
            LOCK(cs_mapSmartnodePaymentVotes);
            if(mapSmartnodePaymentVotes.count(nHash)) {
                LogPrint("mnpayments", "SMARTNODEPAYMENTVOTE -- hash=%s, nHeight=%d seen\n", nHash.ToString(), nCachedBlockHeight);
                return;
            }

            // Avoid processing same vote multiple times
            mapSmartnodePaymentVotes[nHash] = vote;
            // but first mark vote as non-verified,
            // AddPaymentVote() below should take care of it if vote is actually ok
            mapSmartnodePaymentVotes[nHash].MarkAsNotVerified();
        }

        int nFirstBlock = nCachedBlockHeight - GetStorageLimit();
        if(vote.nBlockHeight < nFirstBlock || vote.nBlockHeight > nCachedBlockHeight+20) {
            LogPrint("mnpayments", "SMARTNODEPAYMENTVOTE -- vote out of range: nFirstBlock=%d, nBlockHeight=%d, nHeight=%d\n", nFirstBlock, vote.nBlockHeight, nCachedBlockHeight);
            return;
        }

        std::string strError = "";
        if(!vote.IsValid(pfrom, nCachedBlockHeight, strError, connman)) {
            LogPrint("mnpayments", "SMARTNODEPAYMENTVOTE -- invalid message, error: %s\n", strError);
            return;
        }

        if(!CanVote(vote.vinSmartnode.prevout, vote.nBlockHeight)) {
            LogPrintf("SMARTNODEPAYMENTVOTE -- smartnode already voted, smartnode=%s\n", vote.vinSmartnode.prevout.ToStringShort());
            return;
        }

        smartnode_info_t mnInfo;
        if(!mnodeman.GetSmartnodeInfo(vote.vinSmartnode.prevout, mnInfo)) {
            // mn was not found, so we can't check vote, some info is probably missing
            LogPrintf("SMARTNODEPAYMENTVOTE -- smartnode is missing %s\n", vote.vinSmartnode.prevout.ToStringShort());
            mnodeman.AskForMN(pfrom, vote.vinSmartnode.prevout, connman);
            return;
        }

        int nDos = 0;
        if(!vote.CheckSignature(mnInfo.pubKeySmartnode, nCachedBlockHeight, nDos)) {
            if(nDos) {
                LogPrintf("SMARTNODEPAYMENTVOTE -- ERROR: invalid signature\n");
                Misbehaving(pfrom->GetId(), nDos);
            } else {
                // only warn about anything non-critical (i.e. nDos == 0) in debug mode
                LogPrint("mnpayments", "SMARTNODEPAYMENTVOTE -- WARNING: invalid signature\n");
            }
            // Either our info or vote info could be outdated.
            // In case our info is outdated, ask for an update,
            mnodeman.AskForMN(pfrom, vote.vinSmartnode.prevout, connman);
            // but there is nothing we can do if vote info itself is outdated
            // (i.e. it was signed by a mn which changed its key),
            // so just quit here.
            return;
        }

        CTxDestination address1;
        ExtractDestination(vote.payee, address1);
        CBitcoinAddress address2(address1);

        LogPrint("mnpayments", "SMARTNODEPAYMENTVOTE -- vote: address=%s, nBlockHeight=%d, nHeight=%d, prevout=%s, hash=%s new\n",
                    address2.ToString(), vote.nBlockHeight, nCachedBlockHeight, vote.vinSmartnode.prevout.ToStringShort(), nHash.ToString());

        if(AddPaymentVote(vote)){
            vote.Relay(connman);
            smartnodeSync.BumpAssetLastTime("SMARTNODEPAYMENTVOTE");
        }
    }
}

bool CSmartnodePaymentVote::Sign()
{
    std::string strError;
    std::string strMessage = vinSmartnode.prevout.ToStringShort() +
                boost::lexical_cast<std::string>(nBlockHeight) +
                ScriptToAsmStr(payee);

    if(!CMessageSigner::SignMessage(strMessage, vchSig, activeSmartnode.keySmartnode)) {
        LogPrintf("CSmartnodePaymentVote::Sign -- SignMessage() failed\n");
        return false;
    }

    if(!CMessageSigner::VerifyMessage(activeSmartnode.pubKeySmartnode, vchSig, strMessage, strError)) {
        LogPrintf("CSmartnodePaymentVote::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CSmartnodePayments::GetBlockPayee(int nBlockHeight, CScript& payee)
{
    if(mapSmartnodeBlocks.count(nBlockHeight)){
        return mapSmartnodeBlocks[nBlockHeight].GetBestPayee(payee);
    }

    return false;
}

// Is this smartnode scheduled to get paid soon?
// -- Only look ahead up to 8 blocks to allow for propagation of the latest 2 blocks of votes
bool CSmartnodePayments::IsScheduled(CSmartnode& mn, int nNotBlockHeight)
{
    LOCK(cs_mapSmartnodeBlocks);

    if(!smartnodeSync.IsSmartnodeListSynced()) return false;

    CScript mnpayee;
    mnpayee = GetScriptForDestination(mn.pubKeyCollateralAddress.GetID());

    CScript payee;
    for(int64_t h = nCachedBlockHeight; h <= nCachedBlockHeight + 8; h++){
        if(h == nNotBlockHeight) continue;
        if(mapSmartnodeBlocks.count(h) && mapSmartnodeBlocks[h].GetBestPayee(payee) && mnpayee == payee) {
            return true;
        }
    }

    return false;
}

bool CSmartnodePayments::AddPaymentVote(const CSmartnodePaymentVote& vote)
{
    uint256 blockHash = uint256();
    if(!GetBlockHash(blockHash, vote.nBlockHeight - 101)) return false;

    if(HasVerifiedPaymentVote(vote.GetHash())) return false;

    LOCK2(cs_mapSmartnodeBlocks, cs_mapSmartnodePaymentVotes);

    mapSmartnodePaymentVotes[vote.GetHash()] = vote;

    if(!mapSmartnodeBlocks.count(vote.nBlockHeight)) {
       CSmartnodeBlockPayees blockPayees(vote.nBlockHeight);
       mapSmartnodeBlocks[vote.nBlockHeight] = blockPayees;
    }

    mapSmartnodeBlocks[vote.nBlockHeight].AddPayee(vote);

    return true;
}

bool CSmartnodePayments::HasVerifiedPaymentVote(uint256 hashIn)
{
    LOCK(cs_mapSmartnodePaymentVotes);
    std::map<uint256, CSmartnodePaymentVote>::iterator it = mapSmartnodePaymentVotes.find(hashIn);
    return it != mapSmartnodePaymentVotes.end() && it->second.IsVerified();
}

void CSmartnodeBlockPayees::AddPayee(const CSmartnodePaymentVote& vote)
{
    LOCK(cs_vecPayees);

    BOOST_FOREACH(CSmartnodePayee& payee, vecPayees) {
        if (payee.GetPayee() == vote.payee) {
            payee.AddVoteHash(vote.GetHash());
            return;
        }
    }
    CSmartnodePayee payeeNew(vote.payee, vote.GetHash());
    vecPayees.push_back(payeeNew);
}

bool CSmartnodeBlockPayees::GetBestPayee(CScript& payeeRet)
{
    LOCK(cs_vecPayees);

    if(!vecPayees.size()) {
        LogPrint("mnpayments", "CSmartnodeBlockPayees::GetBestPayee -- ERROR: couldn't find any payee\n");
        return false;
    }

    int nVotes = -1;
    BOOST_FOREACH(CSmartnodePayee& payee, vecPayees) {
        if (payee.GetVoteCount() > nVotes) {
            payeeRet = payee.GetPayee();
            nVotes = payee.GetVoteCount();
        }
    }

    return (nVotes > -1);
}

bool CSmartnodeBlockPayees::HasPayeeWithVotes(const CScript& payeeIn, int nVotesReq)
{
    LOCK(cs_vecPayees);

    BOOST_FOREACH(CSmartnodePayee& payee, vecPayees) {
        if (payee.GetVoteCount() >= nVotesReq && payee.GetPayee() == payeeIn) {
            return true;
        }
    }

    LogPrint("mnpayments", "CSmartnodeBlockPayees::HasPayeeWithVotes -- ERROR: couldn't find any payee with %d+ votes\n", nVotesReq);
    return false;
}

bool CSmartnodeBlockPayees::IsTransactionValid(const CTransaction& txNew)
{
    LOCK(cs_vecPayees);

    int nMaxSignatures = 0;
    std::string strPayeesPossible = "";

    CAmount nSmartnodePayment = GetSmartnodePayment(nBlockHeight, txNew.GetValueOut());

    //require at least MNPAYMENTS_SIGNATURES_REQUIRED signatures

    BOOST_FOREACH(CSmartnodePayee& payee, vecPayees) {
        if (payee.GetVoteCount() >= nMaxSignatures) {
            nMaxSignatures = payee.GetVoteCount();
        }
    }

    // if we don't have at least MNPAYMENTS_SIGNATURES_REQUIRED signatures on a payee, approve whichever is the longest chain
    if(nMaxSignatures < MNPAYMENTS_SIGNATURES_REQUIRED) return true;

    BOOST_FOREACH(CSmartnodePayee& payee, vecPayees) {
        if (payee.GetVoteCount() >= MNPAYMENTS_SIGNATURES_REQUIRED) {
            BOOST_FOREACH(CTxOut txout, txNew.vout) {
                if (payee.GetPayee() == txout.scriptPubKey && nSmartnodePayment == txout.nValue) {
                    LogPrint("mnpayments", "CSmartnodeBlockPayees::IsTransactionValid -- Found required payment\n");
                    return true;
                }
            }

            CTxDestination address1;
            ExtractDestination(payee.GetPayee(), address1);
            CBitcoinAddress address2(address1);

            if(strPayeesPossible == "") {
                strPayeesPossible = address2.ToString();
            } else {
                strPayeesPossible += "," + address2.ToString();
            }
        }
    }

    LogPrintf("CSmartnodeBlockPayees::IsTransactionValid -- ERROR: Missing required payment, possible payees: '%s', amount: %f DASH\n", strPayeesPossible, (float)nSmartnodePayment/COIN);
    return false;
}

std::string CSmartnodeBlockPayees::GetRequiredPaymentsString()
{
    LOCK(cs_vecPayees);

    std::string strRequiredPayments = "Unknown";

    BOOST_FOREACH(CSmartnodePayee& payee, vecPayees)
    {
        CTxDestination address1;
        ExtractDestination(payee.GetPayee(), address1);
        CBitcoinAddress address2(address1);

        if (strRequiredPayments != "Unknown") {
            strRequiredPayments += ", " + address2.ToString() + ":" + boost::lexical_cast<std::string>(payee.GetVoteCount());
        } else {
            strRequiredPayments = address2.ToString() + ":" + boost::lexical_cast<std::string>(payee.GetVoteCount());
        }
    }

    return strRequiredPayments;
}

std::string CSmartnodePayments::GetRequiredPaymentsString(int nBlockHeight)
{
    LOCK(cs_mapSmartnodeBlocks);

    if(mapSmartnodeBlocks.count(nBlockHeight)){
        return mapSmartnodeBlocks[nBlockHeight].GetRequiredPaymentsString();
    }

    return "Unknown";
}

bool CSmartnodePayments::IsTransactionValid(const CTransaction& txNew, int nBlockHeight)
{
    LOCK(cs_mapSmartnodeBlocks);

    if(mapSmartnodeBlocks.count(nBlockHeight)){
        return mapSmartnodeBlocks[nBlockHeight].IsTransactionValid(txNew);
    }

    return true;
}

void CSmartnodePayments::CheckAndRemove()
{
    if(!smartnodeSync.IsBlockchainSynced()) return;

    LOCK2(cs_mapSmartnodeBlocks, cs_mapSmartnodePaymentVotes);

    int nLimit = GetStorageLimit();

    std::map<uint256, CSmartnodePaymentVote>::iterator it = mapSmartnodePaymentVotes.begin();
    while(it != mapSmartnodePaymentVotes.end()) {
        CSmartnodePaymentVote vote = (*it).second;

        if(nCachedBlockHeight - vote.nBlockHeight > nLimit) {
            LogPrint("mnpayments", "CSmartnodePayments::CheckAndRemove -- Removing old Smartnode payment: nBlockHeight=%d\n", vote.nBlockHeight);
            mapSmartnodePaymentVotes.erase(it++);
            mapSmartnodeBlocks.erase(vote.nBlockHeight);
        } else {
            ++it;
        }
    }
    LogPrintf("CSmartnodePayments::CheckAndRemove -- %s\n", ToString());
}

bool CSmartnodePaymentVote::IsValid(CNode* pnode, int nValidationHeight, std::string& strError, CConnman& connman)
{
    smartnode_info_t mnInfo;

    if(!mnodeman.GetSmartnodeInfo(vinSmartnode.prevout, mnInfo)) {
        strError = strprintf("Unknown Smartnode: prevout=%s", vinSmartnode.prevout.ToStringShort());
        // Only ask if we are already synced and still have no idea about that Smartnode
        if(smartnodeSync.IsSmartnodeListSynced()) {
            mnodeman.AskForMN(pnode, vinSmartnode.prevout, connman);
        }

        return false;
    }

    int nMinRequiredProtocol;
    if(nBlockHeight >= nValidationHeight) {
        // new votes must comply SPORK_10_SMARTNODE_PAY_UPDATED_NODES rules
        nMinRequiredProtocol = mnpayments.GetMinSmartnodePaymentsProto();
    } else {
        // allow non-updated smartnodes for old blocks
        nMinRequiredProtocol = MIN_SMARTNODE_PAYMENT_PROTO_VERSION_1;
    }

    if(mnInfo.nProtocolVersion < nMinRequiredProtocol) {
        strError = strprintf("Smartnode protocol is too old: nProtocolVersion=%d, nMinRequiredProtocol=%d", mnInfo.nProtocolVersion, nMinRequiredProtocol);
        return false;
    }

    // Only smartnodes should try to check smartnode rank for old votes - they need to pick the right winner for future blocks.
    // Regular clients (miners included) need to verify smartnode rank for future block votes only.
    if(!fSmartNode && nBlockHeight < nValidationHeight) return true;

    int nRank;

    if(!mnodeman.GetSmartnodeRank(vinSmartnode.prevout, nRank, nBlockHeight - 101, nMinRequiredProtocol)) {
        LogPrint("mnpayments", "CSmartnodePaymentVote::IsValid -- Can't calculate rank for smartnode %s\n",
                    vinSmartnode.prevout.ToStringShort());
        return false;
    }

    if(nRank > MNPAYMENTS_SIGNATURES_TOTAL) {
        // It's common to have smartnodes mistakenly think they are in the top 10
        // We don't want to print all of these messages in normal mode, debug mode should print though
        strError = strprintf("Smartnode is not in the top %d (%d)", MNPAYMENTS_SIGNATURES_TOTAL, nRank);
        // Only ban for new mnw which is out of bounds, for old mnw MN list itself might be way too much off
        if(nRank > MNPAYMENTS_SIGNATURES_TOTAL*2 && nBlockHeight > nValidationHeight) {
            strError = strprintf("Smartnode is not in the top %d (%d)", MNPAYMENTS_SIGNATURES_TOTAL*2, nRank);
            LogPrintf("CSmartnodePaymentVote::IsValid -- Error: %s\n", strError);
            Misbehaving(pnode->GetId(), 20);
        }
        // Still invalid however
        return false;
    }

    return true;
}

bool CSmartnodePayments::ProcessBlock(int nBlockHeight, CConnman& connman)
{
    // DETERMINE IF WE SHOULD BE VOTING FOR THE NEXT PAYEE

    if(fLiteMode || !fSmartNode) return false;

    // We have little chances to pick the right winner if winners list is out of sync
    // but we have no choice, so we'll try. However it doesn't make sense to even try to do so
    // if we have not enough data about smartnodes.
    if(!smartnodeSync.IsSmartnodeListSynced()) return false;

    int nRank;

    if (!mnodeman.GetSmartnodeRank(activeSmartnode.outpoint, nRank, nBlockHeight - 101, GetMinSmartnodePaymentsProto())) {
        LogPrint("mnpayments", "CSmartnodePayments::ProcessBlock -- Unknown Smartnode\n");
        return false;
    }

    if (nRank > MNPAYMENTS_SIGNATURES_TOTAL) {
        LogPrint("mnpayments", "CSmartnodePayments::ProcessBlock -- Smartnode not in the top %d (%d)\n", MNPAYMENTS_SIGNATURES_TOTAL, nRank);
        return false;
    }


    // LOCATE THE NEXT SMARTNODE WHICH SHOULD BE PAID

    LogPrintf("CSmartnodePayments::ProcessBlock -- Start: nBlockHeight=%d, smartnode=%s\n", nBlockHeight, activeSmartnode.outpoint.ToStringShort());

    // pay to the oldest MN that still had no payment but its input is old enough and it was active long enough
    int nCount = 0;
    smartnode_info_t mnInfo;

    if (!mnodeman.GetNextSmartnodeInQueueForPayment(nBlockHeight, true, nCount, mnInfo)) {
        LogPrintf("CSmartnodePayments::ProcessBlock -- ERROR: Failed to find smartnode to pay\n");
        return false;
    }

    LogPrintf("CSmartnodePayments::ProcessBlock -- Smartnode found by GetNextSmartnodeInQueueForPayment(): %s\n", mnInfo.vin.prevout.ToStringShort());


    CScript payee = GetScriptForDestination(mnInfo.pubKeyCollateralAddress.GetID());

    CSmartnodePaymentVote voteNew(activeSmartnode.outpoint, nBlockHeight, payee);

    CTxDestination address1;
    ExtractDestination(payee, address1);
    CBitcoinAddress address2(address1);

    LogPrintf("CSmartnodePayments::ProcessBlock -- vote: payee=%s, nBlockHeight=%d\n", address2.ToString(), nBlockHeight);

    // SIGN MESSAGE TO NETWORK WITH OUR SMARTNODE KEYS

    LogPrintf("CSmartnodePayments::ProcessBlock -- Signing vote\n");
    if (voteNew.Sign()) {
        LogPrintf("CSmartnodePayments::ProcessBlock -- AddPaymentVote()\n");

        if (AddPaymentVote(voteNew)) {
            voteNew.Relay(connman);
            return true;
        }
    }

    return false;
}

void CSmartnodePayments::CheckPreviousBlockVotes(int nPrevBlockHeight)
{
    if (!smartnodeSync.IsWinnersListSynced()) return;

    std::string debugStr;

    debugStr += strprintf("CSmartnodePayments::CheckPreviousBlockVotes -- nPrevBlockHeight=%d, expected voting MNs:\n", nPrevBlockHeight);

    CSmartnodeMan::rank_pair_vec_t mns;
    if (!mnodeman.GetSmartnodeRanks(mns, nPrevBlockHeight - 101, GetMinSmartnodePaymentsProto())) {
        debugStr += "CSmartnodePayments::CheckPreviousBlockVotes -- GetSmartnodeRanks failed\n";
        LogPrint("mnpayments", "%s", debugStr);
        return;
    }

    LOCK2(cs_mapSmartnodeBlocks, cs_mapSmartnodePaymentVotes);

    for (int i = 0; i < MNPAYMENTS_SIGNATURES_TOTAL && i < (int)mns.size(); i++) {
        auto mn = mns[i];
        CScript payee;
        bool found = false;

        if (mapSmartnodeBlocks.count(nPrevBlockHeight)) {
            for (auto &p : mapSmartnodeBlocks[nPrevBlockHeight].vecPayees) {
                for (auto &voteHash : p.GetVoteHashes()) {
                    if (!mapSmartnodePaymentVotes.count(voteHash)) {
                        debugStr += strprintf("CSmartnodePayments::CheckPreviousBlockVotes --   could not find vote %s\n",
                                              voteHash.ToString());
                        continue;
                    }
                    auto vote = mapSmartnodePaymentVotes[voteHash];
                    if (vote.vinSmartnode.prevout == mn.second.vin.prevout) {
                        payee = vote.payee;
                        found = true;
                        break;
                    }
                }
            }
        }

        if (!found) {
            debugStr += strprintf("CSmartnodePayments::CheckPreviousBlockVotes --   %s - no vote received\n",
                                  mn.second.vin.prevout.ToStringShort());
            mapSmartnodesDidNotVote[mn.second.vin.prevout]++;
            continue;
        }

        CTxDestination address1;
        ExtractDestination(payee, address1);
        CBitcoinAddress address2(address1);

        debugStr += strprintf("CSmartnodePayments::CheckPreviousBlockVotes --   %s - voted for %s\n",
                              mn.second.vin.prevout.ToStringShort(), address2.ToString());
    }
    debugStr += "CSmartnodePayments::CheckPreviousBlockVotes -- Smartnodes which missed a vote in the past:\n";
    for (auto it : mapSmartnodesDidNotVote) {
        debugStr += strprintf("CSmartnodePayments::CheckPreviousBlockVotes --   %s: %d\n", it.first.ToStringShort(), it.second);
    }

    LogPrint("mnpayments", "%s", debugStr);
}

void CSmartnodePaymentVote::Relay(CConnman& connman)
{
    // Do not relay until fully synced
    if(!smartnodeSync.IsSynced()) {
        LogPrint("mnpayments", "CSmartnodePayments::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_SMARTNODE_PAYMENT_VOTE, GetHash());
    connman.RelayInv(inv);
}

bool CSmartnodePaymentVote::CheckSignature(const CPubKey& pubKeySmartnode, int nValidationHeight, int &nDos)
{
    // do not ban by default
    nDos = 0;

    std::string strMessage = vinSmartnode.prevout.ToStringShort() +
                boost::lexical_cast<std::string>(nBlockHeight) +
                ScriptToAsmStr(payee);

    std::string strError = "";
    if (!CMessageSigner::VerifyMessage(pubKeySmartnode, vchSig, strMessage, strError)) {
        // Only ban for future block vote when we are already synced.
        // Otherwise it could be the case when MN which signed this vote is using another key now
        // and we have no idea about the old one.
        if(smartnodeSync.IsSmartnodeListSynced() && nBlockHeight > nValidationHeight) {
            nDos = 20;
        }
        return error("CSmartnodePaymentVote::CheckSignature -- Got bad Smartnode payment signature, smartnode=%s, error: %s", vinSmartnode.prevout.ToStringShort().c_str(), strError);
    }

    return true;
}

std::string CSmartnodePaymentVote::ToString() const
{
    std::ostringstream info;

    info << vinSmartnode.prevout.ToStringShort() <<
            ", " << nBlockHeight <<
            ", " << ScriptToAsmStr(payee) <<
            ", " << (int)vchSig.size();

    return info.str();
}

// Send only votes for future blocks, node should request every other missing payment block individually
void CSmartnodePayments::Sync(CNode* pnode, CConnman& connman)
{
    LOCK(cs_mapSmartnodeBlocks);

    if(!smartnodeSync.IsWinnersListSynced()) return;

    int nInvCount = 0;

    for(int h = nCachedBlockHeight; h < nCachedBlockHeight + 20; h++) {
        if(mapSmartnodeBlocks.count(h)) {
            BOOST_FOREACH(CSmartnodePayee& payee, mapSmartnodeBlocks[h].vecPayees) {
                std::vector<uint256> vecVoteHashes = payee.GetVoteHashes();
                BOOST_FOREACH(uint256& hash, vecVoteHashes) {
                    if(!HasVerifiedPaymentVote(hash)) continue;
                    pnode->PushInventory(CInv(MSG_SMARTNODE_PAYMENT_VOTE, hash));
                    nInvCount++;
                }
            }
        }
    }

    LogPrintf("CSmartnodePayments::Sync -- Sent %d votes to peer %d\n", nInvCount, pnode->id);
    connman.PushMessage(pnode, NetMsgType::SYNCSTATUSCOUNT, SMARTNODE_SYNC_MNW, nInvCount);
}

// Request low data/unknown payment blocks in batches directly from some node instead of/after preliminary Sync.
void CSmartnodePayments::RequestLowDataPaymentBlocks(CNode* pnode, CConnman& connman)
{
    if(!smartnodeSync.IsSmartnodeListSynced()) return;

    LOCK2(cs_main, cs_mapSmartnodeBlocks);

    std::vector<CInv> vToFetch;
    int nLimit = GetStorageLimit();

    const CBlockIndex *pindex = chainActive.Tip();

    while(nCachedBlockHeight - pindex->nHeight < nLimit) {
        if(!mapSmartnodeBlocks.count(pindex->nHeight)) {
            // We have no idea about this block height, let's ask
            vToFetch.push_back(CInv(MSG_SMARTNODE_PAYMENT_BLOCK, pindex->GetBlockHash()));
            // We should not violate GETDATA rules
            if(vToFetch.size() == MAX_INV_SZ) {
                LogPrintf("CSmartnodePayments::SyncLowDataPaymentBlocks -- asking peer %d for %d blocks\n", pnode->id, MAX_INV_SZ);
                connman.PushMessage(pnode, NetMsgType::GETDATA, vToFetch);
                // Start filling new batch
                vToFetch.clear();
            }
        }
        if(!pindex->pprev) break;
        pindex = pindex->pprev;
    }

    std::map<int, CSmartnodeBlockPayees>::iterator it = mapSmartnodeBlocks.begin();

    while(it != mapSmartnodeBlocks.end()) {
        int nTotalVotes = 0;
        bool fFound = false;
        BOOST_FOREACH(CSmartnodePayee& payee, it->second.vecPayees) {
            if(payee.GetVoteCount() >= MNPAYMENTS_SIGNATURES_REQUIRED) {
                fFound = true;
                break;
            }
            nTotalVotes += payee.GetVoteCount();
        }
        // A clear winner (MNPAYMENTS_SIGNATURES_REQUIRED+ votes) was found
        // or no clear winner was found but there are at least avg number of votes
        if(fFound || nTotalVotes >= (MNPAYMENTS_SIGNATURES_TOTAL + MNPAYMENTS_SIGNATURES_REQUIRED)/2) {
            // so just move to the next block
            ++it;
            continue;
        }
        // DEBUG
        DBG (
            // Let's see why this failed
            BOOST_FOREACH(CSmartnodePayee& payee, it->second.vecPayees) {
                CTxDestination address1;
                ExtractDestination(payee.GetPayee(), address1);
                CBitcoinAddress address2(address1);
                printf("payee %s votes %d\n", address2.ToString().c_str(), payee.GetVoteCount());
            }
            printf("block %d votes total %d\n", it->first, nTotalVotes);
        )
        // END DEBUG
        // Low data block found, let's try to sync it
        uint256 hash;
        if(GetBlockHash(hash, it->first)) {
            vToFetch.push_back(CInv(MSG_SMARTNODE_PAYMENT_BLOCK, hash));
        }
        // We should not violate GETDATA rules
        if(vToFetch.size() == MAX_INV_SZ) {
            LogPrintf("CSmartnodePayments::SyncLowDataPaymentBlocks -- asking peer %d for %d payment blocks\n", pnode->id, MAX_INV_SZ);
            connman.PushMessage(pnode, NetMsgType::GETDATA, vToFetch);
            // Start filling new batch
            vToFetch.clear();
        }
        ++it;
    }
    // Ask for the rest of it
    if(!vToFetch.empty()) {
        LogPrintf("CSmartnodePayments::SyncLowDataPaymentBlocks -- asking peer %d for %d payment blocks\n", pnode->id, vToFetch.size());
        connman.PushMessage(pnode, NetMsgType::GETDATA, vToFetch);
    }
}

std::string CSmartnodePayments::ToString() const
{
    std::ostringstream info;

    info << "Votes: " << (int)mapSmartnodePaymentVotes.size() <<
            ", Blocks: " << (int)mapSmartnodeBlocks.size();

    return info.str();
}

bool CSmartnodePayments::IsEnoughData()
{
    float nAverageVotes = (MNPAYMENTS_SIGNATURES_TOTAL + MNPAYMENTS_SIGNATURES_REQUIRED) / 2;
    int nStorageLimit = GetStorageLimit();
    return GetBlockCount() > nStorageLimit && GetVoteCount() > nStorageLimit * nAverageVotes;
}

int CSmartnodePayments::GetStorageLimit()
{
    return std::max(int(mnodeman.size() * nStorageCoeff), nMinBlocksToStore);
}

void CSmartnodePayments::UpdatedBlockTip(const CBlockIndex *pindex, CConnman& connman)
{
    if(!pindex) return;

    nCachedBlockHeight = pindex->nHeight;
    LogPrint("mnpayments", "CSmartnodePayments::UpdatedBlockTip -- nCachedBlockHeight=%d\n", nCachedBlockHeight);

    int nFutureBlock = nCachedBlockHeight + 10;

    CheckPreviousBlockVotes(nFutureBlock - 1);
    ProcessBlock(nFutureBlock, connman);
}