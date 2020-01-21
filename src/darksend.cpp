// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activeznode.h"
#include "wallet/coincontrol.h"
#include "consensus/validation.h"
#include "darksend.h"
//#include "governance.h"
#include "init.h"
#include "instantx.h"
#include "znode-payments.h"
#include "znode-sync.h"
#include "znodeman.h"
#include "script/sign.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"

#include <boost/lexical_cast.hpp>

int nPrivateSendRounds = DEFAULT_PRIVATESEND_ROUNDS;
int nPrivateSendAmount = DEFAULT_PRIVATESEND_AMOUNT;
int nLiquidityProvider = DEFAULT_PRIVATESEND_LIQUIDITY;
bool fEnablePrivateSend = false;
bool fPrivateSendMultiSession = DEFAULT_PRIVATESEND_MULTISESSION;

CDarksendPool darkSendPool;
CDarkSendSigner darkSendSigner;
std::map <uint256, CDarksendBroadcastTx> mapDarksendBroadcastTxes;
std::vector <CAmount> vecPrivateSendDenominations;

void CDarksendPool::ProcessMessage(CNode *pfrom, std::string &strCommand, CDataStream &vRecv) {}

void CDarksendPool::InitDenominations() {
    vecPrivateSendDenominations.clear();
    /* Denominations

        A note about convertability. Within mixing pools, each denomination
        is convertable to another.

        For example:
        1DRK+1000 == (.1DRK+100)*10
        10DRK+10000 == (1DRK+1000)*10
    */
    /* Disabled
    vecPrivateSendDenominations.push_back( (100      * COIN)+100000 );
    */
    vecPrivateSendDenominations.push_back((10 * COIN) + 10000);
    vecPrivateSendDenominations.push_back((1 * COIN) + 1000);
    vecPrivateSendDenominations.push_back((.1 * COIN) + 100);
    vecPrivateSendDenominations.push_back((.01 * COIN) + 10);
    /* Disabled till we need them
    vecPrivateSendDenominations.push_back( (.001     * COIN)+1 );
    */
}

void CDarksendPool::ResetPool() {
    nCachedLastSuccessBlock = 0;
    txMyCollateral = CMutableTransaction();
    vecZnodesUsed.clear();
    UnlockCoins();
    SetNull();
}

void CDarksendPool::SetNull() {
    // MN side
    vecSessionCollaterals.clear();

    // Client side
    nEntriesCount = 0;
    fLastEntryAccepted = false;
    pSubmittedToZnode = NULL;

    // Both sides
    nState = POOL_STATE_IDLE;
    nSessionID = 0;
    nSessionDenom = 0;
    vecEntries.clear();
    finalMutableTransaction.vin.clear();
    finalMutableTransaction.vout.clear();
    nTimeLastSuccessfulStep = GetTimeMillis();
}

//
// Unlock coins after mixing fails or succeeds
//
void CDarksendPool::UnlockCoins() {
    while (true) {
        TRY_LOCK(pwalletMain->cs_wallet, lockWallet);
        if (!lockWallet) {
            MilliSleep(50);
            continue;
        }
        BOOST_FOREACH(COutPoint
        outpoint, vecOutPointLocked)
        pwalletMain->UnlockCoin(outpoint);
        break;
    }

    vecOutPointLocked.clear();
}

std::string CDarksendPool::GetStateString() const {
    switch (nState) {
        case POOL_STATE_IDLE:
            return "IDLE";
        case POOL_STATE_QUEUE:
            return "QUEUE";
        case POOL_STATE_ACCEPTING_ENTRIES:
            return "ACCEPTING_ENTRIES";
        case POOL_STATE_SIGNING:
            return "SIGNING";
        case POOL_STATE_ERROR:
            return "ERROR";
        case POOL_STATE_SUCCESS:
            return "SUCCESS";
        default:
            return "UNKNOWN";
    }
}

std::string CDarksendPool::GetStatus() {
    static int nStatusMessageProgress = 0;
    nStatusMessageProgress += 10;
    std::string strSuffix = "";

    if ((pCurrentBlockIndex && pCurrentBlockIndex->nHeight - nCachedLastSuccessBlock < nMinBlockSpacing) || !znodeSync.GetBlockchainSynced())
        return strAutoDenomResult;

    switch (nState) {
        case POOL_STATE_IDLE:
            return _("PrivateSend is idle.");
        case POOL_STATE_QUEUE:
            if (nStatusMessageProgress % 70 <= 30) strSuffix = ".";
            else if (nStatusMessageProgress % 70 <= 50) strSuffix = "..";
            else if (nStatusMessageProgress % 70 <= 70) strSuffix = "...";
            return strprintf(_("Submitted to znode, waiting in queue %s"), strSuffix);;
        case POOL_STATE_ACCEPTING_ENTRIES:
            if (nEntriesCount == 0) {
                nStatusMessageProgress = 0;
                return strAutoDenomResult;
            } else if (fLastEntryAccepted) {
                if (nStatusMessageProgress % 10 > 8) {
                    fLastEntryAccepted = false;
                    nStatusMessageProgress = 0;
                }
                return _("PrivateSend request complete:") + " " + _("Your transaction was accepted into the pool!");
            } else {
                if (nStatusMessageProgress % 70 <= 40) return strprintf(_("Submitted following entries to znode: %u / %d"), nEntriesCount, GetMaxPoolTransactions());
                else if (nStatusMessageProgress % 70 <= 50) strSuffix = ".";
                else if (nStatusMessageProgress % 70 <= 60) strSuffix = "..";
                else if (nStatusMessageProgress % 70 <= 70) strSuffix = "...";
                return strprintf(_("Submitted to znode, waiting for more entries ( %u / %d ) %s"), nEntriesCount, GetMaxPoolTransactions(), strSuffix);
            }
        case POOL_STATE_SIGNING:
            if (nStatusMessageProgress % 70 <= 40) return _("Found enough users, signing ...");
            else if (nStatusMessageProgress % 70 <= 50) strSuffix = ".";
            else if (nStatusMessageProgress % 70 <= 60) strSuffix = "..";
            else if (nStatusMessageProgress % 70 <= 70) strSuffix = "...";
            return strprintf(_("Found enough users, signing ( waiting %s )"), strSuffix);
        case POOL_STATE_ERROR:
            return _("PrivateSend request incomplete:") + " " + strLastMessage + " " + _("Will retry...");
        case POOL_STATE_SUCCESS:
            return _("PrivateSend request complete:") + " " + strLastMessage;
        default:
            return strprintf(_("Unknown state: id = %u"), nState);
    }
}

//
// Check the mixing progress and send client updates if a Znode
//
void CDarksendPool::CheckPool() {
    if (fZNode) {
        LogPrint("privatesend", "CDarksendPool::CheckPool -- entries count %lu\n", GetEntriesCount());

        // If entries are full, create finalized transaction
        if (nState == POOL_STATE_ACCEPTING_ENTRIES && GetEntriesCount() >= GetMaxPoolTransactions()) {
            LogPrint("privatesend", "CDarksendPool::CheckPool -- FINALIZE TRANSACTIONS\n");
            CreateFinalTransaction();
            return;
        }

        // If we have all of the signatures, try to compile the transaction
        if (nState == POOL_STATE_SIGNING && IsSignaturesComplete()) {
            LogPrint("privatesend", "CDarksendPool::CheckPool -- SIGNING\n");
            CommitFinalTransaction();
            return;
        }
    }

    // reset if we're here for 10 seconds
    if ((nState == POOL_STATE_ERROR || nState == POOL_STATE_SUCCESS) && GetTimeMillis() - nTimeLastSuccessfulStep >= 10000) {
        LogPrint("privatesend", "CDarksendPool::CheckPool -- timeout, RESETTING\n");
        UnlockCoins();
        SetNull();
    }
}

void CDarksendPool::CreateFinalTransaction() {
    LogPrint("privatesend", "CDarksendPool::CreateFinalTransaction -- FINALIZE TRANSACTIONS\n");

    CMutableTransaction txNew;

    // make our new transaction
    for (int i = 0; i < GetEntriesCount(); i++) {
        BOOST_FOREACH(
        const CTxDSOut &txdsout, vecEntries[i].vecTxDSOut)
        txNew.vout.push_back(txdsout);

        BOOST_FOREACH(
        const CTxDSIn &txdsin, vecEntries[i].vecTxDSIn)
        txNew.vin.push_back(txdsin);
    }

    // BIP69 https://github.com/kristovatlas/bips/blob/master/bip-0069.mediawiki
    sort(txNew.vin.begin(), txNew.vin.end());
    sort(txNew.vout.begin(), txNew.vout.end());

    finalMutableTransaction = txNew;
    LogPrint("privatesend", "CDarksendPool::CreateFinalTransaction -- finalMutableTransaction=%s", txNew.ToString());

    // request signatures from clients
    RelayFinalTransaction(finalMutableTransaction);
    SetState(POOL_STATE_SIGNING);
}

void CDarksendPool::CommitFinalTransaction() {
}

//
// Charge clients a fee if they're abusive
//
// Why bother? PrivateSend uses collateral to ensure abuse to the process is kept to a minimum.
// The submission and signing stages are completely separate. In the cases where
// a client submits a transaction then refused to sign, there must be a cost. Otherwise they
// would be able to do this over and over again and bring the mixing to a hault.
//
// How does this work? Messages to Znodes come in via NetMsgType::DSVIN, these require a valid collateral
// transaction for the client to be able to enter the pool. This transaction is kept by the Znode
// until the transaction is either complete or fails.
//
void CDarksendPool::ChargeFees() {
}

/*
    Charge the collateral randomly.
    Mixing is completely free, to pay miners we randomly pay the collateral of users.

    Collateral Fee Charges:

    Being that mixing has "no fees" we need to have some kind of cost associated
    with using it to stop abuse. Otherwise it could serve as an attack vector and
    allow endless transaction that would bloat Zcoin and make it unusable. To
    stop these kinds of attacks 1 in 10 successful transactions are charged. This
    adds up to a cost of 0.001DRK per transaction on average.
*/
void CDarksendPool::ChargeRandomFees() {
}

//
// Check for various timeouts (queue objects, mixing, etc)
//
void CDarksendPool::CheckTimeout() {
}

/*
    Check to see if we're ready for submissions from clients
    After receiving multiple dsa messages, the queue will switch to "accepting entries"
    which is the active state right before merging the transaction
*/
void CDarksendPool::CheckForCompleteQueue() {
}

// Check to make sure a given input matches an input in the pool and its scriptSig is valid
bool CDarksendPool::IsInputScriptSigValid(const CTxIn &txin) {
    return true;
}

// check to make sure the collateral provided by the client is valid
bool CDarksendPool::IsCollateralValid(const CTransaction &txCollateral) {
    return true;
}


//
// Add a clients transaction to the pool
//
bool CDarksendPool::AddEntry(const CDarkSendEntry &entryNew, PoolMessage &nMessageIDRet) {
    return true;
}

bool CDarksendPool::AddScriptSig(const CTxIn &txinNew) {
    return false;
}

// Check to make sure everything is signed
bool CDarksendPool::IsSignaturesComplete() {
    return true;
}

//
// Execute a mixing denomination via a Znode.
// This is only ran from clients
//
bool CDarksendPool::SendDenominate(const std::vector <CTxIn> &vecTxIn, const std::vector <CTxOut> &vecTxOut) {
    return true;
}

// Incoming message from Znode updating the progress of mixing
bool CDarksendPool::CheckPoolStateUpdate(PoolState nStateNew, int nEntriesCountNew, PoolStatusUpdate nStatusUpdate, PoolMessage nMessageID, int nSessionIDNew) {
    return false;
}

//
// After we receive the finalized transaction from the Znode, we must
// check it to make sure it's what we want, then sign it if we agree.
// If we refuse to sign, it's possible we'll be charged collateral
//
bool CDarksendPool::SignFinalTransaction(const CTransaction &finalTransactionNew, CNode *pnode) {
    return true;
}

void CDarksendPool::NewBlock() {
}

// mixing transaction was completed (failed or successful)
void CDarksendPool::CompletedTransaction(PoolMessage nMessageID) {
}

//
// Passively run mixing in the background to anonymize funds based on the given configuration.
//
bool CDarksendPool::DoAutomaticDenominating(bool fDryRun) {
    return false;
}

bool CDarksendPool::SubmitDenominate() {
    return false;
}

bool CDarksendPool::PrepareDenominate(int nMinRounds, int nMaxRounds, std::string &strErrorRet, std::vector <CTxIn> &vecTxInRet, std::vector <CTxOut> &vecTxOutRet) {
    return true;
}

// Create collaterals by looping through inputs grouped by addresses
bool CDarksendPool::MakeCollateralAmounts() {
    return false;
}

// Split up large inputs or create fee sized inputs
bool CDarksendPool::MakeCollateralAmounts(const CompactTallyItem &tallyItem) {
    return true;
}

// Create denominations by looping through inputs grouped by addresses
bool CDarksendPool::CreateDenominated() {
    return false;
}

// Create denominations
bool CDarksendPool::CreateDenominated(const CompactTallyItem &tallyItem, bool fCreateMixingCollaterals) {
    return true;
}

bool CDarksendPool::IsOutputsCompatibleWithSessionDenom(const std::vector <CTxDSOut> &vecTxDSOut) {
    return true;
}

bool CDarksendPool::IsAcceptableDenomAndCollateral(int nDenom, CTransaction txCollateral, PoolMessage &nMessageIDRet) {
    return true;
}

bool CDarksendPool::CreateNewSession(int nDenom, CTransaction txCollateral, PoolMessage &nMessageIDRet) {
    return true;
}

bool CDarksendPool::AddUserToExistingSession(int nDenom, CTransaction txCollateral, PoolMessage &nMessageIDRet) {
    return true;
}

/*  Create a nice string to show the denominations
    Function returns as follows (for 4 denominations):
        ( bit on if present )
        bit 0           - 100
        bit 1           - 10
        bit 2           - 1
        bit 3           - .1
        bit 4 and so on - out-of-bounds
        none of above   - non-denom
*/
std::string CDarksendPool::GetDenominationsToString(int nDenom) {
    std::string strDenom = "";
    int nMaxDenoms = vecPrivateSendDenominations.size();

    if (nDenom >= (1 << nMaxDenoms)) {
        return "out-of-bounds";
    }

    for (int i = 0; i < nMaxDenoms; ++i) {
        if (nDenom & (1 << i)) {
            strDenom += (strDenom.empty() ? "" : "+") + FormatMoney(vecPrivateSendDenominations[i]);
        }
    }

    if (strDenom.empty()) {
        return "non-denom";
    }

    return strDenom;
}

int CDarksendPool::GetDenominations(const std::vector <CTxDSOut> &vecTxDSOut) {
    std::vector <CTxOut> vecTxOut;

    BOOST_FOREACH(CTxDSOut
    out, vecTxDSOut)
    vecTxOut.push_back(out);

    return GetDenominations(vecTxOut);
}

/*  Return a bitshifted integer representing the denominations in this list
    Function returns as follows (for 4 denominations):
        ( bit on if present )
        100       - bit 0
        10        - bit 1
        1         - bit 2
        .1        - bit 3
        non-denom - 0, all bits off
*/
int CDarksendPool::GetDenominations(const std::vector <CTxOut> &vecTxOut, bool fSingleRandomDenom) {
    std::vector <std::pair<CAmount, int>> vecDenomUsed;

    // make a list of denominations, with zero uses
    BOOST_FOREACH(CAmount
    nDenomValue, vecPrivateSendDenominations)
    vecDenomUsed.push_back(std::make_pair(nDenomValue, 0));

    // look for denominations and update uses to 1
    BOOST_FOREACH(CTxOut
    txout, vecTxOut) {
        bool found = false;
        BOOST_FOREACH(PAIRTYPE(CAmount, int) &s, vecDenomUsed)
        {
            if (txout.nValue == s.first) {
                s.second = 1;
                found = true;
            }
        }
        if (!found) return 0;
    }

    int nDenom = 0;
    int c = 0;
    // if the denomination is used, shift the bit on
    BOOST_FOREACH(PAIRTYPE(CAmount, int) &s, vecDenomUsed)
    {
        int bit = (fSingleRandomDenom ? GetRandInt(2) : 1) & s.second;
        nDenom |= bit << c++;
        if (fSingleRandomDenom && bit) break; // use just one random denomination
    }

    return nDenom;
}

bool CDarksendPool::GetDenominationsBits(int nDenom, std::vector<int> &vecBitsRet) {
    // ( bit on if present, 4 denominations example )
    // bit 0 - 100DASH+1
    // bit 1 - 10DASH+1
    // bit 2 - 1DASH+1
    // bit 3 - .1DASH+1

    int nMaxDenoms = vecPrivateSendDenominations.size();

    if (nDenom >= (1 << nMaxDenoms)) return false;

    vecBitsRet.clear();

    for (int i = 0; i < nMaxDenoms; ++i) {
        if (nDenom & (1 << i)) {
            vecBitsRet.push_back(i);
        }
    }

    return !vecBitsRet.empty();
}

int CDarksendPool::GetDenominationsByAmounts(const std::vector <CAmount> &vecAmount) {
    CScript scriptTmp = CScript();
    std::vector <CTxOut> vecTxOut;

    BOOST_REVERSE_FOREACH(CAmount
    nAmount, vecAmount) {
        CTxOut txout(nAmount, scriptTmp);
        vecTxOut.push_back(txout);
    }

    return GetDenominations(vecTxOut, true);
}

std::string CDarksendPool::GetMessageByID(PoolMessage nMessageID) {
    switch (nMessageID) {
        case ERR_ALREADY_HAVE:
            return _("Already have that input.");
        case ERR_DENOM:
            return _("No matching denominations found for mixing.");
        case ERR_ENTRIES_FULL:
            return _("Entries are full.");
        case ERR_EXISTING_TX:
            return _("Not compatible with existing transactions.");
        case ERR_FEES:
            return _("Transaction fees are too high.");
        case ERR_INVALID_COLLATERAL:
            return _("Collateral not valid.");
        case ERR_INVALID_INPUT:
            return _("Input is not valid.");
        case ERR_INVALID_SCRIPT:
            return _("Invalid script detected.");
        case ERR_INVALID_TX:
            return _("Transaction not valid.");
        case ERR_MAXIMUM:
            return _("Value more than PrivateSend pool maximum allows.");
        case ERR_MN_LIST:
            return _("Not in the Znode list.");
        case ERR_MODE:
            return _("Incompatible mode.");
        case ERR_NON_STANDARD_PUBKEY:
            return _("Non-standard public key detected.");
        case ERR_NOT_A_MN:
            return _("This is not a Znode.");
        case ERR_QUEUE_FULL:
            return _("Znode queue is full.");
        case ERR_RECENT:
            return _("Last PrivateSend was too recent.");
        case ERR_SESSION:
            return _("Session not complete!");
        case ERR_MISSING_TX:
            return _("Missing input transaction information.");
        case ERR_VERSION:
            return _("Incompatible version.");
        case MSG_NOERR:
            return _("No errors detected.");
        case MSG_SUCCESS:
            return _("Transaction created successfully.");
        case MSG_ENTRIES_ADDED:
            return _("Your entries added successfully.");
        default:
            return _("Unknown response.");
    }
}

bool CDarkSendSigner::IsVinAssociatedWithPubkey(const CTxIn &txin, const CPubKey &pubkey) {
    return false;
}

bool CDarkSendSigner::GetKeysFromSecret(std::string strSecret, CKey &keyRet, CPubKey &pubkeyRet) {
    CBitcoinSecret vchSecret;

    if (!vchSecret.SetString(strSecret)) return false;

    keyRet = vchSecret.GetKey();
    pubkeyRet = keyRet.GetPubKey();

    return true;
}

bool CDarkSendSigner::SignMessage(std::string strMessage, std::vector<unsigned char> &vchSigRet, CKey key) {
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    return key.SignCompact(ss.GetHash(), vchSigRet);
}

bool CDarkSendSigner::VerifyMessage(CPubKey pubkey, const std::vector<unsigned char> &vchSig, std::string strMessage, std::string &strErrorRet) {
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkeyFromSig;
    if (!pubkeyFromSig.RecoverCompact(ss.GetHash(), vchSig)) {
        strErrorRet = "Error recovering public key.";
        return false;
    }

    if (pubkeyFromSig.GetID() != pubkey.GetID()) {
        strErrorRet = strprintf("Keys don't match: pubkey=%s, pubkeyFromSig=%s, strMessage=%s, vchSig=%s",
                                pubkey.GetID().ToString(), pubkeyFromSig.GetID().ToString(), strMessage,
                                EncodeBase64(&vchSig[0], vchSig.size()));
        return false;
    }

    return true;
}

bool CDarkSendEntry::AddScriptSig(const CTxIn &txin) {
    BOOST_FOREACH(CTxDSIn & txdsin, vecTxDSIn)
    {
        if (txdsin.prevout == txin.prevout && txdsin.nSequence == txin.nSequence) {
            if (txdsin.fHasSig) return false;

            txdsin.scriptSig = txin.scriptSig;
            txdsin.prevPubKey = txin.prevPubKey;
            txdsin.fHasSig = true;

            return true;
        }
    }

    return false;
}

bool CDarksendQueue::Sign() {
    if (!fZNode) return false;

    std::string strMessage = vin.ToString() + boost::lexical_cast<std::string>(nDenom) + boost::lexical_cast<std::string>(nTime) + boost::lexical_cast<std::string>(fReady);

    if (!darkSendSigner.SignMessage(strMessage, vchSig, activeZnode.keyZnode)) {
        LogPrintf("CDarksendQueue::Sign -- SignMessage() failed, %s\n", ToString());
        return false;
    }

    return CheckSignature(activeZnode.pubKeyZnode);
}

bool CDarksendQueue::CheckSignature(const CPubKey &pubKeyZnode) {
    std::string strMessage = vin.ToString() + boost::lexical_cast<std::string>(nDenom) + boost::lexical_cast<std::string>(nTime) + boost::lexical_cast<std::string>(fReady);
    std::string strError = "";

    if (!darkSendSigner.VerifyMessage(pubKeyZnode, vchSig, strMessage, strError)) {
        LogPrintf("CDarksendQueue::CheckSignature -- Got bad Znode queue signature: %s; error: %s\n", ToString(), strError);
        return false;
    }

    return true;
}

bool CDarksendQueue::Relay() {
    return true;
}

bool CDarksendBroadcastTx::Sign() {
    if (!fZNode) return false;

    std::string strMessage = tx.GetHash().ToString() + boost::lexical_cast<std::string>(sigTime);

    if (!darkSendSigner.SignMessage(strMessage, vchSig, activeZnode.keyZnode)) {
        LogPrintf("CDarksendBroadcastTx::Sign -- SignMessage() failed\n");
        return false;
    }

    return CheckSignature(activeZnode.pubKeyZnode);
}

bool CDarksendBroadcastTx::CheckSignature(const CPubKey &pubKeyZnode) {
    std::string strMessage = tx.GetHash().ToString() + boost::lexical_cast<std::string>(sigTime);
    std::string strError = "";

    if (!darkSendSigner.VerifyMessage(pubKeyZnode, vchSig, strMessage, strError)) {
        LogPrintf("CDarksendBroadcastTx::CheckSignature -- Got bad dstx signature, error: %s\n", strError);
        return false;
    }

    return true;
}

void CDarksendPool::RelayFinalTransaction(const CTransaction &txFinal) {
}

void CDarksendPool::RelayIn(const CDarkSendEntry &entry) {
}

void CDarksendPool::PushStatus(CNode *pnode, PoolStatusUpdate nStatusUpdate, PoolMessage nMessageID) {
}

void CDarksendPool::RelayStatus(PoolStatusUpdate nStatusUpdate, PoolMessage nMessageID) {
}

void CDarksendPool::RelayCompletedTransaction(PoolMessage nMessageID) {
}

void CDarksendPool::SetState(PoolState nStateNew) {
}

void CDarksendPool::UpdatedBlockTip(const CBlockIndex *pindex) {
}

//TODO: Rename/move to core
void ThreadCheckDarkSendPool() {}
