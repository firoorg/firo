// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SMARTNODE_PAYMENTS_H
#define SMARTNODE_PAYMENTS_H

#include "../util.h"
#include "../core_io.h"
#include "../key.h"
#include "../net_processing.h"
#include "smartnode.h"
#include "../utilstrencodings.h"

class CSmartnodePayments;
class CSmartnodePaymentVote;
class CSmartnodeBlockPayees;

static const int MNPAYMENTS_SIGNATURES_REQUIRED         = 6;
static const int MNPAYMENTS_SIGNATURES_TOTAL            = 10;

//! minimum peer version that can receive and send smartnode payment messages,
//  vote for smartnode and be elected as a payment winner
// V1 - Last protocol version before update
// V2 - Newest protocol version
static const int MIN_SMARTNODE_PAYMENT_PROTO_VERSION_1 = 90023;
static const int MIN_SMARTNODE_PAYMENT_PROTO_VERSION_2 = 90023;

extern CCriticalSection cs_vecPayees;
extern CCriticalSection cs_mapSmartnodeBlocks;
extern CCriticalSection cs_mapSmartnodePayeeVotes;

extern CSmartnodePayments mnpayments;

/// TODO: all 4 functions do not belong here really, they should be refactored/moved somewhere (validation.cpp ?)
bool IsBlockValueValid(const CBlock& block, int nBlockHeight, CAmount blockReward, std::string &strErrorRet);
bool IsBlockPayeeValid(const CTransaction& txNew, int nBlockHeight, CAmount blockReward);
void FillBlockPayments(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, CTxOut& txoutSmartnodeRet, std::vector<CTxOut>& voutSuperblockRet);
std::string GetRequiredPaymentsString(int nBlockHeight);

class CSmartnodePayee
{
private:
    CScript scriptPubKey;
    std::vector<uint256> vecVoteHashes;

public:
    CSmartnodePayee() :
        scriptPubKey(),
        vecVoteHashes()
        {}

    CSmartnodePayee(CScript payee, uint256 hashIn) :
        scriptPubKey(payee),
        vecVoteHashes()
    {
        vecVoteHashes.push_back(hashIn);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*(CScriptBase*)(&scriptPubKey));
        READWRITE(vecVoteHashes);
    }

    CScript GetPayee() { return scriptPubKey; }

    void AddVoteHash(uint256 hashIn) { vecVoteHashes.push_back(hashIn); }
    std::vector<uint256> GetVoteHashes() { return vecVoteHashes; }
    int GetVoteCount() { return vecVoteHashes.size(); }
};

// Keep track of votes for payees from smartnodes
class CSmartnodeBlockPayees
{
public:
    int nBlockHeight;
    std::vector<CSmartnodePayee> vecPayees;

    CSmartnodeBlockPayees() :
        nBlockHeight(0),
        vecPayees()
        {}
    CSmartnodeBlockPayees(int nBlockHeightIn) :
        nBlockHeight(nBlockHeightIn),
        vecPayees()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nBlockHeight);
        READWRITE(vecPayees);
    }

    void AddPayee(const CSmartnodePaymentVote& vote);
    bool GetBestPayee(CScript& payeeRet);
    bool HasPayeeWithVotes(const CScript& payeeIn, int nVotesReq);

    bool IsTransactionValid(const CTransaction& txNew);

    std::string GetRequiredPaymentsString();
};

// vote for the winning payment
class CSmartnodePaymentVote
{
public:
    CTxIn vinSmartnode;

    int nBlockHeight;
    CScript payee;
    std::vector<unsigned char> vchSig;

    CSmartnodePaymentVote() :
        vinSmartnode(),
        nBlockHeight(0),
        payee(),
        vchSig()
        {}

    CSmartnodePaymentVote(COutPoint outpointSmartnode, int nBlockHeight, CScript payee) :
        vinSmartnode(outpointSmartnode),
        nBlockHeight(nBlockHeight),
        payee(payee),
        vchSig()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vinSmartnode);
        READWRITE(nBlockHeight);
        READWRITE(*(CScriptBase*)(&payee));
        READWRITE(vchSig);
    }

    uint256 GetHash() const {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << *(CScriptBase*)(&payee);
        ss << nBlockHeight;
        ss << vinSmartnode.prevout;
        return ss.GetHash();
    }

    bool Sign();
    bool CheckSignature(const CPubKey& pubKeySmartnode, int nValidationHeight, int &nDos);

    bool IsValid(CNode* pnode, int nValidationHeight, std::string& strError, CConnman& connman);
    void Relay(CConnman& connman);

    bool IsVerified() { return !vchSig.empty(); }
    void MarkAsNotVerified() { vchSig.clear(); }

    std::string ToString() const;
};

//
// Smartnode Payments Class
// Keeps track of who should get paid for which blocks
//

class CSmartnodePayments
{
private:
    // smartnode count times nStorageCoeff payments blocks should be stored ...
    const float nStorageCoeff;
    // ... but at least nMinBlocksToStore (payments blocks)
    const int nMinBlocksToStore;

    // Keep track of current block height
    int nCachedBlockHeight;

public:
    std::map<uint256, CSmartnodePaymentVote> mapSmartnodePaymentVotes;
    std::map<int, CSmartnodeBlockPayees> mapSmartnodeBlocks;
    std::map<COutPoint, int> mapSmartnodesLastVote;
    std::map<COutPoint, int> mapSmartnodesDidNotVote;

    CSmartnodePayments() : nStorageCoeff(1.25), nMinBlocksToStore(5000) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(mapSmartnodePaymentVotes);
        READWRITE(mapSmartnodeBlocks);
    }

    void Clear();

    bool AddPaymentVote(const CSmartnodePaymentVote& vote);
    bool HasVerifiedPaymentVote(uint256 hashIn);
    bool ProcessBlock(int nBlockHeight, CConnman& connman);
    void CheckPreviousBlockVotes(int nPrevBlockHeight);

    void Sync(CNode* node, CConnman& connman);
    void RequestLowDataPaymentBlocks(CNode* pnode, CConnman& connman);
    void CheckAndRemove();

    bool GetBlockPayee(int nBlockHeight, CScript& payee);
    bool IsTransactionValid(const CTransaction& txNew, int nBlockHeight);
    bool IsScheduled(CSmartnode& mn, int nNotBlockHeight);

    bool CanVote(COutPoint outSmartnode, int nBlockHeight);

    int GetMinSmartnodePaymentsProto();
    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv, CConnman& connman);
    std::string GetRequiredPaymentsString(int nBlockHeight);
    void FillBlockPayee(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, CTxOut& txoutSmartnodeRet);
    std::string ToString() const;

    int GetBlockCount() { return mapSmartnodeBlocks.size(); }
    int GetVoteCount() { return mapSmartnodePaymentVotes.size(); }

    bool IsEnoughData();
    int GetStorageLimit();

    void UpdatedBlockTip(const CBlockIndex *pindex, CConnman& connman);
};

#endif
