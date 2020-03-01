// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZNODE_PAYMENTS_H
#define ZNODE_PAYMENTS_H

#include "util.h"
#include "core_io.h"
#include "key.h"
#include "validation.h"
#include "znode.h"
#include "utilstrencodings.h"

class CZnodePayments;
class CZnodePaymentVote;
class CZnodeBlockPayees;

static const int MNPAYMENTS_SIGNATURES_REQUIRED         = 6;
static const int MNPAYMENTS_SIGNATURES_TOTAL            = 10;

//! minimum peer version that can receive and send znode payment messages,
//  vote for znode and be elected as a payment winner
// V1 - Last protocol version before update
// V2 - Newest protocol version
static const int MIN_ZNODE_PAYMENT_PROTO_VERSION_1 = 90024;
static const int MIN_ZNODE_PAYMENT_PROTO_VERSION_2 = 90026;

extern CCriticalSection cs_vecPayees;
extern CCriticalSection cs_mapZnodeBlocks;
extern CCriticalSection cs_mapZnodePayeeVotes;

extern CZnodePayments mnpayments;

/// TODO: all 4 functions do not belong here really, they should be refactored/moved somewhere (main.cpp ?)
bool IsBlockValueValid(const CBlock& block, int nBlockHeight, CAmount blockReward, std::string &strErrorRet);
bool IsBlockPayeeValid(const CTransaction& txNew, int nBlockHeight, CAmount blockReward, bool fMTP);
void FillBlockPayments(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, CTxOut& txoutZnodeRet, std::vector<CTxOut>& voutSuperblockRet);
std::string GetRequiredPaymentsString(int nBlockHeight);

class CZnodePayee
{
private:
    CScript scriptPubKey;
    std::vector<uint256> vecVoteHashes;

public:
    CZnodePayee() :
        scriptPubKey(),
        vecVoteHashes()
        {}

    CZnodePayee(CScript payee, uint256 hashIn) :
        scriptPubKey(payee),
        vecVoteHashes()
    {
        vecVoteHashes.push_back(hashIn);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CScriptBase*)(&scriptPubKey));
        READWRITE(vecVoteHashes);
    }

    CScript GetPayee() { return scriptPubKey; }

    void AddVoteHash(uint256 hashIn) { vecVoteHashes.push_back(hashIn); }
    std::vector<uint256> GetVoteHashes() { return vecVoteHashes; }
    int GetVoteCount() { return vecVoteHashes.size(); }
    std::string ToString() const;
};

// Keep track of votes for payees from znodes
class CZnodeBlockPayees
{
public:
    int nBlockHeight;
    std::vector<CZnodePayee> vecPayees;

    CZnodeBlockPayees() :
        nBlockHeight(0),
        vecPayees()
        {}
    CZnodeBlockPayees(int nBlockHeightIn) :
        nBlockHeight(nBlockHeightIn),
        vecPayees()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBlockHeight);
        READWRITE(vecPayees);
    }

    void AddPayee(const CZnodePaymentVote& vote);
    bool GetBestPayee(CScript& payeeRet);
    bool HasPayeeWithVotes(CScript payeeIn, int nVotesReq);

    bool IsTransactionValid(const CTransaction& txNew, bool fMTP);

    std::string GetRequiredPaymentsString();
};

// vote for the winning payment
class CZnodePaymentVote
{
public:
    CTxIn vinZnode;

    int nBlockHeight;
    CScript payee;
    std::vector<unsigned char> vchSig;

    CZnodePaymentVote() :
        vinZnode(),
        nBlockHeight(0),
        payee(),
        vchSig()
        {}

    CZnodePaymentVote(CTxIn vinZnode, int nBlockHeight, CScript payee) :
        vinZnode(vinZnode),
        nBlockHeight(nBlockHeight),
        payee(payee),
        vchSig()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vinZnode);
        READWRITE(nBlockHeight);
        READWRITE(*(CScriptBase*)(&payee));
        READWRITE(vchSig);
    }

    uint256 GetHash() const {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << *(CScriptBase*)(&payee);
        ss << nBlockHeight;
        ss << vinZnode.prevout;
        return ss.GetHash();
    }

    bool Sign();
    bool CheckSignature(const CPubKey& pubKeyZnode, int nValidationHeight, int &nDos);

    bool IsValid(CNode* pnode, int nValidationHeight, std::string& strError);
    void Relay();

    bool IsVerified() { return !vchSig.empty(); }
    void MarkAsNotVerified() { vchSig.clear(); }

    std::string ToString() const;
};

//
// Znode Payments Class
// Keeps track of who should get paid for which blocks
//

class CZnodePayments
{
private:
    // znode count times nStorageCoeff payments blocks should be stored ...
    const float nStorageCoeff;
    // ... but at least nMinBlocksToStore (payments blocks)
    const int nMinBlocksToStore;

    // Keep track of current block index
    const CBlockIndex *pCurrentBlockIndex;

public:
    std::map<uint256, CZnodePaymentVote> mapZnodePaymentVotes;
    std::map<int, CZnodeBlockPayees> mapZnodeBlocks;
    std::map<COutPoint, int> mapZnodesLastVote;

    CZnodePayments() : nStorageCoeff(1.25), nMinBlocksToStore(5000) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(mapZnodePaymentVotes);
        READWRITE(mapZnodeBlocks);
    }

    void Clear();

    bool AddPaymentVote(const CZnodePaymentVote& vote);
    bool HasVerifiedPaymentVote(uint256 hashIn);
    bool ProcessBlock(int nBlockHeight);

    void Sync(CNode* node);
    void RequestLowDataPaymentBlocks(CNode* pnode);
    void CheckAndRemove();

    bool GetBlockPayee(int nBlockHeight, CScript& payee);
    bool IsTransactionValid(const CTransaction& txNew, int nBlockHeight, bool fMTP);
    bool IsScheduled(CZnode& mn, int nNotBlockHeight);

    bool CanVote(COutPoint outZnode, int nBlockHeight);

    int GetMinZnodePaymentsProto();
    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    std::string GetRequiredPaymentsString(int nBlockHeight);
    void FillBlockPayee(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, CTxOut& txoutZnodeRet);
    std::string ToString() const;

    int GetBlockCount() { return mapZnodeBlocks.size(); }
    int GetVoteCount() { return mapZnodePaymentVotes.size(); }

    bool IsEnoughData();
    int GetStorageLimit();

    void UpdatedBlockTip(const CBlockIndex *pindex);
};

#endif
