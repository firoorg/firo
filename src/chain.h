// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAIN_H
#define BITCOIN_CHAIN_H

#include "arith_uint256.h"
#include "primitives/block.h"
#include "pow.h"
#include "tinyformat.h"
#include "uint256.h"
#include "bitcoin_bignum/bignum.h"
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include "sigma/coin.h"
#include "libspark/coin.h"
#include "evo/spork.h"
#include "firo_params.h"
#include "util.h"
#include "chainparams.h"
#include "coin_containers.h"
#include "streams.h"
#include "sparkname.h"

#include <vector>
#include <unordered_set>

class CBlockFileInfo
{
public:
    unsigned int nBlocks;      //!< number of blocks stored in file
    unsigned int nSize;        //!< number of used bytes of block file
    unsigned int nUndoSize;    //!< number of used bytes in the undo file
    unsigned int nHeightFirst; //!< lowest height of block in file
    unsigned int nHeightLast;  //!< highest height of block in file
    uint64_t nTimeFirst;       //!< earliest time of block in file
    uint64_t nTimeLast;        //!< latest time of block in file

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nBlocks));
        READWRITE(VARINT(nSize));
        READWRITE(VARINT(nUndoSize));
        READWRITE(VARINT(nHeightFirst));
        READWRITE(VARINT(nHeightLast));
        READWRITE(VARINT(nTimeFirst));
        READWRITE(VARINT(nTimeLast));
    }

     void SetNull() {
         nBlocks = 0;
         nSize = 0;
         nUndoSize = 0;
         nHeightFirst = 0;
         nHeightLast = 0;
         nTimeFirst = 0;
         nTimeLast = 0;
     }

     CBlockFileInfo() {
         SetNull();
     }

     std::string ToString() const;

     /** update statistics (does not update nSize) */
     void AddBlock(unsigned int nHeightIn, uint64_t nTimeIn) {
         if (nBlocks==0 || nHeightFirst > nHeightIn)
             nHeightFirst = nHeightIn;
         if (nBlocks==0 || nTimeFirst > nTimeIn)
             nTimeFirst = nTimeIn;
         nBlocks++;
         if (nHeightIn > nHeightLast)
             nHeightLast = nHeightIn;
         if (nTimeIn > nTimeLast)
             nTimeLast = nTimeIn;
     }
};

struct CDiskBlockPos
{
    int nFile;
    unsigned int nPos;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nFile));
        READWRITE(VARINT(nPos));
    }

    CDiskBlockPos() {
        SetNull();
    }

    CDiskBlockPos(int nFileIn, unsigned int nPosIn) {
        nFile = nFileIn;
        nPos = nPosIn;
    }

    friend bool operator==(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return (a.nFile == b.nFile && a.nPos == b.nPos);
    }

    friend bool operator!=(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return !(a == b);
    }

    void SetNull() { nFile = -1; nPos = 0; }
    bool IsNull() const { return (nFile == -1); }

    std::string ToString() const
    {
        return strprintf("CBlockDiskPos(nFile=%i, nPos=%i)", nFile, nPos);
    }

};

enum BlockStatus: uint32_t {
    //! Unused.
    BLOCK_VALID_UNKNOWN      =    0,

    //! Parsed, version ok, hash satisfies claimed PoW, 1 <= vtx count <= max, timestamp not in future
    BLOCK_VALID_HEADER       =    1,

    //! All parent headers found, difficulty matches, timestamp >= median previous, checkpoint. Implies all parents
    //! are also at least TREE.
    BLOCK_VALID_TREE         =    2,

    /**
     * Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids,
     * sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS. When all
     * parent blocks also have TRANSACTIONS, CBlockIndex::nChainTx will be set.
     */
    BLOCK_VALID_TRANSACTIONS =    3,

    //! Outputs do not overspend inputs, no double spends, coinbase output ok, no immature coinbase spends, BIP30.
    //! Implies all parents are also at least CHAIN.
    BLOCK_VALID_CHAIN        =    4,

    //! Scripts & signatures ok. Implies all parents are also at least SCRIPTS.
    BLOCK_VALID_SCRIPTS      =    5,

    //! All validity bits.
    BLOCK_VALID_MASK         =   BLOCK_VALID_HEADER | BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS |
                                 BLOCK_VALID_CHAIN | BLOCK_VALID_SCRIPTS,

    BLOCK_HAVE_DATA          =    8, //!< full block available in blk*.dat
    BLOCK_HAVE_UNDO          =   16, //!< undo data available in rev*.dat
    BLOCK_HAVE_MASK          =   BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO,

    BLOCK_FAILED_VALID       =   32, //!< stage after last reached validness failed
    BLOCK_FAILED_CHILD       =   64, //!< descends from failed block
    BLOCK_FAILED_MASK        =   BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,

    BLOCK_OPT_WITNESS       =   128, //!< block data in blk*.data was received with a witness-enforcing client
};

/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block. A blockindex may have multiple pprev pointing
 * to it, but at most one of them can be part of the currently active branch.
 */
class CBlockIndex
{
public:
    //! pointer to the hash of the block, if any. Memory is owned by this CBlockIndex
    const uint256* phashBlock;

    //! pointer to the index of the predecessor of this block
    CBlockIndex* pprev;

    //! pointer to the index of some further predecessor of this block
    CBlockIndex* pskip;

    //! height of the entry in the chain. The genesis block has height 0
    int nHeight;

    //! Which # file this block is stored in (blk?????.dat)
    int nFile;

    //! Byte offset within blk?????.dat where this block's data is stored
    unsigned int nDataPos;

    //! Byte offset within rev?????.dat where this block's undo data is stored
    unsigned int nUndoPos;

    //! (memory only) Total amount of work (expected number of hashes) in the chain up to and including this block
    arith_uint256 nChainWork;

    //! Number of transactions in this block.
    //! Note: in a potential headers-first mode, this number cannot be relied upon
    unsigned int nTx;

    //! (memory only) Number of transactions in the chain up to and including this block.
    //! This value will be non-zero only if and only if transactions for this block and all its parents are available.
    //! Change to 64-bit type when necessary; won't happen before 2030
    unsigned int nChainTx;

    //! Verification status of this block. See enum BlockStatus
    unsigned int nStatus;

    //! block header
    int nVersion;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    // Firo - ProgPow
    uint64_t nNonce64;
    uint256 mix_hash;

    // Firo - MTP
    int32_t nVersionMTP = 0x1000;
    uint256 mtpHashValue;
    // Reserved fields
    uint256 reserved[2];

    //! (memory only) Sequential id assigned to distinguish order in which blocks are received.
    int32_t nSequenceId;

    //! (memory only) Maximum nTime in the chain upto and including this block.
    unsigned int nTimeMax;

    //! Public coin values of mints in this block, ordered by serialized value of public coin
    //! Maps <denomination,id> to vector of public coins
    std::map<std::pair<int,int>, std::vector<CBigNum>> mintedPubCoins;

    //! Accumulator updates. Contains only changes made by mints in this block
    //! Maps <denomination, id> to <accumulator value (CBigNum), number of such mints in this block>
    std::map<std::pair<int,int>, std::pair<CBigNum,int>> accumulatorChanges;

    //! Values of coin serials spent in this block
	std::set<CBigNum> spentSerials;

/////////////////////// Sigma index entries. ////////////////////////////////////////////

    //! Public coin values of mints in this block, ordered by serialized value of public coin
    //! Maps <denomination,id> to vector of public coins
    std::map<std::pair<sigma::CoinDenomination, int>, std::vector<sigma::PublicCoin>> sigmaMintedPubCoins;
    //! Map id to <public coin, tag>
    std::map<int, std::vector<std::pair<lelantus::PublicCoin, uint256>>>  lelantusMintedPubCoins;

    std::unordered_map<GroupElement, lelantus::MintValueData> lelantusMintData;

    //! Map id to <hash of the set>
    std::map<int, std::vector<unsigned char>> anonymitySetHash;
    //! Map id to spark coin
    std::map<int, std::vector<spark::Coin>> sparkMintedCoins;
    //! Map id to <hash of the set>
    std::map<int, std::vector<unsigned char>> sparkSetHash;
    //! map spark coin S to tx hash, this is used when you run with -mobile
    std::unordered_map<GroupElement, std::pair<uint256, std::vector<unsigned char>>> sparkTxHashContext;

    //! Values of coin serials spent in this block
    sigma::spend_info_container sigmaSpentSerials;
    std::unordered_map<Scalar, int> lelantusSpentSerials;
    std::unordered_map<GroupElement, int> spentLTags;
    // linking tag hash mapped to tx hash
    std::unordered_map<uint256, uint256> ltagTxhash;

    //! list of disabling sporks active at this block height
    //! std::map {feature name} -> {block number when feature is re-enabled again, parameter}
    ActiveSporkMap activeDisablingSporks;

    //! List of spark names that were created or extended in this block. Map of spark name to <address, expiration block height, additional info>
    std::map<std::string, CSparkNameBlockIndexData> addedSparkNames;
    //! List of spark names that were removed in this block because of expiration
    std::map<std::string, CSparkNameBlockIndexData> removedSparkNames;

    void SetNull()
    {
        phashBlock = NULL;
        pprev = NULL;
        pskip = NULL;
        nHeight = 0;
        nFile = 0;
        nDataPos = 0;
        nUndoPos = 0;
        nChainWork = arith_uint256();
        nTx = 0;
        nChainTx = 0;
        nStatus = 0;
        nSequenceId = 0;
        nTimeMax = 0;

        nVersion       = 0;
        hashMerkleRoot = uint256();
        nTime          = 0;
        nBits          = 0;
        nNonce         = 0;

        // Firo - ProgPow
        nNonce64       = 0;
        mix_hash       = uint256();

        // Firo - MTP
        nVersionMTP = 0;
        mtpHashValue = reserved[0] = reserved[1] = uint256();

        sigmaMintedPubCoins.clear();
        lelantusMintedPubCoins.clear();
        lelantusMintData.clear();
        anonymitySetHash.clear();
        sparkMintedCoins.clear();
        sparkSetHash.clear();
        spentLTags.clear();
        ltagTxhash.clear();
        sparkTxHashContext.clear();
        sigmaSpentSerials.clear();
        lelantusSpentSerials.clear();
        activeDisablingSporks.clear();
        addedSparkNames.clear();
        removedSparkNames.clear();
    }

    CBlockIndex()
    {
        SetNull();
    }

    CBlockIndex(const CBlockHeader& block)
    {
        SetNull();

        nVersion       = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nTime          = block.nTime;
        nBits          = block.nBits;
        nNonce         = block.nNonce;

        if (block.IsProgPow()) {
            nHeight    = block.nHeight;
            nNonce64   = block.nNonce64;
            mix_hash   = block.mix_hash;
        } else if (block.IsMTP()) {
                nVersionMTP = block.nVersionMTP;
                mtpHashValue = block.mtpHashValue;
                reserved[0] = block.reserved[0];
                reserved[1] = block.reserved[1];
        }
    }

    CDiskBlockPos GetBlockPos() const {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_DATA) {
            ret.nFile = nFile;
            ret.nPos  = nDataPos;
        }
        return ret;
    }

    CDiskBlockPos GetUndoPos() const {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_UNDO) {
            ret.nFile = nFile;
            ret.nPos  = nUndoPos;
        }
        return ret;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        if (pprev)
            block.hashPrevBlock = pprev->GetBlockHash();
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;

        if (block.IsProgPow()) {
            block.nHeight    = nHeight;
            block.nNonce64   = nNonce64;
            block.mix_hash   = mix_hash;
        } else {
            block.nNonce     = nNonce;
            // Firo - MTP
            if(block.IsMTP()){
                block.nVersionMTP = nVersionMTP;
                block.mtpHashValue = mtpHashValue;
                block.reserved[0] = reserved[0];
                block.reserved[1] = reserved[1];
            }
        }

        return block;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    uint256 GetBlockPoWHash() const
    {
        return GetBlockHeader().GetPoWHash(nHeight);
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    int64_t GetBlockTimeMax() const
    {
        return (int64_t)nTimeMax;
    }

    enum { nMedianTimeSpan=11 };

    int64_t GetMedianTimePast() const
    {
        int64_t pmedian[nMedianTimeSpan];
        int64_t* pbegin = &pmedian[nMedianTimeSpan];
        int64_t* pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->GetBlockTime();

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }

    std::string ToString() const
    {
        return strprintf("CBlockIndex(pprev=%p, nHeight=%d, merkle=%s, hashBlock=%s)",
            pprev, nHeight,
            hashMerkleRoot.ToString(),
            GetBlockHash().ToString());
    }

    //! Check whether this block index entry is valid up to the passed validity level.
    bool IsValid(enum BlockStatus nUpTo = BLOCK_VALID_TRANSACTIONS) const
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        return ((nStatus & BLOCK_VALID_MASK) >= nUpTo);
    }

    //! Raise the validity level of this block index entry.
    //! Returns true if the validity was changed.
    bool RaiseValidity(enum BlockStatus nUpTo)
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        if ((nStatus & BLOCK_VALID_MASK) < nUpTo) {
            nStatus = (nStatus & ~BLOCK_VALID_MASK) | nUpTo;
            return true;
        }
        return false;
    }

    //! Build the skiplist pointer for this entry.
    void BuildSkip();

    //! Efficiently find an ancestor of this block.
    CBlockIndex* GetAncestor(int height);
    const CBlockIndex* GetAncestor(int height) const;
};

arith_uint256 GetBlockProof(const CBlockIndex& block);
/** Return the time it would take to redo the work difference between from and to, assuming the current hashrate corresponds to the difficulty at tip, in seconds. */
int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params&);

/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex
{
public:
    uint256 hashPrev;
    int nDiskBlockVersion;

    CDiskBlockIndex() {
        hashPrev = uint256();
        // value doesn't really matter but we won't leave it uninitialized
        nDiskBlockVersion = 0;
    }

    explicit CDiskBlockIndex(const CBlockIndex* pindex) : CBlockIndex(*pindex) {
        hashPrev = (pprev ? pprev->GetBlockHash() : uint256());
        nDiskBlockVersion = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(VARINT(nVersion));

        READWRITE(VARINT(nHeight));
        READWRITE(VARINT(nStatus));
        READWRITE(VARINT(nTx));
        if (nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO))
            READWRITE(VARINT(nFile));
        if (nStatus & BLOCK_HAVE_DATA)
            READWRITE(VARINT(nDataPos));
        if (nStatus & BLOCK_HAVE_UNDO)
            READWRITE(VARINT(nUndoPos));

        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);

        const auto &params = Params().GetConsensus();

        if (nTime >= params.nPPSwitchTime) {
            READWRITE(nNonce64);
            READWRITE(mix_hash);
        } else {
            READWRITE(nNonce);
            // Zcoin - MTP
            if (nTime > ZC_GENESIS_BLOCK_TIME && nTime >= params.nMTPSwitchTime) {
                READWRITE(nVersionMTP);
                READWRITE(mtpHashValue);
                READWRITE(reserved[0]);
                READWRITE(reserved[1]);
            }
        }
        
        if (!(s.GetType() & SER_GETHASH) && nVersion >= ZC_ADVANCED_INDEX_VERSION) {
            READWRITE(mintedPubCoins);
		    READWRITE(accumulatorChanges);
            READWRITE(spentSerials);
	    }

        if (!(s.GetType() & SER_GETHASH) && nHeight >= params.nSigmaStartBlock) {
            READWRITE(sigmaMintedPubCoins);
            READWRITE(sigmaSpentSerials);
        }

        if (!(s.GetType() & SER_GETHASH)
                && nHeight >= params.nLelantusStartBlock
                && nVersion >= LELANTUS_PROTOCOL_ENABLEMENT_VERSION) {
            if(nVersion == LELANTUS_PROTOCOL_ENABLEMENT_VERSION) {
                std::map<int, std::vector<lelantus::PublicCoin>>  lelantusPubCoins;
                READWRITE(lelantusPubCoins);
                for(auto& itr : lelantusPubCoins) {
                    if(!itr.second.empty()) {
                        for(auto& coin : itr.second)
                        lelantusMintedPubCoins[itr.first].push_back(std::make_pair(coin,uint256()));
                    }
                }
            } else
                READWRITE(lelantusMintedPubCoins);
            if (GetBoolArg("-mobile", false)) {
                READWRITE(lelantusMintData);
            }

            READWRITE(lelantusSpentSerials);

            if (nHeight >= params.nLelantusFixesStartBlock)
                READWRITE(anonymitySetHash);
        }

        if (!(s.GetType() & SER_GETHASH)
            && nHeight >= params.nSparkStartBlock) {
            READWRITE(sparkMintedCoins);
            READWRITE(sparkSetHash);
            READWRITE(spentLTags);

            if (GetBoolArg("-mobile", false)) {
                READWRITE(sparkTxHashContext);
                READWRITE(ltagTxhash);
            }
        }


        if (!(s.GetType() & SER_GETHASH) && nHeight >= params.nEvoSporkStartBlock) {
            if (nHeight < params.nEvoSporkStopBlock &&
                // Workaround for late rollout of version 0.14.9.3 in which nEvoSporkStopBlock was extended
                // If version of a record for block is less than 140903 and nHeight is greater than previous value
                // of nEvoSporkStopBlock we don't read activeDisablingSpork from index database
                !(params.nEvoSporkStopBlockExtensionVersion != 0 &&
                    nVersion < params.nEvoSporkStopBlockExtensionVersion &&
                    nHeight >= params.nEvoSporkStopBlockPrevious &&
                    nHeight < params.nEvoSporkStopBlockPrevious + params.nEvoSporkStopBlockExtensionGracefulPeriod))

                READWRITE(activeDisablingSporks);
        }
        nDiskBlockVersion = nVersion;

        if (!(s.GetType() & SER_GETHASH) && nHeight >= params.nSparkNamesStartBlock) {
            READWRITE(addedSparkNames);
            READWRITE(removedSparkNames);
        }
    }

    uint256 GetBlockHash() const
    {
        CBlockHeader    block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrev;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;

        if (block.IsProgPow()) {
            block.nHeight    = nHeight;
            block.nNonce64   = nNonce64;
            block.mix_hash   = mix_hash;
        } else {
            block.nNonce     = nNonce;
            if (block.IsMTP()) {
                block.nVersionMTP = nVersionMTP;
                block.mtpHashValue = mtpHashValue;
                block.reserved[0] = reserved[0];
                block.reserved[1] = reserved[1];
            }
        }


        return block.GetHash();
    }

    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s)",
            GetBlockHash().ToString(),
            hashPrev.ToString());
        return str;
    }
};

/** An in-memory indexed chain of blocks. */
class CChain {
private:
    std::vector<CBlockIndex*> vChain;

public:
    /** Returns the index entry for the genesis block of this chain, or NULL if none. */
    CBlockIndex *Genesis() const {
        return vChain.size() > 0 ? vChain[0] : NULL;
    }

    /** Returns the index entry for the tip of this chain, or NULL if none. */
    CBlockIndex *Tip() const {
        return vChain.size() > 0 ? vChain[vChain.size() - 1] : NULL;
    }

    /** Returns the index entry at a particular height in this chain, or NULL if no such height exists. */
    CBlockIndex *operator[](int nHeight) const {
        if (nHeight < 0 || nHeight >= (int)vChain.size())
            return NULL;
        return vChain[nHeight];
    }

    /** Compare two chains efficiently. */
    friend bool operator==(const CChain &a, const CChain &b) {
        return a.vChain.size() == b.vChain.size() &&
               a.vChain[a.vChain.size() - 1] == b.vChain[b.vChain.size() - 1];
    }

    /** Efficiently check whether a block is present in this chain. */
    bool Contains(const CBlockIndex *pindex) const {
        return (*this)[pindex->nHeight] == pindex;
    }

    /** Find the successor of a block in this chain, or NULL if the given index is not found or is the tip. */
    CBlockIndex *Next(const CBlockIndex *pindex) const {
        if (Contains(pindex))
            return (*this)[pindex->nHeight + 1];
        else
            return NULL;
    }

    /** Return the maximal height in the chain. Is equal to chain.Tip() ? chain.Tip()->nHeight : -1. */
    int Height() const {
        return vChain.size() - 1;
    }

    /** Set/initialize a chain with a given tip. */
    void SetTip(CBlockIndex *pindex);

    /** Return a CBlockLocator that refers to a block in this chain (by default the tip). */
    CBlockLocator GetLocator(const CBlockIndex *pindex = NULL) const;

    /** Find the last common block between this chain and a block index entry. */
    const CBlockIndex *FindFork(const CBlockIndex *pindex) const;

    /** Find the earliest block with timestamp equal or greater than the given. */
    CBlockIndex* FindEarliestAtLeast(int64_t nTime) const;
};

#endif // BITCOIN_CHAIN_H
