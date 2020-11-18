#ifndef __FIRO_MTPSTATE_H
#define __FIRO_MTPSTATE_H

#include "chainparams.h"
#include "chain.h"

/**
 * MTP state is used for keeping track of whether transition to MTP has already happened and if it did 
 * what is the starting MTP block number
 */

// Protected by cs_main
class MTPState {
protected:
    static MTPState *sharedMTPState;

    // this is the block when MTP starts or 0 if we don't know the block number yet
    int nMTPStartBlock;
    // starting MTP block number. Zero if transition hasn't happened yet
    int nFirstMTPBlock;
    // last block index
    CBlockIndex *lastSeenBlockIndex;

public:
    MTPState() : nMTPStartBlock(0), nFirstMTPBlock(0), lastSeenBlockIndex(NULL) {}

    // Get shared instance of MTPState
    static MTPState *GetMTPState() { return sharedMTPState; }

    // Methods to query MTP state
    bool IsMTP() const { return nFirstMTPBlock > 0; }
    int GetFirstMTPBlockNumber() const { return nFirstMTPBlock; }

    // Get first MTP block number given the last block is blockIndex (which can be
    // either ahead or behind lastSeenBlockIndex)
    int GetFirstMTPBlockNumber(const Consensus::Params &params, const CBlockIndex *blockIndex);

    // Update last block
    void SetLastBlock(CBlockIndex *lastBlockIndex, const Consensus::Params &params);

    // Reset to initial state
    void Reset();

    // Initialize from existing chain
    void InitializeFromChain(CChain *chain, const Consensus::Params &params);

    // Set starting MTP block number if we know it
    void SetMTPStartBlock(int _nMTPStartBlock) { nMTPStartBlock = _nMTPStartBlock; }
};

#endif
