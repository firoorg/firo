#ifndef __ZCOIN_MTPSTATE_H
#define __ZCOIN_MTPSTATE_H

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

    // starting MTP block number. Zero if transition hasn't happened yet
    int nFirstMTPBlock;

public:
    MTPState() : nFirstMTPBlock(0) {}

    // Get shared instance of MTPState
    static MTPState *GetMTPState() { return sharedMTPState; }

    // Methods to query MTP state
    bool IsMTP() const { return nFirstMTPBlock > 0; }
    int GetFirstMTPBlockNumber() const { return nFirstMTPBlock; }

    // Update last block
    void SetLastBlock(CBlockIndex *lastBlockIndex, const Consensus::Params &params);

    // Initialize from existing chain
    void InitializeFromChain(CChain *chain, const Consensus::Params &params);
};

#endif