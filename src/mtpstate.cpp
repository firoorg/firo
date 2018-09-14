#include "mtpstate.h"

MTPState *MTPState::sharedMTPState = new MTPState();

void MTPState::SetLastBlock(CBlockIndex *lastBlockIndex, const Consensus::Params &params) {
    if (nFirstMTPBlock > 0) {
        // already has MTP block
        if (lastBlockIndex->nTime < params.nMTPSwitchTime)
            // roll back to pre-MTP block
            nFirstMTPBlock = 0;
    }
    else {
        // not at MTP yet
        if (lastBlockIndex->nHeight > 0 && lastBlockIndex->nTime >= params.nMTPSwitchTime) {
            // switched to MTP at some point. Find the first block with nTime greater than switch time
            CBlockIndex *block = lastBlockIndex;
            while (block->pprev->nHeight > 0 && block->pprev->nTime >= params.nMTPSwitchTime)
                block = block->pprev;

            nFirstMTPBlock = block->nHeight;
        }
    }
}

void MTPState::InitializeFromChain(CChain *chain, const Consensus::Params &params) {
    SetLastBlock(chain->Tip(), params);
}