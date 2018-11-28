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
            LogPrintf("Switch to MTP happened at block height  %d\n", nFirstMTPBlock);
        }
    }
    lastSeenBlockIndex = lastBlockIndex;
}

void MTPState::Reset() {
    nFirstMTPBlock = 0;
    lastSeenBlockIndex = NULL;
}

int MTPState::GetFirstMTPBlockNumber(const Consensus::Params &params, const CBlockIndex *blockIndex) {
    if (!lastSeenBlockIndex || blockIndex->nHeight > lastSeenBlockIndex->nHeight) {
        // blockIndex is actually ahead of lastSeenBlockIndex
        if (nFirstMTPBlock > 0)
            return nFirstMTPBlock;

        if (blockIndex->nHeight == 0)
            return 0;

        // go back the block chain and get the first block with MTP
        int firstMTPBlock = 0;
        do {
           if (blockIndex->nTime >= params.nMTPSwitchTime)
               firstMTPBlock = blockIndex->nHeight;
           blockIndex = blockIndex->pprev;
        } while (blockIndex->nHeight > 0 && blockIndex != lastSeenBlockIndex);

        return firstMTPBlock;
    }
    else
        // return nFirstMTPBlock if blockIndex is past the point of MTP switch, else 0
        return blockIndex->nHeight >= nFirstMTPBlock ? nFirstMTPBlock : 0;
}

void MTPState::InitializeFromChain(CChain *chain, const Consensus::Params &params) {
    SetLastBlock(chain->Tip(), params);
}
