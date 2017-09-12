//
// Created by Ngo Hoang on 7/24/17.
//

#ifndef BTZC_DEFINITION_H
#define BTZC_DEFINITION_H

enum {
    // primary version
    BLOCK_VERSION_DEFAULT = (1 << 0),
    // modifiers
    BLOCK_VERSION_AUXPOW = (1 << 8),
    // bits allocated for chain ID
    BLOCK_VERSION_CHAIN_START = (1 << 16),
    BLOCK_VERSION_CHAIN_END = (1 << 30),
};
static const int64_t nStartRewardTime = 1475020800;

#endif //BTZC_DEFINITION_H



