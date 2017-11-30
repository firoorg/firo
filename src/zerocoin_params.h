#ifndef ZEROCOIN_PARAMS_H
#define ZEROCOIN_PARAMS_H

/** Dust Soft Limit, allowed with additional fee per output */
//static const int64_t DUST_SOFT_LIMIT = 100000; // 0.001 XZC
/** Dust Hard Limit, ignored as wallet inputs (mininput default) */
static const int64_t DUST_HARD_LIMIT = 1000;   // 0.00001 XZC mininput

// There were bugs before this block, don't do some checks on early blocks
#define ZC_CHECK_BUG_FIXED_AT_BLOCK         61168
// Do strict check on duplicate minted public coin value after this block
#define ZC_CHECK_DUPLICATE_MINT_AT_BLOCK    70000

// The mint id number to change to zerocoin v2
#define ZC_V2_SWITCH_ID_1 120
#define ZC_V2_SWITCH_ID_10 30
#define ZC_V2_SWITCH_ID_25 15
#define ZC_V2_SWITCH_ID_50 15
#define ZC_V2_SWITCH_ID_100 30

// Zerocoin V3 starting blocks (main network and testnet)
#define ZC_V3_STARTING_BLOCK                75000
#define ZC_V3_TESTNET_STARTING_BLOCK        10

// Zerocoin coin id used in v3
#define ZC_V3_SPEND_ID                      1000

// Version of index that introduced storing accumulators and coin serials
#define ZC_ADVANCED_INDEX_VERSION           130500

#endif
