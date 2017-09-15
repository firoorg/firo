#ifndef MAIN_ZEROCOIN_H
#define MAIN_ZEROCOIN_H

#include "amount.h"
#include "chain.h"
#include "coins.h"
#include "consensus/validation.h"
#include "libzerocoin/Zerocoin.h"

/** Dust Soft Limit, allowed with additional fee per output */
//static const int64_t DUST_SOFT_LIMIT = 100000; // 0.001 XZC
/** Dust Hard Limit, ignored as wallet inputs (mininput default) */
static const int64_t DUST_HARD_LIMIT = 1000;   // 0.00001 XZC mininput

bool CheckZerocoinFoundersInputs(const CTransaction &tx, CValidationState &state, int nHeight, bool fTestNet);
bool CheckZerocoinTransaction(const CTransaction &tx, CValidationState &state, uint256 hashTx, bool isVerifyDB,
								int nHeight, bool isCheckWallet);

void DisconnectTipZC(CBlock &block, CBlockIndex *pindexDelete);
bool ConnectTipZC(CValidationState &state, const CChainParams &chainparams, CBlockIndex *pindexNew, const CBlock *pblock);
bool ReArrangeZcoinMint(CValidationState &state, const CChainParams &chainparams, CBlockIndex *pindexNew, const CBlock *pblock);

int ZerocoinGetNHeight(const CBlockHeader &block);

#endif
