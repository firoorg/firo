#ifndef MAIN_ZEROCOIN_H
#define MAIN_ZEROCOIN_H

#include "amount.h"
#include "chain.h"
#include "coins.h"
#include "consensus/validation.h"
#include "libzerocoin/Zerocoin.h"
#include "zerocoin_params.h"

bool CheckZerocoinFoundersInputs(const CTransaction &tx, CValidationState &state, int nHeight, bool fTestNet);
bool CheckZerocoinTransaction(const CTransaction &tx,
	CValidationState &state,
	uint256 hashTx,
	bool isVerifyDB,
	int nHeight,
	bool isCheckWallet);

void DisconnectTipZC(CBlock &block, CBlockIndex *pindexDelete);
bool ConnectTipZC(CValidationState &state, const CChainParams &chainparams, CBlockIndex *pindexNew, const CBlock *pblock);
bool ReArrangeZcoinMint(CValidationState &state, const CChainParams &chainparams, CBlockIndex *pindexNew, const CBlock *pblock);

int ZerocoinGetNHeight(const CBlockHeader &block);

#endif

