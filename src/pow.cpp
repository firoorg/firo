// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"
#include "main.h"
#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "consensus/consensus.h"
#include "uint256.h"
#include <iostream>
#include "util.h"
#include "chainparams.h"
#include "libzerocoin/bitcoin_bignum/bignum.h"
#include <boost/math/special_functions/round.hpp>
#include "fixed.h"
#include <algorithm>    // std::max


static CBigNum bnProofOfWorkLimit(~arith_uint256(0) >> 8);

double GetDifficultyHelper(unsigned int nBits) {
   int nShift = (nBits >> 24) & 0xff;
   double dDiff = (double)0x0000ffff / (double)(nBits & 0x00ffffff);

   while (nShift < 29) {
      dDiff *= 256.0;
      nShift++;
   }
   while (nShift > 29) {
      dDiff /= 256.0;
      nShift--;
   }

   return dDiff;
}

static int64_t GetAdjustedWeight(const Consensus::Params& params)
{
   assert(params.LWMAPowTargetSpacing != 0);
   return 45 * pow(600 / params.LWMAPowTargetSpacing, 0.2*pow(600 / params.LWMAPowTargetSpacing, 0.3)) + 0.5;
}

// LWMA difficulty algorithm (simplified)
// Copyright (c) 2017-2018 Zawy
// MIT license http://www.opensource.org/licenses/mit-license.php
// See link below for other file changes required in Cryptonote clones
// https://github.com/zawy12/difficulty-algorithms/issues/3
// If you're a cryptonote coin, you must change in config file:
// CRYPTONOTE_FUTURE_TIME_LIMIT_V2 = 500 instead of 60*60*2
// and use "size_t N = DIFFICULTY_WINDOW_V2 - 1;"before using the following.
// Bitcoin clones reduce following 7200 to 500.
// mapKeyBirth[it->first] = it->second->GetBlockTime() - 7200; 
unsigned int LwmaCalculateNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
   const int T = params.LWMAPowTargetSpacing;
   const int N = params.LWMAAveragingWindow;
   const int k = GetAdjustedWeight(params);
   const int height = pindexLast->nHeight + 1;
   
   LogPrintf("h=%i", height);
   LogPrintf("T=%i", T);
   LogPrintf("N=%i", N);
   LogPrintf("k=%i", k);

   if (height < N + 1)
   {
      LogPrintf("Blockheigh is smaller than N? pindexLast->nBits:%x\n", pindexLast->nBits);
      return pindexLast->nBits;
   }

   assert(height > N);

   arith_uint256 sum_target;
   int t = 0, j = 0;

   // Loop through N most recent blocks.
   for (int i = height - N; i < height; i++) {
      const CBlockIndex* block = pindexLast->GetAncestor(i);
      const CBlockIndex* block_Prev = block->GetAncestor(i - 1);
      int64_t solvetime = block->GetBlockTime() - block_Prev->GetBlockTime();
      
      j++;
      t += solvetime * j;  // Weighted solvetime sum.

                           // Target sum divided by a factor, (k N^2).
                           // The factor is a part of the final equation. However we divide sum_target 
                           // here to avoid potential overflow.
      arith_uint256 target;
      target.SetCompact(block->nBits);
      sum_target += target / (k * N * N);
   }

   // Keep t reasonable in case strange solvetimes occurred.
   if (t < N * k / 3) { t = N * k / 3; }

   const arith_uint256 pow_limit = UintToArith256(params.powLimit);
   arith_uint256 next_target = t * sum_target;

   if (next_target > pow_limit) { next_target = pow_limit; }

   return next_target.GetCompact();
}

// zcoin GetNextWorkRequired
unsigned int GetNextWorkRequired(const CBlockIndex *pindexLast, const CBlockHeader *pblock, const Consensus::Params &params) {
   
   // Zawy's LWMA.
   double const nBits_OfNextBlock = LwmaCalculateNextWorkRequired(pindexLast, params);
   
   LogPrintf("Blockheight: %u \t\tTimestamp:%i \t\tnBits_OfNextBlock:%x\n",pindexLast->nHeight, pindexLast->GetBlockTime(), nBits_OfNextBlock);
   
   return nBits_OfNextBlock;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params &params) {
   bool fNegative;
   bool fOverflow;
   arith_uint256 bnTarget;

   bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
   // Check range
   if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
      return false;

   // Check proof of work matches claimed amount
   if (UintToArith256(hash) > bnTarget)
      return false;
   return true;
}
