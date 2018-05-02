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

// LWMA difficulty algorithm (simplified)
// Copyright (c) 2017-2018 Zawy
// https://github.com/zawy12/difficulty-algorithms/issues/3
unsigned int LwmaCalculateNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
   const int T = params.LWMAPowTargetSpacing;
   const int N = params.LWMAAveragingWindow;
   const int k = (N + 1) / 2 * 0.998 * T;
   const int height = pindexLast->nHeight + 1;
   
   LogPrintf("LWMA h=%i\n", height);
   LogPrintf("LWMA T=%i\n", T);
   LogPrintf("LWMA N=%i\n", N);
   LogPrintf("LWMA k=%i\n", k);

   if (height < N + 1)
   {
      LogPrintf("LWMA Blockheigh is smaller than N? pindexLast->nBits:%x\n", pindexLast->nBits);
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
      t += solvetime * j;  
      
      // divide sum_target  here to avoid potential overflow.
      arith_uint256 target;
      target.SetCompact(block->nBits);
      sum_target += target / (k * N * N);
   }

   // Keep t reasonable in case strange solvetimes occurred.
   if (t < N * k / 3) 
   { 
      LogPrintf("LWMA Keep t reasonable in case strange solvetimes occurred.\n");
      t = N * k / 3; 
   }

   const arith_uint256 pow_limit = UintToArith256(params.powLimit);
   arith_uint256 next_target = t * sum_target;

   if (next_target > pow_limit) 
   { 
      next_target = pow_limit; 
      LogPrintf("LWMA next_target > pow_limit:%h\n", next_target.GetCompact());
   }

   return next_target.GetCompact();
}

// zcoin GetNextWorkRequired
unsigned int GetNextWorkRequired(const CBlockIndex *pindexLast, const CBlockHeader *pblock, const Consensus::Params &params) {
   
   // Zawy's LWMA.
   unsigned int next_target = LwmaCalculateNextWorkRequired(pindexLast, params);
   
   LogPrintf("LWMA Blockheight: %u \t\tTimestamp:%i \t\tcurrent nBit: %x next_target: %x \n",pindexLast->nHeight, pindexLast->GetBlockTime(), pindexLast->nBits, next_target);
   
   return next_target;
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
