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
#include "fixed.h"
#include "powdifficulty.h"

static CBigNum bnProofOfWorkLimit(~arith_uint256(0) >> 8);

// next_difficulty = harmonic_mean(difficulties) * target_solvetime / LWMA(solvetimes)
unsigned int PoWDifficultyParameters::CalculateNextWorkRequired_Old(const CBlockIndex* pindexLast, const Consensus::Params& params) const
{
   if (params.fPowNoRetargeting) {
      return pindexLast->nBits;
   }

   int T = GetPowTargetSpacing();
   const int N = GetAveragingWindow();
   const int k = GetAjustedWeight();
   const int height = pindexLast->nHeight + 1;

   const arith_uint256 pow_limit = UintToArith256(params.powLimit);
   
   assert(height > N);

   int t = 0, j = 0;

   // Loop through N most recent blocks.
   arith_uint256 sum_target;
   for (int i = height - N; i < height; i++) {
      const CBlockIndex* block = pindexLast->GetAncestor(i);
      const CBlockIndex* block_Prev = block->GetAncestor(i - 1);
      int64_t solvetime = block->GetBlockTime() - block_Prev->GetBlockTime();

      if (solvetime > 6 * T) { solvetime = 6 * T; }
      if (solvetime < -5 * T) { solvetime = -5 * T; }

      j++;
      t += solvetime * j;

      arith_uint256 target;
      target.SetCompact(block->nBits);
      sum_target += target / k;
   }

   // Keep t reasonable in case strange solvetimes occurred.
   if (t < N * k / 3) {
      t = N * k / 3;
   }
   
   arith_uint256 next_target = t * sum_target;
   if (next_target > pow_limit) {
      next_target = pow_limit;
   }

   return next_target.GetCompact();
}

unsigned int PoWDifficultyParameters::CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params) const
{
   // Limit adjustment step
   // Use medians to prevent time-warp attacks
   int64_t nActualTimespan = pindexLast->GetMedianTimePast() - nFirstBlockTime;
   LogPrint("pow", "  nActualTimespan = %d  before dampening\n", nActualTimespan);

   nActualTimespan = params.PoWDifficultyParameters.AveragingWindowTimespan() + (nActualTimespan - params.PoWDifficultyParameters.AveragingWindowTimespan()) / 4;
   LogPrint("pow", "  nActualTimespan = %d  before bounds\n", nActualTimespan);

   if (nActualTimespan < params.PoWDifficultyParameters.MinActualTimespan())
      nActualTimespan = params.PoWDifficultyParameters.MinActualTimespan();
   if (nActualTimespan > params.PoWDifficultyParameters.MaxActualTimespan())
      nActualTimespan = params.PoWDifficultyParameters.MaxActualTimespan();

   // Retarget
   const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
   arith_uint256 bnNew;
   arith_uint256 bnOld;
   bnNew.SetCompact(pindexLast->nBits);
   bnOld = bnNew;
   bnNew /= params.PoWDifficultyParameters.AveragingWindowTimespan();
   bnNew *= nActualTimespan;

   if (bnNew > bnPowLimit)
      bnNew = bnPowLimit;

   /// debug print
   LogPrint("pow", "GetNextWorkRequired RETARGET\n");
   LogPrint("pow", "params.AveragingWindowTimespan() = %d    nActualTimespan = %d\n", params.PoWDifficultyParameters.AveragingWindowTimespan(), nActualTimespan);
   LogPrint("pow", "Before: %08x  %s\n", pindexLast->nBits, bnOld.ToString());
   LogPrint("pow", "After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());

   return bnNew.GetCompact();
}

unsigned int PoWDifficultyParameters::GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params) const
{
   unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
   
   // Genesis block
   if (pindexLast == NULL)
      return nProofOfWorkLimit;

   // Special difficulty rule for testnet:
   // If the new block's timestamp is more than 2* 10 minutes
   // then allow mining of a min-difficulty block.
   if (params.fPowAllowMinDifficultyBlocks)
   {
      if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.PoWDifficultyParameters.GetPowTargetSpacing() * 2)
         return nProofOfWorkLimit;
   }

   // Find the first block in the averaging interval
   const CBlockIndex* pindexFirst = pindexLast;
   for (int i = 0; pindexFirst && i < params.PoWDifficultyParameters.GetAveragingWindow(); i++) {
      pindexFirst = pindexFirst->pprev;
   }

   // Check we have enough blocks
   if (pindexFirst == NULL)
      return nProofOfWorkLimit;

   // Okay we are on a valid blockchain... 
   return CalculateNextWorkRequired(pindexLast, pindexFirst->GetMedianTimePast(), params);
}

// verticalcoin GetNextWorkRequired
unsigned int GetNextWorkRequired(const CBlockIndex *pindexLast, const CBlockHeader *pblock, const Consensus::Params &params) {
   bool fTestNet = Params().NetworkIDString() == CBaseChainParams::TESTNET;
   
   assert(pindexLast != nullptr);

   // Zawy's LWMA.
   return params.PoWDifficultyParameters.GetNextWorkRequired(pindexLast, pblock, params);
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
