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
#include <boost/math/special_functions/round.hpp>

uint64_t PoWDifficultyParameters::CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params) const
{
   // LWMA difficulty algorithm
   // Background:  https://github.com/zawy12/difficulty-algorithms/issues/3
   // Copyright (c) 2017-2018 Zawy (pseudocode)
   // MIT license http://www.opensource.org/licenses/mit-license.php
   // Copyright (c) 2018 The Karbowanec developers (initial code)
   // Copyright (c) 2018 Haven Protocol (refinements)
   // Degnr8, Karbowanec, Masari, Bitcoin Gold, Bitcoin Candy, and Haven have contributed.

   // This algorithm is: next_difficulty = harmonic_mean(Difficulties) * T / LWMA(Solvetimes)
   // The harmonic_mean(Difficulties) = 1/average(Targets) so it is also:
   // next_target = avg(Targets) * LWMA(Solvetimes) / T.
   // Do not use "if solvetime < 1 then solvetime = 1" which allows a catastrophic exploit.
   // Do not sort timestamps.  "Solvetimes" and "LWMA" variables must allow negatives.
   // Do not use MTP as most recent block.  Do not use (POW)Limits, filtering, or tempering.
   // Do not forget to set N (aka DIFFICULTY_WINDOW in Cryptonote) to recommendation below.
   // Make sure cut and lag are not applied to the timestamps and cumulativeDifficulties.

   // The nodes' future time limit (FTL) aka CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT needs to
   // be reduced from 60*60*2 to 500 seconds to prevent timestamp manipulation from miners.  

          std::size_t N = GetAveragingWindow();
   
   const std::int64_t T = GetTargetTimespan();
   const std::int64_t height = pindexLast->nHeight + 1;
   // If new coin, just "give away" first 5 blocks at low difficulty
   if (n <= 5) { return  1; }

   // If height "n" is from 6 to N, then reset N to n-1.
   else if (n < N + 1) { N = n - 1; }

   // To get an average solvetime to within +/- ~0.1%, use an adjustment factor.
   // adjust=0.999 for 80 < N < 120(?)
   const double adjust = 0.998;  // for 45 < N < 80 
                                 // The divisor k normalizes the LWMA sum to a standard LWMA.
   const double k = N * (N + 1) / 2;

   int t = 0, j = 0;
   arith_uint256 sum_target;

   // Loop through N most recent blocks.
   for (int i = height - N; i < height; i++) {
      const CBlockIndex* block = pindexLast->GetAncestor(i);
      const CBlockIndex* block_Prev = block->GetAncestor(i - 1);
      int64_t solvetime = block->GetBlockTime() - block_Prev->GetBlockTime();

      j++;
      t += solvetime * j;  // Weighted solvetime sum.

                           // Target sum divided by a factor, (k N^2).
                           // The factor is a part of the final equation. However we divide sum_target here to avoid
                           // potential overflow.
      arith_uint256 target;
      target.SetCompact(block->nBits);
      sum_target += target / (k * N * N);

   }
   // Keep t reasonable in case strange solvetimes occurred.
   if (t < N * k / 3) {
      t = N * k / 3;
   }

   const arith_uint256 pow_limit = UintToArith256(params.powLimit);
   arith_uint256 next_target = T * sum_target;
   if (next_target > pow_limit) {
      next_target = pow_limit;
   }

   LogPrintf("CalculateNextWorkRequired::next_difficulty: %u\n", next_target);

   return next_target.GetLow64();
}

uint64_t PoWDifficultyParameters::GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params) const
{
   unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

   // Genesis block
   if (pindexLast == nullptr)
   {
      LogPrintf("PoWDifficultyParameters::GetNextWorkRequired::Genesis Block detected::nProofOfWorkLimit:%u\n", nProofOfWorkLimit);
      return nProofOfWorkLimit;
   }
   // Special difficulty rule for testnet:
   // If the new block's timestamp is more than 2* 10 minutes
   // then allow mining of a min-difficulty block.
   if (params.fPowAllowMinDifficultyBlocks)
   {
      if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + GetPowTargetSpacing() * 2)
      {
         LogPrintf("PoWDifficultyParameters::GetNextWorkRequired::Special difficulty rule for testnet:::nProofOfWorkLimit:%u\n", nProofOfWorkLimit);
         return nProofOfWorkLimit;
      }
   }

   // Find the first block in the averaging interval
   const CBlockIndex* pindexCheck = pindexLast;
   for (std::int64_t i = 0; pindexCheck && i < GetAveragingWindow(); i++) {
      pindexCheck = pindexCheck->pprev;
   }

   // Check we have enough blocks
   if (pindexCheck == nullptr)
   {
      LogPrintf("PoWDifficultyParameters::GetNextWorkRequired::Check we have enough blocks::nProofOfWorkLimit:%u\n", nProofOfWorkLimit);
      return nProofOfWorkLimit;
   }
   // Okay we are on a valid blockchain... 
   return CalculateNextWorkRequired(pindexLast, pindexCheck->GetMedianTimePast(), params);
}

// verticalcoin GetNextWorkRequired
unsigned int GetNextWorkRequired(const CBlockIndex *pindexLast, const CBlockHeader *pblock, const Consensus::Params &params) {
   assert(pindexLast != nullptr);

   PoWDifficultyParameters PoWDifficultyParameters;

   // Zawy's LWMA.
   return PoWDifficultyParameters.GetNextWorkRequired(pindexLast, pblock, params);
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params &params) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
   
    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
    {
       LogPrintf("CheckProofOfWork::Range check failed\n");
       return false;
    }
   
    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
    {
       LogPrintf("CheckProofOfWork::check of claimed amount failed\n");
       return false;
    }
    return true;
}

