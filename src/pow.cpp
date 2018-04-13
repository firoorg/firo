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

static CBigNum bnProofOfWorkLimit(~arith_uint256(0) >> 8);

unsigned int PoWDifficultyParameters::CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params) const
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
   
   // we need a vector of timestamps
   std::vector<std::uint64_t> timestamps;

   // and a vector of Chainwork
   std::vector<unsigned int> cumulative_difficulties;

   for (auto i = 0; i < N; ++i)
   {
      const CBlockIndex* block = pindexLast->GetAncestor(i);
      timestamps.emplace_back(block->GetBlockTime());
      cumulative_difficulties.emplace_back(block->nChainWork);
   }

   const int64_t T = GetTargetTimespan();

   // N=45, 55, 70, 90, 120 for T=600, 240, 120, 90, and 60 seconds
   // This is optimized for small coin protection.  It's fast.
   // Largest coin for a given POW can safely double N.


   if (timestamps.size() > N) {
      timestamps.resize(N + 1);
      cumulative_difficulties.resize(N + 1);
   }

   std::size_t n = timestamps.size();
   assert(n == cumulative_difficulties.size());
   assert(n <= GetAveragingWindow());

   // If new coin, just "give away" first 5 blocks at low difficulty
   if (n <= 5) { return  1; }

   // If height "n" is from 6 to N, then reset N to n-1.
   else if (n < N + 1) { N = n - 1; }

   // To get an average solvetime to within +/- ~0.1%, use an adjustment factor.
   // adjust=0.999 for 80 < N < 120(?)
   const double adjust = 0.998;  // for 45 < N < 80 
                                 // The divisor k normalizes the LWMA sum to a standard LWMA.
   const double k = N * (N + 1) / 2;

   double LWMA(0), sum_inverse_D(0), harmonic_mean_D(0), nextDifficulty(0);
   uint64_t difficulty(0), next_difficulty(0);

   // Loop through N most recent blocks. N is most recently solved block.
   for (std::size_t i = 1; i <= N; i++) {
      auto solveTime = static_cast<int64_t>(timestamps[i]) - static_cast<int64_t>(timestamps[i - 1]);
      solveTime = std::min<int64_t>((T * 7), std::max<int64_t>(solveTime, (-7 * T)));
      difficulty = cumulative_difficulties[i] - cumulative_difficulties[i - 1];
      LWMA += solveTime * i / k;
      sum_inverse_D += 1 / static_cast<double>(difficulty);
   }
   harmonic_mean_D = N / sum_inverse_D;

   // Keep LWMA sane in case something unforeseen occurs.
   if (static_cast<int64_t>(boost::math::round(LWMA)) < T / 20)
      LWMA = static_cast<double>(T / 20);

   nextDifficulty = harmonic_mean_D * T / LWMA * adjust;

   // No limits should be employed, but this is correct way to employ a 20% symmetrical limit:
   // nextDifficulty=max(previous_Difficulty*0.8,min(previous_Difficulty/0.8, next_Difficulty)); 

   next_difficulty = static_cast<uint64_t>(nextDifficulty);

   return next_difficulty;
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
      if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + GetPowTargetSpacing() * 2)
         return nProofOfWorkLimit;
   }

   // Find the first block in the averaging interval
   const CBlockIndex* pindexFirst = pindexLast;
   for (int i = 0; pindexFirst && i < GetAveragingWindow(); i++) {
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
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;
    return true;
}
