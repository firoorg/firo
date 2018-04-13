// https://github.com/zawy12/difficulty-algorithms/issues/3
// LWMA difficulty algorithm
// Copyright (c) 2017-2018 Zawy
// MIT license http://www.opensource.org/licenses/mit-license.php.
// Tom Harding, Karbowanec, Masari, Bitcoin Gold, and Bitcoin Candy have contributed.
// https://github.com/zawy12/difficulty-algorithms/issues/3

#include <math.h> // pow
#include "miner.h"

const static int64_t LWMAStartingBlock     = 1;
const static int64_t LWMAAveragingWindow   = 70;      // N = 70
const static int64_t LWMAPowTargetTimespan = 30 * 60; // 30 minutes between retargets
const static int64_t LWMAPowTargetSpacing  = 2 * 60;  // 2 minute blocktime

class CBlockIndex;

class PoWDifficultyParameters
{
   // T = target_solvetime;
   // Base your N on your solvetime and coin size:
   //  N=45, 60, 70, 100, 140 for T=600, 240, 120, 90, 60 respectively.
   // Use N=1.25xN if your coin is one of the top 50.
   // Use N=2xN if your coin is one of top 10 coins. 

   // Block height at which Zawy's LWMA difficulty algorithm becomes active                          
   int m_ZawyLWMAHeight = LWMAStartingBlock; // Verticalcoin starts with this algo on first Block.

   
   // Params for Zawy's LWMA difficulty adjustment algorithm.
   
   // Base your N on your solvetime and coin size: N=45, 60, _70_, 100, 140 for T=600, 240, _120_, 90, 60 respectively.

   int64_t m_nAveragingWindow      = LWMAAveragingWindow; 
   int64_t m_nAjustedWeight        = 0;
   int64_t m_nPowTargetTimespan    = LWMAPowTargetTimespan;
   int64_t m_nPowTargetSpacing     = LWMAPowTargetSpacing;    
   int64_t m_AdjustmentMagicNumber = 500;
   double  m_Adjustment            = 0.9989;
   
   // k = (N+1)/2 * 0.9989^(500/N) * T
   int64_t CalcAdjustedHeight()
   {
      const double adjust = pow(m_Adjustment, m_AdjustmentMagicNumber / GetPowTargetSpacing());
      m_nAjustedWeight = adjust * ((GetAveragingWindow() + 1) / 2) * GetPowTargetSpacing();

      return m_nAjustedWeight;
   }

   int64_t AveragingWindowTimespan()      const { return GetAveragingWindow() * GetPowTargetSpacing(); }

public:
   PoWDifficultyParameters() { 
      CalcAdjustedHeight();
   }

   ~PoWDifficultyParameters() = default;

   int64_t GetAveragingWindow() const { return m_nAveragingWindow;   } // N
   int64_t GetAjustedWeight()   const { return m_nAjustedWeight;     } // k
   int64_t GetPowTargetSpacing()const { return m_nPowTargetSpacing;  } // T 
   int64_t GetTargetTimespan()  const { return m_nPowTargetTimespan; }


   unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params) const;
   unsigned int GetNextWorkRequired(      const CBlockIndex *pindexLast, const CBlockHeader *pblock, const Consensus::Params &params) const;
};