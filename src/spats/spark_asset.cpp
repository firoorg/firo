//
// Created by Gevorg Voskanyan
//

#include <cassert>
#include <type_traits>

#include "../amount.h"

#include "spark_asset.hpp"

namespace spats {

static_assert( std::is_same_v< CAmount, std::int64_t >,
               "Mismatched type expectation, meaning the compute_new_spark_asset_fee() definition doesn't correspond to its declaration in the header file!" );

CAmount compute_new_spark_asset_fee( const std::string_view asset_symbol ) noexcept
{
   const auto length = asset_symbol.length();
   assert( length > 0 );
   switch ( length ) {
      case 1:
         return 1000 * COIN;
      case 2:
         return 100 * COIN;
      case 3:
      case 4:
      case 5:
         return 10 * COIN;
      default:
         assert( length >= 6 );
         return COIN;   // 1 coin of the base asset, i.e. FIRO
   }
}

}   // namespace spats