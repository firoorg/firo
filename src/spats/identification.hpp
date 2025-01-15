//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_IDENTIFICATION_HPP_INCLUDED
#define FIRO_SPATS_IDENTIFICATION_HPP_INCLUDED

#include <cstdint>
#include <limits>
#include <utility>

#include "utils/enum.hpp"

namespace spats {

using asset_type_underlying_type = std::uint64_t;
using identifier_underlying_type = std::uint64_t;

enum class asset_type_t : asset_type_underlying_type {};
enum class identifier_t : identifier_underlying_type {};

constexpr bool is_fungible_asset_type( asset_type_t a ) noexcept
{
   return utils::to_underlying( a ) % 2 == 0;
}

constexpr asset_type_t next_in_kind( asset_type_t a ) noexcept
{
   return asset_type_t{ utils::to_underlying( a ) + 2 };
}

constexpr identifier_t &operator++( identifier_t &i ) noexcept
{
   return i = identifier_t{ utils::to_underlying( i ) + 1 };
}

constexpr asset_type_t max_allowed_asset_type_value{ std::numeric_limits< asset_type_underlying_type >::max() - 10 };   // leaving some breathing room...
constexpr identifier_t max_allowed_identifier_value{ std::numeric_limits< identifier_underlying_type >::max() - 10 };   // leaving some breathing room...

using universal_asset_id_t = std::pair< asset_type_t, identifier_t >;   // Can be used to identify both fungible & non-fungible assets
using nft_id_t = universal_asset_id_t;

}   // namespace spats

#endif   // FIRO_SPATS_IDENTIFICATION_HPP_INCLUDED
