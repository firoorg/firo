//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_BASE_ASSET_HPP_INCLUDED
#define FIRO_SPATS_BASE_ASSET_HPP_INCLUDED

#include <string_view>

#include "../amount.h"

#include "spark_asset.hpp"

namespace spats {
namespace base {

constexpr asset_type_t asset_type{ 0 };

constexpr universal_asset_id_t universal_id{ asset_type, identifier_t{ 0 } };

static_assert( is_fungible_asset_type( asset_type ) );

constexpr auto asset_name = "Firo"sv;
constexpr auto asset_symbol = "FIRO"sv;
// TODO confirm the exact description text
constexpr auto asset_description = "Digital currency that aims to spark a privacy revolution with its innovative features and research - base asset/currency of spats"sv;

// Function instead of variable, to avoid static initialization order issues
inline const AssetNaming &naming()
{
   static const AssetNaming n{ std::string( asset_name ), std::string( asset_symbol ), std::string( asset_description ) };
   return n;
}

const auto metadata = ""sv;

// 'initial' meaning at the time of the first public release/deployment of spats-enabled Firo tools
constexpr auto initial_admin_public_address = "<TODO find out>"sv;

constexpr unsigned precision = 8;
constexpr supply_amount_t initial_supply{ MAX_MONEY, precision };
static_assert( initial_supply.unpack() == std::pair< std::uint64_t, std::uint64_t >( 21'000'000, 0 ) );

constexpr bool resupplyable = false;

}   // namespace base
}   // namespace spats

#endif   // FIRO_SPATS_BASE_ASSET_HPP_INCLUDED
