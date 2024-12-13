//
// Created by Gevorg Voskanyan
//

#ifndef SPATS_BASE_ASSET_HPP_INCLUDED
#define SPATS_BASE_ASSET_HPP_INCLUDED

#include <string_view>

#include "spark_asset.hpp"

namespace spats {

using namespace std::literals;

namespace base {

constexpr asset_type_t asset_type{ 0 };

static_assert( is_fungible_asset_type( asset_type ) );

constexpr auto asset_name = "Firo"sv;
constexpr auto asset_symbol = "FIRO"sv;
// TODO confirm the exact description text
constexpr auto asset_description = "Digital currency that aims to spark a privacy revolution with its innovative features and research - base asset/currency of spats"sv;

const asset_naming naming{ std::string( asset_name ), std::string( asset_symbol ), std::string( asset_description ) };

const auto metadata = ""sv;

// For the two below, 'initial' meaning at the time of the first public release/deployment of spats-enabled Firo tools
constexpr auto initial_admin_public_address = "<TODO find out>"sv;
constexpr supply_amount_t initial_supply{ 100000000000 /*TODO find out the real number, of course*/, 8 };

constexpr bool resuppliable = true;

}   // namespace base
}   // namespace spats

#endif   // SPATS_BASE_ASSET_HPP_INCLUDED
