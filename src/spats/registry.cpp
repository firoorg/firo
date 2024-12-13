//
// Created by Gevorg Voskanyan
//

#include <boost/algorithm/string/predicate.hpp>

#include "base_asset.hpp"
#include "registry.hpp"

namespace spats {

registry::registry()
{
   add_the_base_asset();
}

void registry::add_the_base_asset()
{
   internal_add( fungible_spark_asset{
     base::asset_type, base::naming, std::string( base::metadata ), std::string( base::initial_admin_public_address ), base::initial_supply, base::resuppliable } );
}

bool registry::has_nonfungible_asset( asset_type_t asset_type, identifier_t identifier ) const noexcept
{
   assert( !is_fungible_asset_type( asset_type ) );
   const auto it = nft_lines_.find( asset_type );
   return it != nft_lines_.end() && it->second.contains( identifier );
}

std::optional< asset_type_t > registry::get_lowest_available_asset_type_for_new_fungible_asset() const noexcept
{
   // TODO Performance: retrieve from an interval_set maintained along
   for ( asset_type_t a{ 0 }; a <= max_allowed_asset_type_value; a = next_in_kind( a ) ) {
      assert( is_fungible_asset_type( a ) );
      if ( !fungible_assets_.contains( a ) ) {
         assert( a != base::asset_type && "The base asset type value should always be unavailable for a new asset to be added" );
         return a;
      }
   }
   return {};
}

std::optional< asset_type_t > registry::get_lowest_available_asset_type_for_new_nft_line() const noexcept
{
   // TODO Performance: retrieve from an interval_set maintained along
   for ( asset_type_t a{ 1 }; a <= max_allowed_asset_type_value; a = next_in_kind( a ) ) {
      assert( !is_fungible_asset_type( a ) );
      if ( !nft_lines_.contains( a ) )
         return a;
   }
   return {};
}

std::optional< identifier_t > registry::get_lowest_available_identifier_for_nft_line( const asset_type_t nft_line_asset_type ) const noexcept
{
   // TODO Performance: retrieve from an interval_set maintained along
   assert( !is_fungible_asset_type( nft_line_asset_type ) );
   assert( nft_line_asset_type <= max_allowed_asset_type_value );
   if ( nft_line_asset_type > max_allowed_asset_type_value )
      return {};

   if ( const auto it = nft_lines_.find( nft_line_asset_type ); it != nft_lines_.end() ) {
      for ( identifier_t i{ 0 }; i <= max_allowed_identifier_value; ++i )
         if ( !it->second.contains( i ) )
            return i;
      return {};
   }

   return identifier_t{ 0 };   // That NFT line doesn't exist yet, so the identifier can start from 0, which is available of course
}

std::vector< spark_asset > registry::get_assets_administered_by( const public_address_t &public_address ) const
{
   // TODO Performance: maintain a map of public addresses to asset_type values it administers
   // TODO Performance: perhaps also maintain a cache map of the final results, given that this function is expected to be called with the same public_address repeatedly
   std::vector< spark_asset > assets;
   std::ranges::move( get_fungible_assets_administered_by( public_address ), std::back_inserter( assets ) );
   std::ranges::move( get_nfts_administered_by( public_address ), std::back_inserter( assets ) );
   return assets;
}

std::vector< fungible_spark_asset > registry::get_fungible_assets_administered_by( const public_address_t &public_address ) const
{
   // TODO Performance: maintain a map of public addresses to asset_type values it administers
   // TODO Performance: perhaps also maintain a cache map of the final results, given that this function is expected to be called with the same public_address repeatedly
   std::vector< fungible_spark_asset > assets;
   for ( const auto &[ x, a ] : fungible_assets_ )
      if ( a.admin_public_address() == public_address )
         assets.emplace_back( a );
   return assets;
}

std::vector< nft > registry::get_nfts_administered_by( const public_address_t &public_address ) const
{
   // TODO Performance: maintain a map of public addresses to asset_type values it administers
   // TODO Performance: perhaps also maintain a cache map of the final results, given that this function is expected to be called with the same public_address repeatedly
   std::vector< nft > assets;
   for ( const auto &[ x, nft_line ] : nft_lines_ )
      if ( !nft_line.empty() && nft_line.begin()->second.admin_public_address() == public_address )
         for ( const auto &[ i, a ] : nft_line ) {
            assert( a.admin_public_address() == public_address && "all NTFs of the same line must have the same admin" );
            assets.emplace_back( a );
         }
   return assets;
}

void registry::validate_addition( const fungible_spark_asset &a )
{
   const spark_asset_base &b = a;
   validate_addition( b );
   assert( is_fungible_asset_type( a.asset_type() ) );
   if ( fungible_assets_.contains( a.asset_type() ) )
      throw std::domain_error( "Fungible asset with given asset type already exists." );   // TODO format context info into all throw statements wherever needed
}

void registry::validate_addition( const nonfungible_spark_asset &a )
{
   const spark_asset_base &b = a;
   validate_addition( b );
   if ( has_nonfungible_asset( a.asset_type(), a.identifier() ) )
      throw std::domain_error( "NFT with given asset type and identifier already exists." );
   if ( const auto it = nft_lines_.find( a.asset_type() ); it != nft_lines_.end() && !it->second.empty() ) {
      // the addition is to an already existing and extant NFT line
      const auto &nft_line = it->second;
      if ( nft_line.begin()->second.admin_public_address() != a.admin_public_address() )
         throw std::domain_error(
           "All NFTs of the same line must be administered by the same address: can't add a new NFT to an existing line with different admin addresses between them." );
   }
}

void registry::validate_addition( const spark_asset_base &a )
{
   const auto &n = a.naming();
   if ( n.symbol.get() == base::asset_symbol )
      throw std::invalid_argument( "Not allowed to create a spark asset with a reserved symbol" );
   if ( boost::algorithm::iequals( n.name.get(), base::asset_name ) )
      throw std::invalid_argument( "Not allowed to create a spark asset with a reserved name" );
}

void registry::internal_add( fungible_spark_asset &&a )
{
   const auto asset_type = a.asset_type();
   assert( !fungible_assets_.contains( asset_type ) );
   fungible_assets_.emplace( asset_type, std::move( a ) );
   assert( fungible_assets_.contains( asset_type ) );
}

void registry::internal_add( nonfungible_spark_asset &&a )
{
   const auto asset_type = a.asset_type();
   const auto identifier = a.identifier();
   assert( !has_nonfungible_asset( asset_type, identifier ) );
   nft_lines_[ asset_type ].emplace( identifier, std::move( a ) );
   assert( has_nonfungible_asset( asset_type, identifier ) );
}

}   // namespace spats