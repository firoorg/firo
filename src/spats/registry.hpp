//
// Created by Gevorg Voskanyan
//

#ifndef SPATS_REGISTRY_HPP_INCLUDED
#define SPATS_REGISTRY_HPP_INCLUDED

#include <unordered_map>
#include <optional>
#include <vector>

#include "spark_asset.hpp"

namespace spats {

class registry {
public:
   registry();

   void add( fungible_spark_asset &&a )
   {
      validate_addition( a );
      internal_add( std::move( a ) );
   }

   void add( nonfungible_spark_asset &&a )
   {
      validate_addition( a );
      internal_add( std::move( a ) );
   }

   void add( spark_asset &&a )
   {
      std::visit( [ this ]( auto &&x ) { add( std::move( x ) ); }, a );
   }

   std::optional< asset_type_t > get_lowest_available_asset_type_for_new_fungible_asset() const noexcept;
   std::optional< asset_type_t > get_lowest_available_asset_type_for_new_nft_line() const noexcept;
   std::optional< identifier_t > get_lowest_available_identifier_for_nft_line( asset_type_t nft_line_asset_type ) const noexcept;

   std::vector< spark_asset > get_assets_administered_by( const public_address_t &public_address ) const;
   std::vector< fungible_spark_asset > get_fungible_assets_administered_by( const public_address_t &public_address ) const;
   std::vector< nft > get_nfts_administered_by( const public_address_t &public_address ) const;

   // TODO s11n

private:
   // TODO Performance: a more efficient storage type for both, using contiguous memory to the extent possible
   std::unordered_map< asset_type_t, fungible_spark_asset > fungible_assets_;
   std::unordered_map< asset_type_t, std::unordered_map< identifier_t, nonfungible_spark_asset > > nft_lines_;

   void validate_addition( const fungible_spark_asset &a );
   void validate_addition( const nonfungible_spark_asset &a );
   void validate_addition( const spark_asset_base &a );
   void internal_add( fungible_spark_asset &&a );
   void internal_add( nonfungible_spark_asset &&a );
   void add_the_base_asset();
   bool has_nonfungible_asset( asset_type_t asset_type, identifier_t identifier ) const noexcept;
};

}   // namespace spats

#endif   // SPATS_REGISTRY_HPP_INCLUDED
