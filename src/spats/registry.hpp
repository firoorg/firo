//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_REGISTRY_HPP_INCLUDED
#define FIRO_SPATS_REGISTRY_HPP_INCLUDED

#include "actions.hpp"

#include <unordered_map>
#include <optional>
#include <vector>

#include "spark_asset.hpp"

namespace spats {

class Registry {
public:
   Registry();

   void validate( const Action &a ) const;
   void validate( const ActionSequence &actions ) const;
   void process( Action &&a );
   //void process( ActionSequence &&actions );

   std::optional< asset_type_t > get_lowest_available_asset_type_for_new_fungible_asset() const noexcept;
   std::optional< asset_type_t > get_lowest_available_asset_type_for_new_nft_line() const noexcept;
   std::optional< identifier_t > get_lowest_available_identifier_for_nft_line( asset_type_t nft_line_asset_type ) const noexcept;

   std::vector< SparkAsset > get_assets_administered_by( const public_address_t &public_address ) const;
   std::vector< FungibleSparkAsset > get_fungible_assets_administered_by( const public_address_t &public_address ) const;
   std::vector< Nft > get_nfts_administered_by( const public_address_t &public_address ) const;

   void clear();

private:
   // TODO MT safety
   // TODO Performance: a more efficient storage type for both, using contiguous memory to the extent possible
   std::unordered_map< asset_type_t, FungibleSparkAsset > fungible_assets_;
   std::unordered_map< asset_type_t, std::unordered_map< identifier_t, NonfungibleSparkAsset > > nft_lines_;

   Registry( const Registry & ) = default;
   Registry( Registry && ) = default;
   Registry &operator=( const Registry & ) = default;
   Registry &operator=( Registry && ) = default;

   void validate_addition( const FungibleSparkAsset &a );
   void validate_addition( const NonfungibleSparkAsset &a );
   void validate_addition( const SparkAssetBase &a );

   void add( FungibleSparkAsset &&a )
   {
      validate_addition( a );
      internal_add( std::move( a ) );
   }

   void add( NonfungibleSparkAsset &&a )
   {
      validate_addition( a );
      internal_add( std::move( a ) );
   }

   void add( SparkAsset &&a )
   {
      std::visit( [ this ]( auto &&x ) { add( std::move( x ) ); }, a );
   }

   void validate_unregister( const UnregisterAssetParameters &p );

   void unregister( const UnregisterAssetParameters &p );

   void internal_add( FungibleSparkAsset &&a );
   void internal_add( NonfungibleSparkAsset &&a );
   void add_the_base_asset();
   bool has_nonfungible_asset( asset_type_t asset_type, identifier_t identifier ) const noexcept;
};

}   // namespace spats

#endif   // FIRO_SPATS_REGISTRY_HPP_INCLUDED
