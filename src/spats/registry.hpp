//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_REGISTRY_HPP_INCLUDED
#define FIRO_SPATS_REGISTRY_HPP_INCLUDED

#include <unordered_map>
#include <optional>
#include <vector>
#include <list>
#include <shared_mutex>

#include "../utils/lock_proof.hpp"

#include "spark_asset.hpp"
#include "actions.hpp"

namespace spats {

class Registry {
public:
   Registry();

   void validate( const Action &a, int block_height ) const;
   void validate( const ActionSequence &actions, int block_height ) const;

   // returns true if the registry state has been updated as a result of processing the given action
   bool process( const Action &a, int block_height );

   // returns true if the registry state has been updated as a result of unprocessing the given action
   bool unprocess( const Action &a, int block_height );

   std::optional< asset_type_t > get_lowest_available_asset_type_for_new_fungible_asset() const noexcept;
   std::optional< asset_type_t > get_lowest_available_asset_type_for_new_nft_line() const noexcept;
   std::optional< identifier_t > get_lowest_available_identifier_for_nft_line( asset_type_t nft_line_asset_type ) const noexcept;

   std::vector< SparkAsset > get_assets_administered_by( const public_address_t &public_address ) const;
   std::vector< FungibleSparkAsset > get_fungible_assets_administered_by( const public_address_t &public_address ) const;
   std::vector< Nft > get_nfts_administered_by( const public_address_t &public_address ) const;

   void clear();

private:
   struct UnregisterAsset {
      int block_height_unregistered_at;
      SparkAsset asset;
   };

   mutable std::shared_mutex mutex_;
   // TODO Performance: a more efficient storage type for both, using contiguous memory to the extent possible
   // All below data members are protected by mutex_
   std::unordered_map< asset_type_t, FungibleSparkAsset > fungible_assets_;
   std::unordered_map< asset_type_t, std::unordered_map< identifier_t, NonfungibleSparkAsset > > nft_lines_;
   std::list< UnregisterAsset > unregistered_assets_;
   int last_block_height_processed_ = -1;

   using read_lock_proof = utils::read_lock_proof< &Registry::mutex_ >;
   using write_lock_proof = utils::write_lock_proof< &Registry::mutex_ >;

   // ATTENTION: The callers of these copy/move operations must provide the proper locking themselves!
   Registry( const Registry & );
   Registry( Registry && );
   Registry &operator=( const Registry & );
   Registry &operator=( Registry &&rhs );

   // validating addition (creation)
   void internal_validate( const FungibleSparkAsset &a, read_lock_proof ) const;
   void internal_validate( const NonfungibleSparkAsset &a, read_lock_proof ) const;
   static void internal_validate( const SparkAssetBase &a );
   void validate( const SparkAsset &a, read_lock_proof rlp ) const;

   void add( const FungibleSparkAsset &a, write_lock_proof wlp )
   {
      internal_validate( a, wlp );
      internal_add( a, wlp );
   }

   void add( const NonfungibleSparkAsset &a, write_lock_proof wlp )
   {
      internal_validate( a, wlp );
      internal_add( a, wlp );
   }

   // addition (creation)
   bool process( const SparkAsset &a, int block_height, write_lock_proof wlp );

   void validate( const UnregisterAssetParameters &p, read_lock_proof ) const;

   bool process( const UnregisterAssetParameters &p, int block_height, write_lock_proof );

   bool unprocess( const SparkAsset &a, int block_height, write_lock_proof wlp );
   bool unprocess( const UnregisterAssetParameters &p, int block_height, write_lock_proof );

   void internal_add( const FungibleSparkAsset &a, write_lock_proof );
   void internal_add( const NonfungibleSparkAsset &a, write_lock_proof );

   void add_the_base_asset( write_lock_proof );
   bool has_nonfungible_asset( asset_type_t asset_type, identifier_t identifier, read_lock_proof ) const noexcept;

   void cleanup_old_blocks_bookkeeping( int block_height, write_lock_proof );
};

}   // namespace spats

#endif   // FIRO_SPATS_REGISTRY_HPP_INCLUDED
