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
#include <deque>

#include "../uint256.h"
#include "../utils/empty_class.hpp"
#include "../utils/lock_proof.hpp"

#include "spark_asset.hpp"
#include "actions.hpp"

namespace spats {

class Registry {
public:
   using block_hash_t = uint256;

   Registry();

   void validate( const Action &a, int block_height ) const;
   void validate( const ActionSequence &actions, int block_height ) const;

   // returns true if the registry state has been updated as a result of processing the given action
   bool process( const Action &a, int block_height, const std::optional< block_hash_t > &block_hash );

   // returns true if the registry state has been updated as a result of unprocessing the given action
   bool unprocess( const Action &a, int block_height );

   std::optional< asset_type_t > get_lowest_available_asset_type_for_new_fungible_asset() const noexcept;
   std::optional< asset_type_t > get_lowest_available_asset_type_for_new_nft_line() const noexcept;
   std::optional< identifier_t > get_lowest_available_identifier_for_nft_line( asset_type_t nft_line_asset_type ) const noexcept;

   std::vector< SparkAsset > get_assets_administered_by( const public_address_t &public_address ) const;
   std::vector< FungibleSparkAsset > get_fungible_assets_administered_by( const public_address_t &public_address ) const;
   std::vector< Nft > get_nfts_administered_by( const public_address_t &public_address ) const;

   struct LocatedAsset {
      std::optional< block_hash_t > block_hash;
      SparkAsset asset;
   };

   std::optional< LocatedAsset > get_asset( asset_type_t asset_type, std::optional< identifier_t > identifier ) const;

   void clear();

private:
   struct BlockAnnotation {
      std::optional< block_hash_t > block_hash;
#if 0   // not sure yet whether this will be needed here or not
      // if ever added, then add a block_height_before_modification to AssetModificationBlockBookkeeping too
      // as well as to BlockAnnotated constructor too, of course
      int block_height;
#endif
   };

   struct UnregisteredAsset {
      int block_height_unregistered_at;
      SparkAsset asset;
      // BlockAnnotation block_annotation;//TODO
   };

   template < typename T >
   struct BlockAnnotated : T, BlockAnnotation {
      BlockAnnotated( T t, std::optional< block_hash_t > blockhash )
         : T( std::move( t ) )
         , BlockAnnotation{ std::move( blockhash ) }
      {}
   };

   mutable std::shared_mutex mutex_;
   // TODO Performance: a more efficient storage type for both, using contiguous memory to the extent possible
   // All below data members, till the end of this class, are protected by mutex_
   std::unordered_map< asset_type_t, BlockAnnotated< FungibleSparkAsset > > fungible_assets_;
   std::unordered_map< asset_type_t, std::unordered_map< identifier_t, BlockAnnotated< NonfungibleSparkAsset > > > nft_lines_;
   std::list< UnregisteredAsset > unregistered_assets_;

   struct AssetModificationBlockBookkeeping {
      std::optional< block_hash_t > block_hash_before_modification;
      int block_height_modification_applied_at;
   };

   // The deque here is intended to be used like a stack, except during the very old blocks history cleanup, where elements may be removed from its front
   using asset_modification_blocks_history_t = std::deque< AssetModificationBlockBookkeeping >;
   std::map< universal_asset_id_t, asset_modification_blocks_history_t > modification_history_blocks_by_asset_;

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

   void add( const FungibleSparkAsset &a, std::optional< block_hash_t > block_hash, write_lock_proof wlp )
   {
      internal_validate( a, wlp );   // will throw if invalid
      internal_add( a, std::move( block_hash ), wlp );
   }

   void add( const NonfungibleSparkAsset &a, std::optional< block_hash_t > block_hash, write_lock_proof wlp )
   {
      internal_validate( a, wlp );   // will throw if invalid
      internal_add( a, std::move( block_hash ), wlp );
   }

   // addition (creation)
   bool process( const SparkAsset &a, int block_height, const std::optional< block_hash_t > &block_hash, write_lock_proof wlp );

   // unregistration
   void validate( const UnregisterAssetParameters &p, read_lock_proof ) const;
   bool process( const UnregisterAssetParameters &p, int block_height, const std::optional< block_hash_t > &block_hash, write_lock_proof );

   // modification
   void internal_validate( const FungibleAssetModification &m, read_lock_proof ) const;
   void internal_validate( const NonfungibleAssetModification &m, read_lock_proof ) const;
   void validate( const AssetModification &m, read_lock_proof ) const;
   bool process( const AssetModification &m,
                 int block_height,
                 const std::optional< block_hash_t > &block_hash,
                 write_lock_proof,
                 BlockAnnotation **out_block_annotation_ptr = nullptr );

   bool modify( const FungibleAssetModification &m,
                int block_height,
                std::optional< block_hash_t > block_hash,
                write_lock_proof wlp,
                BlockAnnotation **out_block_annotation_ptr = nullptr )
   {
      internal_validate( m, wlp );   // will throw if invalid
      return internal_modify( m, block_height, std::move( block_hash ), wlp, out_block_annotation_ptr );
   }

   bool modify( const NonfungibleAssetModification &m,
                int block_height,
                std::optional< block_hash_t > block_hash,
                write_lock_proof wlp,
                BlockAnnotation **out_block_annotation_ptr = nullptr )
   {
      internal_validate( m, wlp );   // will throw if invalid
      return internal_modify( m, block_height, std::move( block_hash ), wlp, out_block_annotation_ptr );
   }

   bool unprocess( const SparkAsset &a, int block_height, write_lock_proof wlp );
   bool unprocess( const UnregisterAssetParameters &p, int block_height, write_lock_proof );
   bool unprocess( const AssetModification &m, int block_height, write_lock_proof );

   void internal_add( const FungibleSparkAsset &a, std::optional< block_hash_t > block_hash, write_lock_proof );
   void internal_add( const NonfungibleSparkAsset &a, std::optional< block_hash_t > block_hash, write_lock_proof );
   bool internal_modify( const FungibleAssetModification &m,
                         int block_height,
                         std::optional< block_hash_t > block_hash,
                         write_lock_proof,
                         BlockAnnotation **out_block_annotation_ptr = nullptr );
   bool internal_modify( const NonfungibleAssetModification &m,
                         int block_height,
                         std::optional< block_hash_t > block_hash,
                         write_lock_proof,
                         BlockAnnotation **out_block_annotation_ptr = nullptr );

   void add_the_base_asset( write_lock_proof );
   bool has_nonfungible_asset( asset_type_t asset_type, identifier_t identifier, read_lock_proof ) const noexcept;

   std::vector< SparkAsset > get_assets_administered_by( const public_address_t &public_address, read_lock_proof ) const;
   std::vector< FungibleSparkAsset > get_fungible_assets_administered_by( const public_address_t &public_address, read_lock_proof ) const;
   std::vector< Nft > get_nfts_administered_by( const public_address_t &public_address, read_lock_proof ) const;

   std::optional< LocatedAsset > get_asset( asset_type_t asset_type, std::optional< identifier_t > identifier, read_lock_proof ) const;

   void restore_block_annotation_before_modification( universal_asset_id_t modified_asset_id,
                                                      BlockAnnotation &block_annotation,
                                                      int block_height_modified_at,
                                                      write_lock_proof wlp );
   void cleanup_old_blocks_bookkeeping( int block_height, write_lock_proof );
};

}   // namespace spats

#endif   // FIRO_SPATS_REGISTRY_HPP_INCLUDED
