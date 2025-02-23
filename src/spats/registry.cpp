//
// Created by Gevorg Voskanyan
//

#include <mutex>

#include <boost/algorithm/string/predicate.hpp>

#include "base_asset.hpp"
#include "registry.hpp"

namespace spats {

Registry::Registry()
{
   // Technically, locking isn't needed here because we are in the constructor, but we need to supply write_lock_proof regardless...
   // The cost isn't a big deal here, so this is fine.
   std::unique_lock lock( mutex_ );
   add_the_base_asset( { *this, lock } );
}

void Registry::validate( const Action &a, int block_height ) const
{
   std::shared_lock lock( mutex_ );
   std::visit( [ & ]( const auto &x ) { validate( x.get(), { *this, lock } ); }, a );
}

void Registry::validate( const ActionSequence &actions, int block_height ) const
{
   if ( actions.empty() )
      return;
   if ( actions.size() == 1 )
      return validate( actions.front(), block_height );

   // We have multiple actions to validate. In general, we cannot just validate the actions against the registry in isolation, because a prior action in a sequence may
   // affect the validity of a subsequent action in the sequence. So we need to validate the actions against the registry in the context of the entire sequence, by making
   // a copy of the registry and processing the actions on the copy, in sequence. All process() functions validate the action as their first item of business, so that
   // would take care of this correctly, though likely not with the best efficiency in terms of performance.
   std::shared_lock lock( mutex_ );
   auto copy = *this;
   lock.unlock();
   for ( const auto &a : actions )
      copy.process( a, block_height, {} );   // block hash isn't needed for validation, only actual storage
}

bool Registry::process( const Action &a, int block_height, const std::optional< block_hash_t > &block_hash )
{
   std::unique_lock lock( mutex_ );
   write_lock_proof wlp{ *this, lock };
   const bool ret = std::visit( [ & ]( const auto &x ) { return process( x.get(), block_height, block_hash, wlp ); }, a );

   if ( last_block_height_processed_ != block_height ) {
      last_block_height_processed_ = block_height;
      cleanup_old_blocks_bookkeeping( block_height, wlp );
   }

   return ret;
}

bool Registry::unprocess( const Action &a, int block_height )
{
   std::unique_lock lock( mutex_ );
   return std::visit( [ & ]( const auto &x ) { return unprocess( x.get(), block_height, { *this, lock } ); }, a );
}

void Registry::add_the_base_asset( write_lock_proof wlp )
{
   internal_add( FungibleSparkAsset{ base::asset_type,
                                     base::naming(),
                                     std::string( base::metadata ),
                                     std::string( base::initial_admin_public_address ),
                                     base::initial_supply,
                                     base::resuppliable },
                 {},   // TODO or should this be the genesis block's hash?
                 wlp );
}

bool Registry::has_nonfungible_asset( asset_type_t asset_type, identifier_t identifier, read_lock_proof ) const noexcept
{
   assert( !is_fungible_asset_type( asset_type ) );
   const auto it = nft_lines_.find( asset_type );
   return it != nft_lines_.end() && it->second.contains( identifier );
}

bool Registry::process( const SparkAsset &a, int /*block_height*/, const std::optional< block_hash_t > &block_hash, write_lock_proof wlp )
{
   std::visit( [ this, &block_hash, wlp ]( auto &&x ) { add( x, block_hash, wlp ); }, a );
   return true;
}

void Registry::validate( const UnregisterAssetParameters &p, read_lock_proof ) const
{
   const public_address_t *admin_public_address;
   if ( is_fungible_asset_type( p.asset_type() ) ) {
      const auto it = fungible_assets_.find( p.asset_type() );
      if ( it == fungible_assets_.end() )
         throw std::invalid_argument( "No such asset found to unregister" );
      admin_public_address = &it->second.admin_public_address();
   }
   else {
      const auto it = nft_lines_.find( p.asset_type() );
      if ( it == nft_lines_.end() || it->second.empty() || p.identifier() && !it->second.contains( *p.identifier() ) )
         throw std::invalid_argument( "No such asset found to unregister" );
      admin_public_address = &it->second.begin()->second.admin_public_address();
      assert( !p.identifier() || *admin_public_address == it->second.find( *p.identifier() )->second.admin_public_address() );
   }

   if ( *admin_public_address != p.initiator_public_address() )
      throw std::domain_error( "No permission to unregister the given asset" );
}

bool Registry::process( const UnregisterAssetParameters &p, int block_height, const std::optional< block_hash_t > &block_hash, write_lock_proof wlp )
{
   validate( p, wlp );   // will throw if invalid

   if ( is_fungible_asset_type( p.asset_type() ) ) {
      const auto it = fungible_assets_.find( p.asset_type() );
      if ( it != fungible_assets_.end() ) {
         if ( block_height >= 0 )
            unregistered_assets_.emplace_back( block_height, std::move( it->second ) );
         fungible_assets_.erase( it );
         return true;
      }
      return false;
   }

   const auto it = nft_lines_.find( p.asset_type() );
   if ( it == nft_lines_.end() )
      return false;
   if ( p.identifier() ) {
      const auto nft_it = it->second.find( *p.identifier() );
      if ( nft_it == it->second.end() )
         return false;
      if ( block_height >= 0 )
         unregistered_assets_.emplace_back( block_height, std::move( nft_it->second ) );
      it->second.erase( nft_it );
      if ( it->second.empty() )
         nft_lines_.erase( it );
      return true;
   }

   if ( block_height >= 0 )
      for ( auto &[ t, a ] : it->second )
         unregistered_assets_.emplace_back( block_height, std::move( a ) );
   nft_lines_.erase( it );
   return true;
}

void Registry::validate( const AssetModification &m, read_lock_proof rlp ) const
{
   std::visit( [ & ]( const auto &x ) { internal_validate( x, rlp ); }, m );
}

void Registry::internal_validate( const FungibleAssetModification &m, read_lock_proof ) const
{
   const auto &existing_asset = m.old_asset();
   const auto asset_type = existing_asset.asset_type();
   assert( is_fungible_asset_type( asset_type ) );
   const auto it = fungible_assets_.find( asset_type );
   if ( it == fungible_assets_.end() )
      throw std::invalid_argument( "Asset to modify not found" );
   if ( it->second != existing_asset )
      throw std::domain_error( "Asset to modify has different data than what was expected" );
   if ( it->second.admin_public_address() != m.initiator_public_address() )
      throw std::domain_error( "No permission to modify the given asset" );
}

void Registry::internal_validate( const NonfungibleAssetModification &m, read_lock_proof ) const
{
   const auto &existing_asset = m.old_asset();
   const auto asset_type = existing_asset.asset_type();
   assert( !is_fungible_asset_type( asset_type ) );
   const auto it = nft_lines_.find( asset_type );
   if ( it != nft_lines_.end() ) {
      const auto nft_it = it->second.find( existing_asset.identifier() );
      if ( nft_it != it->second.end() ) {
         if ( nft_it->second != existing_asset )
            throw std::domain_error( "NFT to modify has different data than what was expected" );
         if ( nft_it->second.admin_public_address() != m.initiator_public_address() )
            throw std::domain_error( "No permission to modify the given NFT" );
         return;   // all ok with the modification if it reaches here
      }
   }
   throw std::invalid_argument( "No such NFT found to unregister" );
}

bool Registry::process(
  const AssetModification &m, int block_height, const std::optional< block_hash_t > &block_hash, write_lock_proof wlp, BlockAnnotation **out_block_annotation_ptr )
{
   return std::visit( [ &, wlp ]( const auto &x ) { return modify( x, block_height, block_hash, wlp, out_block_annotation_ptr ); }, m );
}

void Registry::validate( const MintParameters &p, read_lock_proof ) const
{
   assert( p.asset_type() <= max_allowed_asset_type_value );
   assert( p.asset_type() != base::asset_type );
   assert( is_fungible_asset_type( p.asset_type() ) );
   assert( p.new_supply() );
   const auto it = fungible_assets_.find( p.asset_type() );
   if ( it == fungible_assets_.end() )
      throw std::invalid_argument( "No such asset found to mint for" );
   const FungibleSparkAsset &a = it->second;
   if ( !a.resupplyable() )
      throw std::domain_error( "Cannot mint new supply for a non-resupplyable asset" );
   if ( p.new_supply().precision() != a.precision() )
      throw std::domain_error( "Cannot mint new supply with a different precision than the asset's" );
   if ( a.admin_public_address() != p.initiator_public_address() )
      throw std::domain_error( "No permission to mint for the given asset" );
   a.total_supply() + p.new_supply();   // may throw due to overflow
}

bool Registry::process( const MintParameters &p, int /*block_height*/, const std::optional< block_hash_t > & /*block_hash*/, write_lock_proof wlp )
{
   validate( p, wlp );   // will throw if invalid
   const auto it = fungible_assets_.find( p.asset_type() );
   assert( it != fungible_assets_.end() );
   it->second.asset().add_new_supply( p.new_supply() );
   return true;
}

bool Registry::unprocess( const SparkAsset &a, [[maybe_unused]] int block_height, write_lock_proof wlp )
{
   const auto &b = get_base( a );
   return process( UnregisterAssetParameters{ b.asset_type(), get_identifier( a ), b.admin_public_address() }, -1, {}, wlp );
}

bool Registry::unprocess( const UnregisterAssetParameters &p, int block_height, write_lock_proof wlp )
{
   const auto unregistered_identifier_match = []( const std::optional< identifier_t > asset_identifier,
                                                  const std::optional< identifier_t > unregister_action_identifier ) {
      return asset_identifier == unregister_action_identifier || !unregister_action_identifier;
   };

   bool any_changes = false;
   auto it = unregistered_assets_.begin();
   while ( it = std::find_if( it,
                              unregistered_assets_.end(),
                              [ & ]( const auto &x ) {
                                 return x.block_height_unregistered_at == block_height && get_base( x.asset ).asset_type() == p.asset_type() &&
                                        unregistered_identifier_match( get_identifier( x.asset ), p.identifier() );
                              } ),
           it != unregistered_assets_.end() ) {
      process( it->asset, -1, it->block_annotation.block_hash, wlp );
      it = unregistered_assets_.erase( it );
      any_changes = true;
   }
   return any_changes;
}

bool Registry::unprocess( const AssetModification &m, int block_height, write_lock_proof wlp )
{
   if ( !has_any_modifications( m ) )
      return false;
   assert( block_height >= 0 );
   const auto &b = get_base( m );
   BlockAnnotation *block_annotation = nullptr;
   // just applying the modification in reverse
   [[maybe_unused]] const bool modified_back =
     process( make_asset_modification( get_new_asset( m ), get_old_asset( m ), b.initiator_public_address() ), -1, {}, wlp, &block_annotation );
   assert( modified_back );
   assert( block_annotation );
   // and restoring the block hash
   restore_block_annotation_before_modification( { b.asset_type(), get_identifier( get_old_asset( m ) ).value_or( identifier_t{} ) },
                                                 *block_annotation,
                                                 block_height,
                                                 wlp );
   return true;
}

bool Registry::unprocess( const MintParameters &p, int /*block_height*/, write_lock_proof )
{
   const auto it = fungible_assets_.find( p.asset_type() );
   assert( it != fungible_assets_.end() );
   it->second.asset().remove_supply( p.new_supply() );
   return true;
}

std::optional< asset_type_t > Registry::get_lowest_available_asset_type_for_new_fungible_asset() const noexcept
{
   // TODO Performance: retrieve from an interval_set maintained along
   for ( asset_type_t a{ 0 }; a <= max_allowed_asset_type_value; a = next_in_kind( a ) ) {
      assert( is_fungible_asset_type( a ) );
      std::shared_lock lock( mutex_ );
      if ( !fungible_assets_.contains( a ) ) {
         assert( a != base::asset_type && "The base asset type value should always be unavailable for a new asset to be added" );
         return a;
      }
   }
   return {};
}

std::optional< asset_type_t > Registry::get_lowest_available_asset_type_for_new_nft_line() const noexcept
{
   // TODO Performance: retrieve from an interval_set maintained along
   for ( asset_type_t a{ 1 }; a <= max_allowed_asset_type_value; a = next_in_kind( a ) ) {
      assert( !is_fungible_asset_type( a ) );
      std::shared_lock lock( mutex_ );
      if ( !nft_lines_.contains( a ) )
         return a;
   }
   return {};
}

std::optional< identifier_t > Registry::get_lowest_available_identifier_for_nft_line( const asset_type_t nft_line_asset_type ) const noexcept
{
   // TODO Performance: retrieve from an interval_set maintained along
   assert( !is_fungible_asset_type( nft_line_asset_type ) );
   assert( nft_line_asset_type <= max_allowed_asset_type_value );
   if ( nft_line_asset_type > max_allowed_asset_type_value )
      return {};

   std::shared_lock lock( mutex_ );
   if ( const auto it = nft_lines_.find( nft_line_asset_type ); it != nft_lines_.end() ) {
      for ( identifier_t i{ 0 }; i <= max_allowed_identifier_value; ++i )
         if ( !it->second.contains( i ) )
            return i;
      return {};
   }

   return identifier_t{ 0 };   // That NFT line doesn't exist yet, so the identifier can start from 0, which is available of course
}

std::vector< SparkAsset > Registry::get_assets_administered_by( const public_address_t &public_address, read_lock_proof rlp ) const
{
   // TODO Performance: maintain a map of public addresses to asset_type values it administers
   // TODO Performance: perhaps also maintain a cache map of the final results, given that this function is expected to be called with the same public_address repeatedly
   std::vector< SparkAsset > assets;
   std::ranges::move( get_fungible_assets_administered_by( public_address, rlp ), std::back_inserter( assets ) );
   std::ranges::move( get_nfts_administered_by( public_address, rlp ), std::back_inserter( assets ) );
   return assets;
}

std::vector< SparkAsset > Registry::get_assets_administered_by( const public_address_t &public_address ) const
{
   std::shared_lock lock( mutex_ );
   return get_assets_administered_by( public_address, { *this, lock } );
}

std::vector< FungibleSparkAsset > Registry::get_fungible_assets_administered_by( const public_address_t &public_address, read_lock_proof ) const
{
   // TODO Performance: maintain a map of public addresses to asset_type values it administers
   // TODO Performance: perhaps also maintain a cache map of the final results, given that this function is expected to be called with the same public_address repeatedly
   std::vector< FungibleSparkAsset > assets;
   for ( const auto &[ x, a ] : fungible_assets_ )
      if ( a.admin_public_address() == public_address )
         assets.emplace_back( a );
   return assets;
}

std::vector< FungibleSparkAsset > Registry::get_fungible_assets_administered_by( const public_address_t &public_address ) const
{
   std::shared_lock lock( mutex_ );
   return get_fungible_assets_administered_by( public_address, { *this, lock } );
}

std::vector< Nft > Registry::get_nfts_administered_by( const public_address_t &public_address, read_lock_proof ) const
{
   // TODO Performance: maintain a map of public addresses to asset_type values it administers
   // TODO Performance: perhaps also maintain a cache map of the final results, given that this function is expected to be called with the same public_address repeatedly
   std::vector< Nft > assets;
   for ( const auto &[ x, nft_line ] : nft_lines_ )
      if ( !nft_line.empty() && nft_line.begin()->second.admin_public_address() == public_address )
         for ( const auto &[ i, a ] : nft_line ) {
            assert( a.admin_public_address() == public_address && "all NTFs of the same line must have the same admin" );
            assets.emplace_back( a );
         }
   return assets;
}

std::optional< Registry::LocatedAsset > Registry::get_asset( asset_type_t asset_type, std::optional< identifier_t > identifier, read_lock_proof rlp ) const
{
   if ( is_fungible_asset_type( asset_type ) ) {
      if ( identifier.value_or( identifier_t{} ) != identifier_t{} ) {
         assert( !"Identifier cannot be present for a fungible asset" );
         return {};
      }
      const auto it = fungible_assets_.find( asset_type );
      if ( it == fungible_assets_.end() )
         return {};
      return LocatedAsset{ it->second.block_hash, get_block_hash_before_last_modification( { asset_type, identifier_t{} }, rlp ), it->second };
   }

   if ( !identifier ) {
      assert( !"Identifier cannot be absent for an NFT" );
      return {};
   }
   const auto it = nft_lines_.find( asset_type );
   if ( it == nft_lines_.end() )
      return {};
   const auto nft_it = it->second.find( *identifier );
   if ( nft_it == it->second.end() )
      return {};
   return LocatedAsset{ nft_it->second.block_hash, get_block_hash_before_last_modification( { asset_type, *identifier }, rlp ), nft_it->second };
}

std::optional< Registry::block_hash_t > Registry::get_block_hash_before_last_modification( universal_asset_id_t asset_id, read_lock_proof ) const
{
   const auto it = modification_history_blocks_by_asset_.find( asset_id );
   if ( it == modification_history_blocks_by_asset_.end() )
      return {};
   const auto &bk = it->second;
   if ( bk.empty() ) [[unlikely]] {
      // a degenerate case, can only happen if .emplace_back() in internal_modify() failed with an exception
      return {};
   }
   return bk.back().block_hash_before_modification;
}

void Registry::restore_block_annotation_before_modification( const universal_asset_id_t modified_asset_id,
                                                             BlockAnnotation &block_annotation,
                                                             const int block_height_modified_at,
                                                             write_lock_proof )
{
   assert( block_height_modified_at >= 0 );
   const auto it = modification_history_blocks_by_asset_.find( modified_asset_id );
   assert( it != modification_history_blocks_by_asset_.end() );
   auto &bookkeepings = it->second;
   if ( bookkeepings.empty() ) [[unlikely]] {   // a degenerate case, can only happen if .emplace_back() in internal_modify() failed with an exception
      block_annotation.block_hash.reset();
      return;
   }
   auto &bk = bookkeepings.back();
   assert( bk.block_height_modification_applied_at == block_height_modified_at );
   block_annotation.block_hash = std::move( bk.block_hash_before_modification );
   bookkeepings.pop_back();
   if ( bookkeepings.empty() )
      modification_history_blocks_by_asset_.erase( it );
}

std::vector< Nft > Registry::get_nfts_administered_by( const public_address_t &public_address ) const
{
   std::shared_lock lock( mutex_ );
   return get_nfts_administered_by( public_address, { *this, lock } );
}

std::optional< Registry::LocatedAsset > Registry::get_asset( asset_type_t asset_type, std::optional< identifier_t > identifier ) const
{
   std::shared_lock lock( mutex_ );
   return get_asset( asset_type, identifier, { *this, lock } );
}

void Registry::clear()
{
   std::shared_lock lock( mutex_ );
   *this = {};
}

Registry::Registry( const Registry &other )
   : fungible_assets_( other.fungible_assets_ )
   , nft_lines_( other.nft_lines_ )
   , unregistered_assets_( other.unregistered_assets_ )
   , last_block_height_processed_( other.last_block_height_processed_ )
{}

Registry::Registry( Registry &&other )
   : fungible_assets_( std::move( other.fungible_assets_ ) )
   , nft_lines_( std::move( other.nft_lines_ ) )
   , unregistered_assets_( std::move( other.unregistered_assets_ ) )
   , last_block_height_processed_( other.last_block_height_processed_ )
{}

Registry &Registry::operator=( const Registry &rhs )
{
   fungible_assets_ = rhs.fungible_assets_;
   nft_lines_ = rhs.nft_lines_;
   unregistered_assets_ = rhs.unregistered_assets_;
   last_block_height_processed_ = rhs.last_block_height_processed_;
   return *this;
}

Registry &Registry::operator=( Registry &&rhs )
{
   fungible_assets_ = std::move( rhs.fungible_assets_ );
   nft_lines_ = std::move( rhs.nft_lines_ );
   unregistered_assets_ = std::move( rhs.unregistered_assets_ );
   last_block_height_processed_ = rhs.last_block_height_processed_;
   return *this;
}

void Registry::internal_validate( const FungibleSparkAsset &a, read_lock_proof ) const
{
   const SparkAssetBase &b = a;
   internal_validate( b );
   assert( is_fungible_asset_type( a.asset_type() ) );
   if ( fungible_assets_.contains( a.asset_type() ) )
      throw std::domain_error( "Fungible asset with given asset type already exists." );   // TODO format context info into all throw statements wherever needed
}

void Registry::internal_validate( const NonfungibleSparkAsset &a, read_lock_proof rlp ) const
{
   const SparkAssetBase &b = a;
   internal_validate( b );
   if ( has_nonfungible_asset( a.asset_type(), a.identifier(), rlp ) )
      throw std::domain_error( "NFT with given asset type and identifier already exists." );
   if ( const auto it = nft_lines_.find( a.asset_type() ); it != nft_lines_.end() && !it->second.empty() ) {
      // the addition is to an already existing and extant NFT line
      const auto &nft_line = it->second;
      if ( nft_line.begin()->second.admin_public_address() != a.admin_public_address() )
         throw std::domain_error(
           "All NFTs of the same line must be administered by the same address: can't add a new NFT to an existing line with different admin addresses between them." );
   }
}

void Registry::internal_validate( const SparkAssetBase &a )
{
   const auto &n = a.naming();
   if ( n.symbol.get() == base::asset_symbol )
      throw std::invalid_argument( "Not allowed to create a spark asset with a reserved symbol" );
   if ( boost::algorithm::iequals( n.name.get(), base::asset_name ) )
      throw std::invalid_argument( "Not allowed to create a spark asset with a reserved name" );
}

void Registry::validate( const SparkAsset &a, read_lock_proof rlp ) const
{
   std::visit( [ & ]( const auto &x ) { internal_validate( x, rlp ); }, a );
}

void Registry::internal_add( const FungibleSparkAsset &a, std::optional< block_hash_t > block_hash, write_lock_proof )
{
   const auto asset_type = a.asset_type();
   assert( !fungible_assets_.contains( asset_type ) );
   fungible_assets_.emplace( asset_type, BlockAnnotated( a, std::move( block_hash ) ) );
   assert( fungible_assets_.contains( asset_type ) );
}

void Registry::internal_add( const NonfungibleSparkAsset &a, std::optional< block_hash_t > block_hash, write_lock_proof wlp )
{
   const auto asset_type = a.asset_type();
   const auto identifier = a.identifier();
   assert( !has_nonfungible_asset( asset_type, identifier, wlp ) );
   nft_lines_[ asset_type ].emplace( identifier, BlockAnnotated( a, std::move( block_hash ) ) );
   assert( has_nonfungible_asset( asset_type, identifier, wlp ) );
}

bool Registry::internal_modify(
  const FungibleAssetModification &m, int block_height, std::optional< block_hash_t > block_hash, write_lock_proof, BlockAnnotation **out_block_annotation_ptr )
{
   assert( !out_block_annotation_ptr || !block_hash && block_height == -1 );
   if ( !m )
      return false;
   const auto asset_type = m.old_asset().asset_type();
   const auto it = fungible_assets_.find( asset_type );
   assert( it != fungible_assets_.end() );
   auto &a = it->second;
   assert( a == m.old_asset() );
   assert( a.admin_public_address() == m.initiator_public_address() );
   m.apply_on( a );
   assert( a == m.new_asset() );
   assert( a.admin_public_address() == m.initiator_public_address() );
   if ( block_hash ) {
      auto &effective_block_hash = it->second.block_hash;
      if ( block_height >= 0 )
         modification_history_blocks_by_asset_[ { asset_type, identifier_t{} } ].emplace_back( std::move( effective_block_hash ), block_height );
      effective_block_hash = std::move( block_hash );
   }
   else if ( out_block_annotation_ptr ) {
      assert( block_height == -1 );
      *out_block_annotation_ptr = &a;
   }
   return true;
}

bool Registry::internal_modify(
  const NonfungibleAssetModification &m, int block_height, std::optional< block_hash_t > block_hash, write_lock_proof, BlockAnnotation **out_block_annotation_ptr )
{
   assert( !out_block_annotation_ptr || !block_hash && block_height == -1 );
   if ( !m )
      return false;
   const auto asset_type = m.old_asset().asset_type();
   const auto it = nft_lines_.find( asset_type );
   assert( it != nft_lines_.end() );
   assert( it->second.contains( m.old_asset().identifier() ) );
   assert( it->second.begin()->second.admin_public_address() == m.initiator_public_address() );
   const auto identifier = m.old_asset().identifier();
   auto &a = it->second.at( identifier );
   assert( a == m.old_asset() );
   assert( a.admin_public_address() == m.initiator_public_address() );
   m.apply_on( a );
   assert( a == m.new_asset() );
   assert( a.admin_public_address() == m.initiator_public_address() );
   if ( block_hash ) {
      auto &effective_block_hash = a.block_hash;
      if ( block_height >= 0 )
         modification_history_blocks_by_asset_[ { asset_type, identifier } ].emplace_back( std::move( effective_block_hash ), block_height );
      effective_block_hash = std::move( block_hash );
   }
   else if ( out_block_annotation_ptr ) {
      assert( block_height == -1 );
      *out_block_annotation_ptr = &a;
   }
   return true;
}

void Registry::cleanup_old_blocks_bookkeeping( int block_height, write_lock_proof )
{
   const int cleanup_threshold = 2000;
   if ( block_height >= cleanup_threshold ) {
      const int remove_earlier_than_block_number = block_height - cleanup_threshold;

      std::erase_if( unregistered_assets_, [ = ]( const auto &u ) { return u.block_height_unregistered_at < remove_earlier_than_block_number; } );

      std::vector< universal_asset_id_t > degenerate_empty_bookkeepings;
      // spare the last one in an asset's modification bookkeepings, keep in perpetuity, for get_block_hash_before_last_modification()
      for ( auto &[ asset_id, bookkeepings ] : modification_history_blocks_by_asset_ ) {
         if ( bookkeepings.empty() ) [[unlikely]] {
            degenerate_empty_bookkeepings.push_back( asset_id );
            continue;
         }
         while ( bookkeepings.size() > 1 && bookkeepings.front().block_height_modification_applied_at < remove_earlier_than_block_number )
            bookkeepings.pop_front();
         assert( !bookkeepings.empty() );
      }
      // very unlikely for degenerate_empty_bookkeepings to ever be non-empty, but just in case ...
      for ( const auto asset_id : degenerate_empty_bookkeepings )
         modification_history_blocks_by_asset_.erase( asset_id );
   }
}

}   // namespace spats
