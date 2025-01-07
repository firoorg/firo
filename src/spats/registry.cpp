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
      copy.process( a, block_height );
}

bool Registry::process( const Action &a, int block_height )
{
   std::unique_lock lock( mutex_ );
   write_lock_proof wlp{ *this, lock };
   const bool ret = std::visit( [ & ]( const auto &x ) { return process( x.get(), block_height, wlp ); }, a );

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
                                     base::naming,
                                     std::string( base::metadata ),
                                     std::string( base::initial_admin_public_address ),
                                     base::initial_supply,
                                     base::resuppliable },
                 wlp );
}

bool Registry::has_nonfungible_asset( asset_type_t asset_type, identifier_t identifier, read_lock_proof ) const noexcept
{
   assert( !is_fungible_asset_type( asset_type ) );
   const auto it = nft_lines_.find( asset_type );
   return it != nft_lines_.end() && it->second.contains( identifier );
}

bool Registry::process( const SparkAsset &a, [[maybe_unused]] int block_height, write_lock_proof wlp )
{
   std::visit( [ this, wlp ]( auto &&x ) { add( x, wlp ); }, a );
   return true;
}

void Registry::validate( const UnregisterAssetParameters &p, read_lock_proof ) const
{
   if ( p.asset_type == base::asset_type )
      throw std::domain_error( "The base asset cannot be unregistered!" );

   const public_address_t *admin_public_address;
   if ( is_fungible_asset_type( p.asset_type ) ) {
      if ( p.identifier && *p.identifier != identifier_t{ 0 } )
         throw std::invalid_argument( "No 'identifier' should be provided for identifying a fungible asset" );
      const auto it = fungible_assets_.find( p.asset_type );
      if ( it == fungible_assets_.end() )
         throw std::invalid_argument( "No such asset found to unregister" );
      admin_public_address = &it->second.admin_public_address();
   }
   else {
      const auto it = nft_lines_.find( p.asset_type );
      if ( it == nft_lines_.end() || it->second.empty() || p.identifier && !it->second.contains( *p.identifier ) )
         throw std::invalid_argument( "No such asset found to unregister" );
      admin_public_address = &it->second.begin()->second.admin_public_address();
      assert( !p.identifier || admin_public_address == &it->second.find( *p.identifier )->second.admin_public_address() );
   }

   if ( *admin_public_address != p.initiator_public_address )
      throw std::domain_error( "No permission to unregister the given asset" );
}

bool Registry::process( const UnregisterAssetParameters &p, int block_height, write_lock_proof wlp )
{
   validate( p, wlp );

   if ( is_fungible_asset_type( p.asset_type ) ) {
      const auto it = fungible_assets_.find( p.asset_type );
      if ( it != fungible_assets_.end() ) {
         if ( block_height >= 0 )
            unregistered_assets_.push_back( { block_height, std::move( it->second ) } );
         fungible_assets_.erase( it );
         return true;
      }
      return false;
   }

   const auto it = nft_lines_.find( p.asset_type );
   if ( it == nft_lines_.end() )
      return false;
   if ( p.identifier ) {
      const auto nft_it = it->second.find( *p.identifier );
      if ( nft_it == it->second.end() )
         return false;
      if ( block_height >= 0 )
         unregistered_assets_.push_back( { block_height, std::move( nft_it->second ) } );
      it->second.erase( nft_it );
      if ( it->second.empty() )
         nft_lines_.erase( it );
      return true;
   }

   if ( block_height >= 0 )
      for ( auto &[ t, a ] : it->second )
         unregistered_assets_.push_back( { block_height, std::move( a ) } );
   nft_lines_.erase( it );
   return true;
}

bool Registry::unprocess( const SparkAsset &a, [[maybe_unused]] int block_height, write_lock_proof wlp )
{
   const auto &b = get_base( a );
   return process( UnregisterAssetParameters{ b.asset_type(), get_identifier( a ), b.admin_public_address() }, -1, wlp );
}

bool Registry::unprocess( const UnregisterAssetParameters &p, int block_height, write_lock_proof wlp )
{
   const auto it = std::ranges::find_if( unregistered_assets_, [ & ]( const auto &x ) {
      return x.block_height_unregistered_at == block_height && get_base( x.asset ).asset_type() == p.asset_type && get_identifier( x.asset ) == p.identifier;
   } );
   if ( it != unregistered_assets_.end() ) {
      process( it->asset, -1, wlp );
      unregistered_assets_.erase( it );
      return true;
   }
   return false;
}

std::optional< asset_type_t > Registry::get_lowest_available_asset_type_for_new_fungible_asset() const noexcept
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

std::optional< asset_type_t > Registry::get_lowest_available_asset_type_for_new_nft_line() const noexcept
{
   // TODO Performance: retrieve from an interval_set maintained along
   for ( asset_type_t a{ 1 }; a <= max_allowed_asset_type_value; a = next_in_kind( a ) ) {
      assert( !is_fungible_asset_type( a ) );
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

   if ( const auto it = nft_lines_.find( nft_line_asset_type ); it != nft_lines_.end() ) {
      for ( identifier_t i{ 0 }; i <= max_allowed_identifier_value; ++i )
         if ( !it->second.contains( i ) )
            return i;
      return {};
   }

   return identifier_t{ 0 };   // That NFT line doesn't exist yet, so the identifier can start from 0, which is available of course
}

std::vector< SparkAsset > Registry::get_assets_administered_by( const public_address_t &public_address ) const
{
   // TODO Performance: maintain a map of public addresses to asset_type values it administers
   // TODO Performance: perhaps also maintain a cache map of the final results, given that this function is expected to be called with the same public_address repeatedly
   std::vector< SparkAsset > assets;
   std::ranges::move( get_fungible_assets_administered_by( public_address ), std::back_inserter( assets ) );
   std::ranges::move( get_nfts_administered_by( public_address ), std::back_inserter( assets ) );
   return assets;
}

std::vector< FungibleSparkAsset > Registry::get_fungible_assets_administered_by( const public_address_t &public_address ) const
{
   // TODO Performance: maintain a map of public addresses to asset_type values it administers
   // TODO Performance: perhaps also maintain a cache map of the final results, given that this function is expected to be called with the same public_address repeatedly
   std::vector< FungibleSparkAsset > assets;
   for ( const auto &[ x, a ] : fungible_assets_ )
      if ( a.admin_public_address() == public_address )
         assets.emplace_back( a );
   return assets;
}

std::vector< Nft > Registry::get_nfts_administered_by( const public_address_t &public_address ) const
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

void Registry::clear()
{
   std::shared_lock lock( mutex_ );
   *this = {};
}

Registry::Registry( const Registry &other )
   : fungible_assets_( other.fungible_assets_ )
   , nft_lines_( other.nft_lines_ )
{}

Registry::Registry( Registry &&other )
   : fungible_assets_( std::move( other.fungible_assets_ ) )
   , nft_lines_( std::move( other.nft_lines_ ) )
{}

Registry &Registry::operator=( const Registry &rhs )
{
   fungible_assets_ = rhs.fungible_assets_;
   nft_lines_ = rhs.nft_lines_;
   return *this;
}

Registry &Registry::operator=( Registry &&rhs )
{
   fungible_assets_ = std::move( rhs.fungible_assets_ );
   nft_lines_ = std::move( rhs.nft_lines_ );
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

void Registry::internal_add( const FungibleSparkAsset &a, write_lock_proof )
{
   const auto asset_type = a.asset_type();
   assert( !fungible_assets_.contains( asset_type ) );
   fungible_assets_.emplace( asset_type, std::move( a ) );
   assert( fungible_assets_.contains( asset_type ) );
}

void Registry::internal_add( const NonfungibleSparkAsset &a, write_lock_proof wlp )
{
   const auto asset_type = a.asset_type();
   const auto identifier = a.identifier();
   assert( !has_nonfungible_asset( asset_type, identifier, wlp ) );
   nft_lines_[ asset_type ].emplace( identifier, std::move( a ) );
   assert( has_nonfungible_asset( asset_type, identifier, wlp ) );
}

void Registry::cleanup_old_blocks_bookkeeping( int block_height, write_lock_proof )
{
   const int cleanup_threshold = 2000;
   if ( block_height >= cleanup_threshold ) {
      const int remove_earlier_than_block_number = block_height - cleanup_threshold;
      std::erase_if( unregistered_assets_, [ = ]( const auto &u ) { return u.block_height_unregistered_at < remove_earlier_than_block_number; } );
   }
}

}   // namespace spats
