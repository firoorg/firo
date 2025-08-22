//
// Created by Gevorg Voskanyan
//

#include "../chain.h"

#include "actions.hpp"
#include "manager.hpp"

namespace spats {

void Manager::add_spats_actions( const Actions &actions, const int block_height, const std::optional< block_hash_t > &block_hash )
{
   if ( !actions.empty() )
      LogPrintf( "Adding %d spats actions with block height %d and hash %s\n", actions.size(), block_height, block_hash ? block_hash->ToString() : "<NULL>" );
   bool registry_updated = false;
   for ( const auto &a : actions )
      registry_updated = registry_.process( a, block_height, block_hash ) || registry_updated;   // may throw
   if ( registry_updated )
      notify_registry_changes( actions );
}

void Manager::add_block( const CBlockIndex &block )
{
   add_spats_actions( block.spats_actions, block.nHeight, block.phashBlock ? std::optional( *block.phashBlock ) : std::nullopt );
}

void Manager::remove_block( const CBlockIndex &block )
{
   bool registry_updated = false;
   for ( const auto &a : block.spats_actions )
      registry_updated = registry_.unprocess( a, block.nHeight ) || registry_updated;   // may throw
   if ( registry_updated )
      notify_registry_changes( block.spats_actions );
}

void Manager::reset()
{
   registry_.clear();
}

void Manager::add_updates_observer( UpdatesObserver &o )
{
   std::lock_guard lock( observers_mutex_ );
   if ( std::ranges::find( update_observers_, &o ) == update_observers_.end() )
      update_observers_.push_back( &o );
}

void Manager::remove_updates_observer( UpdatesObserver &o )
{
   std::lock_guard lock( observers_mutex_ );
   std::erase( update_observers_, &o );
}

void Manager::notify_registry_changes( const Actions &as_a_result_of_actions ) const
{
   // Called after processing or unprocessing all `as_a_result_of_actions` into the registry - SUCCESSFULLY! Won't be called if any action failed (IMPORTANT).
   UpdatesObserver::admin_addresses_set_t affected_asset_admin_addresses;
   UpdatesObserver::asset_ids_set_t affected_asset_ids;
   // TODO Performance: Actually, not all of these actions may have changed the registry. Some certainly did, but some perhaps didn't (i.e. [un]process() returned false).
   //                   Consider not adding affected admin address and asset id for such actions to the resulting sets. Although not sure if that really would be an improvement, given that
   //                   actions that don't actually change the registry are edge cases that should be rare.
   for ( const auto &a : as_a_result_of_actions ) {
      // ATTENTION: Note that here we are safe calling get_admin_public_address() because we know all actions have been processed (or unprocessed) successfully, i.e. are
      //            valid, which is a requirement for correct operation of get_admin_public_address() overloads.
      //            If any action failed, the registry would have thrown an exception in the validate() function, and thus this function would not be called with that.
      //            Also note that the set of affected admin addresses together with the set of asset ids of actions are the same regardless of if the actions have been
      //            processed or unprocessed, because the underlying change in the registry is just being reversed during an unprocess, thus those affected things are the
      //            same in both directions.
      affected_asset_admin_addresses.insert( get_admin_public_address( a ) );
      affected_asset_ids.insert( std::visit( []( const auto &x ) { return x.asset_id(); }, a ) );
   }
   std::shared_lock lock( observers_mutex_ );
   for ( auto *const o : update_observers_ )
      o->notify_registry_changed( affected_asset_admin_addresses, affected_asset_ids );
}

}   // namespace spats