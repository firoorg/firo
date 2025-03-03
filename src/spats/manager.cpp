//
// Created by Gevorg Voskanyan
//

#include "../chain.h"

#include "manager.hpp"

namespace spats {

void Manager::add_spats_actions( const Actions &actions, const int block_height, const std::optional< block_hash_t > &block_hash )
{
   if ( !actions.empty() || block_height >= 1200 )   // TODO remove the 1200 part
      LogPrintf( "Adding %d spats actions with block height %d and hash %s\n", actions.size(), block_height, block_hash ? block_hash->ToString() : "<NULL>" );
   bool registry_updated = false;
   for ( const auto &a : actions )
      registry_updated = registry_.process( a, block_height, block_hash ) || registry_updated;   // TODO process wallet-specific txs as appropriate
   if ( registry_updated )
      if ( UpdatesObserver *const o = updates_observer_.load() )
         o->notify_registry_changed();
}

void Manager::add_block( const CBlockIndex &block )
{
   add_spats_actions( block.spats_actions, block.nHeight, block.phashBlock ? std::optional( *block.phashBlock ) : std::nullopt );
}

void Manager::remove_block( const CBlockIndex &block )
{
   bool registry_updated = false;
   for ( const auto &a : block.spats_actions )
      registry_updated = registry_.unprocess( a, block.nHeight ) || registry_updated;   // TODO unprocess wallet-specific txs as appropriate
   if ( registry_updated )
      if ( UpdatesObserver *const o = updates_observer_.load() )
         o->notify_registry_changed();
}

void Manager::reset()
{
   registry_.clear();
}

}   // namespace spats