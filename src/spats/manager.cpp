//
// Created by Gevorg Voskanyan
//

#include "../chain.h"

#include "manager.hpp"

namespace spats {

void Manager::add_spats_action_sequence( const ActionSequence &action_sequence, int block_height )
{
   if ( !action_sequence.empty() || block_height >= 1200 )  // TODO remove the 1200 part
      LogPrintf( "Adding %d spats actions with block height: %d\n", action_sequence.size(), block_height );
   bool registry_updated = false;
   for ( const auto &a : action_sequence )
      registry_updated = registry_.process( a, block_height ) || registry_updated;   // TODO process wallet-specific txs as appropriate
   if ( registry_updated )
      if ( UpdatesObserver *const o = updates_observer_.load() )
         o->notify_registry_changed();
}

void Manager::add_block( const CBlockIndex &block )
{
   add_spats_action_sequence( block.spats_action_sequence, block.nHeight );
}

void Manager::remove_block( const CBlockIndex &block )
{
   bool registry_updated = false;
   for ( const auto &a : block.spats_action_sequence )
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