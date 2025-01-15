//
// Created by Gevorg Voskanyan
//

#include "../chain.h"

#include "manager.hpp"

namespace spats {

void Manager::add_block( const CBlockIndex &block )
{
   bool registry_updated = false;
   for ( const auto &a : block.spats_action_sequence )
      registry_updated = registry_.process( a, block.nHeight ) || registry_updated;   // TODO process wallet-specific txs as appropriate
   if ( registry_updated )
      if ( UpdatesObserver *const o = updates_observer_.load() )
         o->notify_registry_changed();
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