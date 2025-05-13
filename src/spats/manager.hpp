//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_MANAGER_HPP_INCLUDED
#define FIRO_SPATS_MANAGER_HPP_INCLUDED

#include <unordered_set>
#include <set>
#include <optional>
#include <shared_mutex>
#include <vector>

#include "registry.hpp"

class CBlockIndex;

namespace spats {

class UpdatesObserver {
public:
   using admin_addresses_set_t = std::unordered_set< public_address_t >;
   using asset_ids_set_t = std::set< flexible_asset_id_t >;

   void notify_registry_changed( const admin_addresses_set_t &affected_asset_admin_addresses, const asset_ids_set_t &affected_asset_ids )
   {
      process_spats_registry_changed( affected_asset_admin_addresses, affected_asset_ids );
   }
   // TODO more

protected:
   ~UpdatesObserver() = default;

private:
   // ATTENTION: NO overridden function is allowed to call Manager::add_updates_observer() or Manager::remove_updates_observer() during its call from the same thread,
   //            otherwise it would result in a DEADLOCK!
   virtual void process_spats_registry_changed( const admin_addresses_set_t &affected_asset_admin_addresses, const asset_ids_set_t &affected_asset_universal_ids ) = 0;
};

class Manager {
public:
   using block_hash_t = Registry::block_hash_t;

   void add_spats_actions( const Actions &actions, int block_height, const std::optional< block_hash_t > &block_hash );
   void add_block( const CBlockIndex &block );
   void remove_block( const CBlockIndex &block );
   void reset();

   Registry &registry() noexcept { return registry_; }
   const Registry &registry() const noexcept { return registry_; }

   void add_updates_observer( UpdatesObserver &o );
   void remove_updates_observer( UpdatesObserver &o );

private:
   Registry registry_;
   mutable std::shared_mutex observers_mutex_;
   std::vector< UpdatesObserver * > update_observers_;   // protected by observers_mutex_

   void notify_registry_changes( const Actions &as_a_result_of_actions ) const;
};

}   // namespace spats

#endif   // FIRO_SPATS_MANAGER_HPP_INCLUDED