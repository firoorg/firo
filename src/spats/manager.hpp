//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_MANAGER_HPP_INCLUDED
#define FIRO_SPATS_MANAGER_HPP_INCLUDED

#include "registry.hpp"

class CBlockIndex;

namespace spats {

class UpdatesObserver {
public:
   void notify_registry_changed() { process_registry_changed(); }
   // TODO more

protected:
   ~UpdatesObserver() = default;

private:
   virtual void process_registry_changed() = 0;
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

   void set_updates_observer( UpdatesObserver *o = nullptr ) noexcept { updates_observer_ = o; }

private:
   Registry registry_;
   std::atomic< UpdatesObserver * > updates_observer_{};
};

}   // namespace spats

#endif   // FIRO_SPATS_MANAGER_HPP_INCLUDED