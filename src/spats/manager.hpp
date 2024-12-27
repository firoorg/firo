//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_MANAGER_HPP_INCLUDED
#define FIRO_SPATS_MANAGER_HPP_INCLUDED

#include "registry.hpp"

class CBlockIndex;

namespace spats {

class Wallet;

class Manager {
public:
   void add_block( const CBlockIndex &block );
   void remove_block( const CBlockIndex &block );
   void reset();

   Registry &registry() noexcept { return registry_; }
   const Registry &registry() const noexcept { return registry_; }

   void set_observer_wallet( Wallet &w ) noexcept { observer_wallet_ = &w; }

private:
   Registry registry_;
   Wallet *observer_wallet_ = nullptr;
};

}   // namespace spats

#endif   // FIRO_SPATS_MANAGER_HPP_INCLUDED
