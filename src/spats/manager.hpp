//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_MANAGER_HPP_INCLUDED
#define FIRO_SPATS_MANAGER_HPP_INCLUDED

#include "registry.hpp"

class CBlockIndex;

namespace spats {

class Manager {
public:
   void add_block( const CBlockIndex &block );
   void remove_block( const CBlockIndex &block );
   void reset();

   Registry &registry() noexcept { return registry_; }
   const Registry &registry() const noexcept { return registry_; }

private:
   Registry registry_;
};

}   // namespace spats

#endif   // FIRO_SPATS_MANAGER_HPP_INCLUDED
