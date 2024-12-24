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

private:
   Registry registry_;
};

}   // namespace spats

#endif   // FIRO_SPATS_MANAGER_HPP_INCLUDED
