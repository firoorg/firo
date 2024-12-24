//
// Created by Gevorg Voskanyan
//

#include "manager.hpp"

namespace spats {

void Manager::add_block( const CBlockIndex &block ) {}

void Manager::remove_block( const CBlockIndex &block ) {}

void Manager::reset()
{
   registry_.clear();
}

}   // namespace spats