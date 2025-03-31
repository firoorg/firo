//
// Created by Gevorg Voskanyan
//

#include <string.h>
// Weird compile error without the above #include:
/*                 from src/spats/modification.cpp:9:
/usr/include/string.h:413:15: error: conflicting declaration of ‘size_t strnlen(const char*, size_t)’ with ‘C’ linkage
  413 | extern size_t strnlen (const char *__string, size_t __maxlen)
      |               ^~~~~~~
In file included from src/spats/../util.h:18:
src/spats/../compat.h:94:8: note: previous declaration with ‘C++’ linkage
   94 | size_t strnlen( const char *start, size_t max_len);*/

#include <ostream>

#include "../util.h"

#include "modification.hpp"

namespace spats {

const char *const tail = "   ";

std::ostream &operator<<( std::ostream &os, const AssetModificationBase &m )
{
   if ( m.asset_naming_change_ )
      os << ' ' << m.asset_naming_change_ << tail;
   if ( m.metadata_change_ )
      os << _( "Metadata" ) << ' ' << m.metadata_change_ << tail;
   return os;
}

std::ostream &operator<<( std::ostream &os, const AttributeModification< AssetNaming > &m )
{
   const auto &o = m.old_value();
   const auto &n = m.new_value();
   if ( n.symbol != o.symbol )
      os << _( "Symbol" ) << ' ', print_change_old_to_new( os, o.symbol, n.symbol ), os << tail;
   if ( n.name != o.name )
      os << _( "Name" ) << ' ', print_change_old_to_new( os, o.name, n.name ), os << tail;
   if ( n.description != o.description )
      os << _( "Description" ) << ' ', print_change_old_to_new( os, o.description, n.description ), os << tail;
   return os;
}

}   // namespace spats