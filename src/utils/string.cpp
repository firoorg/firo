// Copyright (c) 2025 Gevorg Voskanyan
// Copyright (c) 2025 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "string.hpp"

namespace utils {

std::string abbreviate_for_display( std::string s )
{
   constexpr auto threshold = 100;
   if ( s.size() > threshold ) {
      constexpr auto edge_length = threshold / 2 - 5;
      s.replace( edge_length, s.size() - 2 * edge_length, "..." );
   }
   return s;
}

}   // namespace utils
