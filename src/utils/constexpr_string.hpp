// Copyright (c) 2025 Gevorg Voskanyan
// Copyright (c) 2025 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_UTILS_CONSTEXPR_STRING_HPP_INCLUDED
#define FIRO_UTILS_CONSTEXPR_STRING_HPP_INCLUDED

#include <cstddef>

// Helper structure for compile-time strings
template < std::size_t N >
struct constexpr_string {
   char value[ N ];

   // constexpr constructor to populate the string
   constexpr constexpr_string( const char ( &str )[ N ] ) noexcept
   {
      for ( std::size_t i = 0; i < N; ++i )
         value[ i ] = str[ i ];
   }

   constexpr const char *get() const noexcept { return value; }
   constexpr operator const char * () const noexcept { return get(); }
};

#endif   // FIRO_UTILS_CONSTEXPR_STRING_HPP_INCLUDED
