// Copyright (c) 2024 Gevorg Voskanyan
// Copyright (c) 2024 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_UTILS_MATH_HPP_INCLUDED
#define FIRO_UTILS_MATH_HPP_INCLUDED

#include <concepts>

namespace utils::math {

template < typename T, std::unsigned_integral P >
constexpr auto integral_power( T t, P p ) -> decltype( t * t )
{
   // Taken and slightly modified from https://codereview.stackexchange.com/a/250559
   if ( !p )
      return T( 1 );

   auto result = integral_power( t, p / 2 );
   result *= result;

   if ( p & P( 1 ) )
      result *= t;

   return result;
}

}   // namespace utils::math

#endif   // FIRO_UTILS_MATH_HPP_INCLUDED
