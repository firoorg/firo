//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_UTIL_HPP_INCLUDED
#define FIRO_SPATS_UTIL_HPP_INCLUDED

#include <type_traits>
#include <concepts>

namespace spats {

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

}   // namespace spats

#endif   // FIRO_SPATS_UTIL_HPP_INCLUDED
