//
// Created by Gevorg Voskanyan
//

#ifndef SPATS_UTIL_HPP_INCLUDED
#define SPATS_UTIL_HPP_INCLUDED

#include <type_traits>
#include <concepts>

namespace spats {

// TODO C++23: remove and replace usages with std::to_underlying()
template < typename E >
constexpr std::underlying_type_t< E > to_underlying( E e ) noexcept
{
   return static_cast< std::underlying_type_t< E > >( e );
}

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

#endif   // SPATS_UTIL_HPP_INCLUDED
