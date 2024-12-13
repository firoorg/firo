//
// Created by Gevorg Voskanyan
//

#ifndef SPATS_UTIL_HPP_INCLUDED
#define SPATS_UTIL_HPP_INCLUDED

#include <type_traits>

namespace spats {

// TODO C++23: remove and replace usages with std::to_underlying()
template < typename E >
constexpr std::underlying_type_t< E > to_underlying( E e ) noexcept
{
   return static_cast< std::underlying_type_t< E > >( e );
}

}   // namespace spats

#endif // SPATS_UTIL_HPP_INCLUDED
