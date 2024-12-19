//
// Created by Gevorg Voskanyan.
//

#ifndef FIRO_ENUM_HPP_INCLUDED
#define FIRO_ENUM_HPP_INCLUDED

#include <type_traits>

template < typename E >
concept Enum = std::is_enum_v< E >;

// TODO C++23: remove and replace usages with std::to_underlying()
constexpr auto to_underlying( Enum auto e ) noexcept
{
   return static_cast< std::underlying_type_t< decltype( e ) > >( e );
}

#endif   // FIRO_ENUM_HPP_INCLUDED
