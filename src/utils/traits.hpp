// Copyright (c) 2024 Gevorg Voskanyan
// Copyright (c) 2024 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_UTILS_TRAITS_HPP_INCLUDED
#define FIRO_UTILS_TRAITS_HPP_INCLUDED

#include <type_traits>
#include <variant>

namespace utils {

template < auto >
struct is_member_ptr : std::false_type {};

template < typename T, class C, T C::*Mmp >
struct is_member_ptr< Mmp > : std::true_type {
   using class_type = C;
   using data_type = T;
};

template < typename >
struct is_variant : std::false_type {};

template < typename... Ts >
struct is_variant< std::variant< Ts... > > : std::true_type {};

namespace concepts {

template < class V >
concept variant = is_variant< V >::value;

}

template < typename >
struct variant_types_unpacker;

template < typename... Ts >
struct variant_types_unpacker< std::variant< Ts... > > {
   static_assert( concepts::variant< std::variant< Ts... > > );
   template < class F >
   auto operator()( F &&f ) const
   {
      return std::forward< F >( f ).template operator()< Ts... >();
   }
};

}   // namespace utils

#endif   // FIRO_UTILS_TRAITS_HPP_INCLUDED
