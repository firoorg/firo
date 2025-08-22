// Copyright (c) 2024-2025 Gevorg Voskanyan
// Copyright (c) 2024-2025 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_UTILS_ENUM_HPP_INCLUDED
#define FIRO_UTILS_ENUM_HPP_INCLUDED

#include <type_traits>

namespace utils {

namespace concepts {

template < typename E >
concept Enum = std::is_enum_v< E >;

}

// TODO C++23: remove and replace usages with std::to_underlying()
constexpr auto to_underlying( concepts::Enum auto e ) noexcept
{
   return static_cast< std::underlying_type_t< decltype( e ) > >( e );
}

}   // namespace utils

#endif   // FIRO_UTILS_ENUM_HPP_INCLUDED
