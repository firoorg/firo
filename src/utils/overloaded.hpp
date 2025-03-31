// Copyright (c) 2024 Gevorg Voskanyan
// Copyright (c) 2024 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_UTILS_OVERLOADED_HPP_INCLUDED
#define FIRO_UTILS_OVERLOADED_HPP_INCLUDED

namespace utils {

template < class... Ts >
struct overloaded : Ts... {
   using Ts::operator()...;
};

template < class... Ts >
overloaded( Ts... ) -> overloaded< Ts... >;

}   // namespace utils

#endif   // FIRO_UTILS_OVERLOADED_HPP_INCLUDED
