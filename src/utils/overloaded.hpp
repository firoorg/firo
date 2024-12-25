//
// Created by Gevorg Voskanyan
//

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
