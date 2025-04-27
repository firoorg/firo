// Copyright (c) 2025 Gevorg Voskanyan
// Copyright (c) 2025 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_UTILS_SCOPE_EXIT_HPP_INCLUDED
#define FIRO_UTILS_SCOPE_EXIT_HPP_INCLUDED

#include <exception>
#include <utility>
#include <type_traits>

#include <boost/version.hpp>
#include <boost/exception/diagnostic_information.hpp>

#include "util.h"

namespace utils {

template < typename F >
#if BOOST_VERSION >= 108500
[[deprecated( "Remove this and replace all usages with boost::scope::scope_fail now that it is available in this project" )]]
#endif
class on_exception_exit {
public:
   explicit on_exception_exit( F f ) noexcept( std::is_nothrow_move_constructible_v< F > )
      : num_uncaught_exceptions_at_construction_( std::uncaught_exceptions() )
      , f_( std::move( f ) )
   {}

   ~on_exception_exit()
   {
      if ( std::uncaught_exceptions() > num_uncaught_exceptions_at_construction_ )
         try {
            f_();
         }
         catch ( ... ) {
            try {
               LogPrintf( "Exception in ~on_exception_exit(): %s\n", boost::current_exception_diagnostic_information() );
            }
            catch ( ... ) {
            }
         }
   }

private:
   const int num_uncaught_exceptions_at_construction_;
   F f_;

   on_exception_exit( const on_exception_exit & ) = delete;
   on_exception_exit( on_exception_exit && ) = delete;
   void operator=( const on_exception_exit & ) = delete;
   void operator=( on_exception_exit && ) = delete;
};

}   // namespace utils

#endif   // FIRO_UTILS_SCOPE_EXIT_HPP_INCLUDED
