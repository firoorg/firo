//
// Created by Gevorg Voskanyan
//

#ifndef SPATS_SCALED_AMOUNT_HPP_INCLUDED
#define SPATS_SCALED_AMOUNT_HPP_INCLUDED

#include "util.hpp"

#include <cstdint>
#include <cmath>
#include <concepts>
#include <stdexcept>
#include <type_traits>

namespace spats {

// If RawAmountType is unsigned, then scaled_amount< RawAmountType > will denote a non-negative number. Any operation that would mathematically yield a negative number
// would be blocked (exception will be thrown), rather than using modulo arithmetic that would happen with a naked unsigned type. So wraparounds/overflows are not
// allowed, and that is regardless if the type is signed or unsigned - any such attempts would result in an exception and the held value won't change. Thus, an operation
// would succeed if and only if the mathematical result is representable in the scaled_amount specialization at hand.
template < typename RawAmountType = std::uint64_t >
   requires( std::integral< RawAmountType > && !std::is_same_v< RawAmountType, bool > )
class scaled_amount {
public:
   using raw_amount_type = RawAmountType;

   constexpr scaled_amount( raw_amount_type raw = {}, unsigned precision = 8 )
      : raw_amount_( raw )
      , precision_( precision )
   {
      set_precision( precision );   // IMPORTANT: not redundant, done in order to check the limits of precision, may throw
   }

   constexpr scaled_amount &operator=( raw_amount_type raw ) noexcept
   {
      raw_amount_ = raw;
      return *this;
   }

   void operator=( std::floating_point auto F ) = delete;   // no assignment from floating-point types directly

   // TODO @= overloads, with checks against overflow/underflow/wraparound

   [[nodiscard]] constexpr raw_amount_type raw() const noexcept { return raw_amount_; }
   [[nodiscard]] constexpr unsigned precision() const noexcept { return precision_; }

   [[nodiscard]] constexpr std::pair< RawAmountType, RawAmountType > unpack() const noexcept
   {
      const auto df = decimal_factor();
      const auto r = raw();
      const auto after = r % df;
      const auto before = ( r - after ) / df;
      return { before, after };
   }

   [[nodiscard]] constexpr double as_double() const noexcept { return raw() / decimal_factor(); }
   explicit constexpr operator double() const noexcept { return as_double(); }

   explicit constexpr operator bool() const noexcept { return !!raw_amount_; }

private:
   // the true mathematical amount is raw_amount_ / 10^precision_
   raw_amount_type raw_amount_{};
   unsigned precision_{};

   // For now, not allowing precision to change after construction, hence this is private.
   // If we ever do, then need to readjust the raw value such that as_double() would return the same value before & after.
   constexpr void set_precision( unsigned const precision )
   {
      // though theoretically possible, choosing not to support here precisions which would equal or exceed the number of digits of the max raw value
      if ( precision >= std::numeric_limits< raw_amount_type >::digits10 )
         throw std::invalid_argument( "precision is too high, not supported" );   // TODO add details
      precision_ = precision;
   }

   constexpr auto decimal_factor() const noexcept { return integral_power( std::uintmax_t( 10 ), precision() ); }
};

// TODO comparison operators
// TODO output

}   // namespace spats

#endif   // SPATS_SCALED_AMOUNT_HPP_INCLUDED
