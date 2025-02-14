//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_UTILS_SCALED_AMOUNT_HPP_INCLUDED
#define FIRO_UTILS_SCALED_AMOUNT_HPP_INCLUDED

#include <cstdint>
#include <cmath>
#include <concepts>
#include <stdexcept>
#include <type_traits>
#include <iomanip>
#include <iostream>   // TODO remove

#include <boost/io/ios_state.hpp>

#include "../utils/math.hpp"

namespace utils {

// If RawAmountType is an unsigned type, then scaled_amount< RawAmountType > will denote a non-negative number. Any operation that would mathematically yield a negative
// number would be blocked (exception will be thrown), rather than using modulo arithmetic that would happen with a naked unsigned type. So wraparounds/overflows are not
// allowed, and that is regardless if the type is signed or unsigned - any such attempts would result in an exception and the held value won't change. Thus, an operation
// would succeed if and only if the mathematical result is representable in the scaled_amount specialization at hand.
template < typename RawAmountType = std::uint64_t >
   requires( std::integral< RawAmountType > && !std::is_same_v< RawAmountType, bool > )
class scaled_amount {
public:
   using raw_amount_type = RawAmountType;
   using precision_type = unsigned;

   constexpr scaled_amount( raw_amount_type raw, precision_type precision )
      : raw_amount_( raw )
      , precision_( precision )
   {
      set_precision( precision );   // IMPORTANT: not redundant, done in order to check the limits of precision, may throw
      assert( this->raw() == raw && this->precision() == precision );
   }

   constexpr scaled_amount() noexcept
      : scaled_amount( {}, {} )
   {
      assert( !raw_amount_ && !precision_ );
      assert( !*this && "default-constructed scaled_amount should result in the value 0" );
   }

   // Choosing not to support single argument construction from raw_amount_type because both 0 and 8 could be reasonable expected defaults for precision for different
   // people, among the target audience of bitcoin and derivatives developers, especially with NFTs being added onto the scene. Thus, the safe thing to do is to force the
   // user of this class be explicit about the required precision when constructing objects.
   scaled_amount( std::integral auto ) = delete;

   // No construction/assignment from floating-point types directly.
   // Instead, have the caller be responsible for handling the necessary precision for dealing with fp values, as appropriate for it.
   scaled_amount( std::floating_point auto ) = delete;
   void operator=( std::floating_point auto ) = delete;

   // No direct assignment from integers either, too error-prone potentially
   void operator=( std::integral auto ) = delete;

   // TODO @= overloads, with checks against overflow/underflow/wraparound

   [[nodiscard]] constexpr raw_amount_type raw() const noexcept { return raw_amount_; }
   [[nodiscard]] constexpr precision_type precision() const noexcept { return precision_; }

   // ATTENTION: only use if you are absolutely sure that .precision() already has the value you want for it!
   constexpr void set_raw( raw_amount_type raw ) noexcept { raw_amount_ = raw; }

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

   bool operator==( scaled_amount const &rhs ) const noexcept
   {
      if ( precision() == rhs.precision() )
         return raw() == rhs.raw();
      try {
         auto lhs = *this;
         lhs.set_precision( rhs.precision() );
         return lhs.raw() == rhs.raw();
      }
      catch ( ... ) {
         return false;
      }
   }

private:
   // the true mathematical amount is raw_amount_ / 10^precision_
   raw_amount_type raw_amount_{};
   precision_type precision_{};

   constexpr void set_precision( precision_type const precision )
   {
      // though theoretically possible, choosing not to support here precisions which would equal or exceed the number of digits of the max raw value
      if ( precision >= std::numeric_limits< raw_amount_type >::digits10 )
         throw std::invalid_argument( "precision is too high, not supported" );   // TODO add details
      if ( precision_ == precision )
         return;
      // TODO remove cout stuff
      std::cout << "set_precision() raw_ = " << raw_amount_ << " precision_ " << precision_ << " precision " << precision << "\n";
      std::cout << "as_double() before = " << as_double() << "\n";
      // TODO overflow/underflow checks
      if ( precision_ > precision )
         raw_amount_ *= math::integral_power( std::uintmax_t( 10 ), precision_ - precision );
      else
         raw_amount_ /= math::integral_power( std::uintmax_t( 10 ), precision - precision_ );
      precision_ = precision;
      std::cout << "as_double() after = " << as_double() << "\n";
   }

   constexpr auto decimal_factor() const noexcept { return math::integral_power( std::uintmax_t( 10 ), precision() ); }
};

// TODO more comparison operators

template < typename CharT, typename Traits, typename RawAmountType >
std::basic_ostream< CharT, Traits > &operator<<( std::basic_ostream< CharT, Traits > &os, const scaled_amount< RawAmountType > &amount )
{
   const auto [ before, after ] = amount.unpack();
   boost::io::ios_fill_saver ifs( os );
   os << before << "." << std::setfill( '0' ) << std::setw( amount.precision() ) << after;
   return os;
}

}   // namespace utils

#endif   // FIRO_UTILS_SCALED_AMOUNT_HPP_INCLUDED
