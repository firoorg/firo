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

   scaled_amount &operator+=( scaled_amount const &rhs )
   {
      if ( precision() != rhs.precision() ) {
         assert( "scaled_amount op+= requires precisions to match" );
         throw std::invalid_argument( "scaled_amount op+= requires precisions to match" );
      }
      const auto result = raw() + rhs.raw();
      if ( rhs.raw() > 0 && result < raw() )
         throw std::overflow_error( "scaled_amount op+= would result in overflow, thus rejected" );
      if ( rhs.raw() < 0 && result > raw() )
         throw std::underflow_error( "scaled_amount op+= would result in underflow, thus rejected" );
      raw_amount_ = result;
      return *this;
   }

   scaled_amount &operator-=( scaled_amount const &rhs )
   {
      if ( precision() != rhs.precision() ) {
         assert( "scaled_amount op-= requires precisions to match" );
         throw std::invalid_argument( "scaled_amount op-= requires precisions to match" );
      }
      if constexpr ( std::is_unsigned_v< RawAmountType > )
         if ( rhs.raw() > raw() )   // checking against unsigned wraparound (technically not an underflow, but here we treat it as such anyway)
            throw std::underflow_error( "scaled_amount op-= would result in underflow, thus rejected" );
      const auto result = raw() - rhs.raw();
      if ( rhs.raw() > 0 && result > raw() )
         throw std::underflow_error( "scaled_amount op-= would result in underflow, thus rejected" );
      if ( rhs.raw() < 0 && result < raw() )
         throw std::overflow_error( "scaled_amount op-= would result in overflow, thus rejected" );
      raw_amount_ = result;
      return *this;
   }

   // TODO more @= overloads, with checks against overflow/underflow/wraparound

   [[nodiscard]] constexpr raw_amount_type raw() const noexcept { return raw_amount_; }
   [[nodiscard]] constexpr precision_type precision() const noexcept { return precision_; }

   constexpr auto decimal_factor() const noexcept { return math::integral_power( std::uintmax_t( 10 ), precision() ); }

   // The maximum supported value with the current .precision()
   constexpr scaled_amount max_value() const noexcept { return { std::numeric_limits< raw_amount_type >::max(), precision() }; }
   // The minimum supported value with the current .precision()
   constexpr scaled_amount min_value() const noexcept { return { std::numeric_limits< raw_amount_type >::min(), precision() }; }

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

   [[nodiscard]] constexpr double as_double() const noexcept { return raw() / static_cast< double >( decimal_factor() ); }
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
         // falling back to the slower but more robust check:
         return operator<=>( rhs ) == std::strong_ordering::equal;
      }
   }

   // Yes, strong_ordering, because if it compares equal with <=> then it will definitely compare equal with == too here
   std::strong_ordering operator<=>( scaled_amount const &rhs ) const noexcept
   {
      if ( precision() == rhs.precision() )
         return raw() <=> rhs.raw();
      // comparing a.x with b.y
      const auto [ a, x ] = unpack();
      const auto [ b, y ] = rhs.unpack();
      if ( a < b )
         return std::strong_ordering::less;
      if ( a > b )
         return std::strong_ordering::greater;
      const auto dfx = decimal_factor();
      const auto dfy = rhs.decimal_factor();
      const auto maxdf = std::max( dfx, dfy );
      return x * ( maxdf / dfx ) <=> y * ( maxdf / dfy );
   }

   static scaled_amount from_string( std::string_view str )
   {
      bool negative = false;
      if ( str.front() == '+' ) {
         str.remove_prefix( 1 );
      }
      if constexpr ( std::is_signed_v< RawAmountType > ) {
         if ( str.front() == '-' ) {
            negative = true;
            str.remove_prefix( 1 );
         }
      }

      if ( str.front() == '.' )
         throw std::invalid_argument( "Cannot have a dot at the beginning of string representation of a scaled_amount" );
      // a trailing dot is ok though, provided it's the only dot in str, although op<< won't ever produce a trailing dot, but whatever...

      precision_type precision = 0;
      raw_amount_type raw = 0;
      bool after_dot = false;
      for ( const auto c : str ) {
         if ( c == '.' ) {
            if ( after_dot )
               throw std::invalid_argument( "Cannot have more than one dot in string representation of a scaled_amount" );
            after_dot = true;
            continue;
         }

         if ( c >= '0' && c <= '9' ) {
            const auto new_raw = raw * 10 + ( c - '0' );
            static_assert( std::is_same_v< decltype( new_raw ), const raw_amount_type > );
            if ( new_raw < raw )   // This would reject numeric_limits::min(), not sure if we need/want to support that extreme value here anyway, but TODO test
               // TODO the actual N
               negative ? throw std::underflow_error( "Negative number too big for scaled_amount of N bits" )
                        : throw std::overflow_error( "Number too big for scaled_amount of N bits" );
            raw = new_raw;
         }
         else
            throw std::invalid_argument( "invalid character in string" );

         if ( after_dot )
            ++precision;
      }

      return { negative ? -raw : raw, precision };
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
};

template < typename RawAmountType >
scaled_amount< RawAmountType > operator+( scaled_amount< RawAmountType > lhs, const scaled_amount< RawAmountType > &rhs )
{
   lhs += rhs;
   return lhs;
}

template < typename RawAmountType >
scaled_amount< RawAmountType > operator-( scaled_amount< RawAmountType > lhs, const scaled_amount< RawAmountType > &rhs )
{
   lhs -= rhs;
   return lhs;
}

template < typename CharT, typename Traits, typename RawAmountType >
std::basic_ostream< CharT, Traits > &operator<<( std::basic_ostream< CharT, Traits > &os, const scaled_amount< RawAmountType > &amount )
{
   const auto [ before, after ] = amount.unpack();
   os << before;
   if ( amount.precision() > 0 ) {
      boost::io::ios_fill_saver ifs( os );
      os << "." << std::setfill( '0' ) << std::setw( amount.precision() ) << after;
   }
   return os;
}

}   // namespace utils

#endif   // FIRO_UTILS_SCALED_AMOUNT_HPP_INCLUDED
