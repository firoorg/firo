//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_CONSTRAINED_VALUE_HPP_INCLUDED
#define FIRO_SPATS_CONSTRAINED_VALUE_HPP_INCLUDED

#include <concepts>
#include <stdexcept>

namespace spats {   // TODO promote to a more general namespace & directory? Do we have an existing proper place for these kind of things?

namespace detail {

template < std::semiregular T, auto ValidityPredicate >
   requires std::predicate< decltype( ValidityPredicate ), const T & >
class validity_ensurer {
protected:
   explicit validity_ensurer( const T &t ) { ensure_validity( t ); }

   static void ensure_validity( const T &t )
   {
      if ( !ValidityPredicate( t ) )
         throw std::invalid_argument( "Invalid value supplied to constrained_value" );
   }
};

}   // namespace detail

template < std::semiregular T, auto ValidityPredicate >
   requires std::predicate< decltype( ValidityPredicate ), const T & >
class constrained_value : detail::validity_ensurer< T, ValidityPredicate > {
   using base_type = detail::validity_ensurer< T, ValidityPredicate >;

public:
   constrained_value( T &&value )
      : base_type( value )
      , value_( std::move( value ) )
   {}

   constrained_value &operator=( T &&value )
   {
      base_type::ensure_validity( value );
      value_ = std::move( value );
      return *this;
   }

   [[nodiscard]] const T &get() const noexcept { return value_; }

   // deliberately implicit
   operator const T &() const noexcept { return get(); }

private:
   T value_;
};

// TODO operators like == if and when it is supported by T

}   // namespace spats

#endif   // FIRO_SPATS_CONSTRAINED_VALUE_HPP_INCLUDED
