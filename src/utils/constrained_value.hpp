//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_UTILS_CONSTRAINED_VALUE_HPP_INCLUDED
#define FIRO_UTILS_CONSTRAINED_VALUE_HPP_INCLUDED

#include <concepts>
#include <stdexcept>
#include <string>

#include <boost/lexical_cast.hpp>

#include "constexpr_string.hpp"

using namespace std::literals;

namespace utils {

namespace detail {

template < std::semiregular T, auto ValidityPredicate, constexpr_string InvalidValueErrorMessage >
   requires std::predicate< decltype( ValidityPredicate ), const T & >
class validity_ensurer {
protected:
   explicit validity_ensurer( const T &t ) { ensure_validity( t ); }

   static void ensure_validity( const T &t )
   {
      if ( !ValidityPredicate( t ) )
         throw std::invalid_argument( InvalidValueErrorMessage.get() + ": "s + boost::lexical_cast< std::string >( t ) );
   }
};

}   // namespace detail

template < std::semiregular T, auto ValidityPredicate, constexpr_string InvalidValueErrorMessage >
   requires std::predicate< decltype( ValidityPredicate ), const T & >
class constrained_value : detail::validity_ensurer< T, ValidityPredicate, InvalidValueErrorMessage > {
   using base_type = detail::validity_ensurer< T, ValidityPredicate, InvalidValueErrorMessage >;

public:
#if 0   // TODO contemplate if/how to support this
   constrained_value()
      requires( std::is_default_constructible_v< T > && ValidityPredicate( T() ) )
      : base_type( T() )
      , value_()
   {}
#endif

   constrained_value( T &&value )
      : base_type( value )
      , value_( std::move( value ) )
   {}

   template < typename Stream >
   constrained_value( deserialize_type, Stream &is )
      : constrained_value( deserialize_from( is ) )
   {}

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      os << value_;
   }

   constrained_value &operator=( T &&value )
   {
      base_type::ensure_validity( value );
      value_ = std::move( value );
      return *this;
   }

   [[nodiscard]] const T &get() const noexcept { return value_; }

   // deliberately implicit
   operator const T &() const noexcept { return get(); }

   friend bool operator==( const constrained_value &a, const constrained_value &b ) noexcept( noexcept( a.get() == b.get() ) )
      requires( std::equality_comparable< T > )
   {
      return a.get() == b.get();
   }

private:
   T value_;

   template < typename Stream >
   static T deserialize_from( Stream &is )
   {
      if constexpr ( std::is_default_constructible_v< T > ) {
         T t;
         is >> t;
         return t;
      }
      else
         return T( deserialize, is );
   }
};

template < std::semiregular T, auto ValidityPredicate, constexpr_string InvalidValueErrorMessage >
std::ostream &operator<<( std::ostream &os, const constrained_value< T, ValidityPredicate, InvalidValueErrorMessage > &v )
{
   return os << v.get();
}

}   // namespace utils

#endif   // FIRO_UTILS_CONSTRAINED_VALUE_HPP_INCLUDED
