// From http://www.codef00.com/code/Fixed.h
// See also: http://stackoverflow.com/questions/79677/whats-the-best-way-to-do-fixed-point-math

/*
 * Copyright (c) 2008
 * Evan Teran
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appears in all copies and that both the
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the same name not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission. We make no representations about the
 * suitability this software for any purpose. It is provided "as is"
 * without express or implied warranty.
 */

#ifndef FIXED_20060211_H_
#define FIXED_20060211_H_

#include <ostream>
#include <exception>
#include <cstddef> // for std::size_t
#include <climits> // for CHAR_BIT
#include <stdint.h>

#include <boost/static_assert.hpp>
#include <boost/operators.hpp>
#include <boost/utility/enable_if.hpp>

namespace numeric {

template <std::size_t I, std::size_t F>
class Fixed;

namespace detail {
	template <class T>
	struct bit_size {
		static const std::size_t size = sizeof(T) * CHAR_BIT;
	};

	// helper templates to make magic with types :)
	// these allow us to determine resonable types from
	// a desired size, they also let us infer the next largest type
	// from a type which is nice for the division op
	template <std::size_t T>
	struct type_from_size {
		static const bool is_specialized = false;
		typedef void      value_type;
	};

#if defined(__GNUC__) && defined(__x86_64__) 
#if defined(__SIZEOF_INT128__) && __SIZEOF_INT128__ == 16
	template <>
	struct type_from_size<128> {
		static const bool           is_specialized = true;
		static const std::size_t    size = 128;
		typedef __int128            value_type;
		typedef type_from_size<128> next_size;
	};
#endif
#endif

	template <>
	struct type_from_size<64> {
		static const bool           is_specialized = true;
		static const std::size_t    size = 64;
		typedef int64_t             value_type;
		typedef type_from_size<128> next_size;
	};

	template <>
	struct type_from_size<32> {
		static const bool          is_specialized = true;
		static const std::size_t   size = 32;
		typedef int32_t            value_type;
		typedef type_from_size<64> next_size;
	};

	template <>
	struct type_from_size<16> {
		static const bool          is_specialized = true;
		static const std::size_t   size = 16;
		typedef int16_t            value_type;
		typedef type_from_size<32> next_size;
	};

	template <>
	struct type_from_size<8> {
		static const bool          is_specialized = true;
		static const std::size_t   size = 8;
		typedef int8_t             value_type;
		typedef type_from_size<16> next_size;
	};

	// this is to assist in adding support for non-native base
	// types (for adding big-int support), this should be fine
	// unless your bit-int class doesn't nicely support casting
	template<class B, class N>
	B next_to_base(const N& rhs) {
		return static_cast<B>(rhs);
	}

	struct divide_by_zero : std::exception {
	};

	template <std::size_t I, std::size_t F>
	void divide(const Fixed<I,F> &numerator, const Fixed<I,F> &denominator, Fixed<I,F> &quotient, Fixed<I,F> &remainder, typename boost::enable_if_c<detail::type_from_size<I+F>::next_size::is_specialized>::type* = 0) {

		BOOST_STATIC_ASSERT(detail::type_from_size<I + F>::next_size::is_specialized);

		typedef typename Fixed<I,F>::next_type next_type;
		typedef typename Fixed<I,F>::base_type base_type;
		static const std::size_t fractional_bits = Fixed<I,F>::fractional_bits;

		next_type t(numerator.to_raw());
		t <<= fractional_bits;

		quotient  = Fixed<I,F>::from_base(detail::next_to_base<base_type>(t / denominator.to_raw()));
		remainder = Fixed<I,F>::from_base(detail::next_to_base<base_type>(t % denominator.to_raw()));
	}

	template <std::size_t I, std::size_t F>
	void divide(Fixed<I,F> numerator, Fixed<I,F> denominator, Fixed<I,F> &quotient, Fixed<I,F> &remainder, typename boost::disable_if_c<detail::type_from_size<I+F>::next_size::is_specialized>::type* = 0) {

		// NOTE: division is broken for large types :-(
		// especially when dealing with negative quantities

		typedef typename Fixed<I,F>::base_type base_type;
		static const int bits = Fixed<I,F>::total_bits;

		if(denominator == 0) {
			throw divide_by_zero();
		} else {

			int sign = 0;

			if(numerator < 0) {
				sign ^= 1;
				numerator = -numerator;
			}

			if(denominator < 0) {
				sign ^= 1;
				denominator = -denominator;
			}

			base_type n      = numerator.to_raw();
			base_type d      = denominator.to_raw();
			base_type x      = 1;
			base_type answer = 0;


			while((n >= d) && (((d >> (bits - 1)) & 1) == 0)) {
				x <<= 1;
				d <<= 1;
			}

			while(x != 0) {
				if(n >= d) {
					n -= d;
					answer |= x;
				}

				x >>= 1;
				d >>= 1;
			}

			quotient  = answer;
			remainder = n;

			if(sign) {
				quotient = -quotient;
			}
		}
	}

	// this is the usual implementation of multiplication
	template <std::size_t I, std::size_t F>
	void multiply(const Fixed<I,F> &lhs, const Fixed<I,F> &rhs, Fixed<I,F> &result, typename boost::enable_if_c<detail::type_from_size<I+F>::next_size::is_specialized>::type* = 0) {

		BOOST_STATIC_ASSERT(detail::type_from_size<I + F>::next_size::is_specialized);

		typedef typename Fixed<I,F>::next_type next_type;
		typedef typename Fixed<I,F>::base_type base_type;

		static const std::size_t fractional_bits = Fixed<I,F>::fractional_bits;

		next_type t(static_cast<next_type>(lhs.to_raw()) * static_cast<next_type>(rhs.to_raw()));
		t >>= fractional_bits;
		result = Fixed<I,F>::from_base(next_to_base<base_type>(t));
	}

	// this is the fall back version we use when we don't have a next size
	// it is slightly slower, but is more robust since it doesn't
	// require and upgraded type
	template <std::size_t I, std::size_t F>
	void multiply(const Fixed<I,F> &lhs, const Fixed<I,F> &rhs, Fixed<I,F> &result, typename boost::disable_if_c<detail::type_from_size<I+F>::next_size::is_specialized>::type* = 0) {

		typedef typename Fixed<I,F>::base_type base_type;

		static const std::size_t fractional_bits = Fixed<I,F>::fractional_bits;
		static const std::size_t integer_mask    = Fixed<I,F>::integer_mask;
		static const std::size_t fractional_mask = Fixed<I,F>::fractional_mask;

		// more costly but doesn't need a larger type
		const base_type a_hi = (lhs.to_raw() & integer_mask) >> fractional_bits;
		const base_type b_hi = (rhs.to_raw() & integer_mask) >> fractional_bits;
		const base_type a_lo = (lhs.to_raw() & fractional_mask);
		const base_type b_lo = (rhs.to_raw() & fractional_mask);

		const base_type x1 = a_hi * b_hi;
		const base_type x2 = a_hi * b_lo;
		const base_type x3 = a_lo * b_hi;
		const base_type x4 = a_lo * b_lo;

		result = Fixed<I,F>::from_base((x1 << fractional_bits) + (x3 + x2) + (x4 >> fractional_bits));

	}
}


// lets us do things like "typedef numeric::fixed_from_type<int32_t>::fixed_type fixed";
// NOTE: that we will use a type of equivalent size, not neccessarily the type
// specified. Should make little to no difference to the user
template <class T>
struct fixed_from_type {
	typedef Fixed<detail::bit_size<T>::size / 2, detail::bit_size<T>::size / 2> fixed_type;
};


/*
 * inheriting from boost::operators enables us to be a drop in replacement for base types
 * without having to specify all the different versions of operators manually
 */
template <std::size_t I, std::size_t F>
class Fixed : boost::operators<Fixed<I,F> >, boost::shiftable<Fixed<I,F> > {
	BOOST_STATIC_ASSERT(detail::type_from_size<I + F>::is_specialized);
	
public:
	static const std::size_t fractional_bits = F;
	static const std::size_t integer_bits    = I;
	static const std::size_t total_bits      = I + F;

	typedef detail::type_from_size<total_bits>             base_type_info;

	typedef typename base_type_info::value_type            base_type;
	typedef typename base_type_info::next_size::value_type next_type;

public:
	static const std::size_t base_size     = base_type_info::size;
	static const base_type fractional_mask = ~((~base_type(0)) << fractional_bits);
	static const base_type integer_mask    = ~fractional_mask;

public:
	static const base_type one = base_type(1) << fractional_bits;

public: // constructors
	Fixed() : data_(0) {
	}

	Fixed(long n) : data_(base_type(n) << fractional_bits) {
		// TODO: assert in range!
	}

	Fixed(unsigned long n) : data_(base_type(n) << fractional_bits) {
		// TODO: assert in range!
	}

	Fixed(int n) : data_(base_type(n) << fractional_bits) {
		// TODO: assert in range!
	}

	Fixed(unsigned int n) : data_(base_type(n) << fractional_bits) {
		// TODO: assert in range!
	}

	Fixed(float n) : data_(static_cast<base_type>(n * one)) {
		// TODO: assert in range!
	}

	Fixed(double n) : data_(static_cast<base_type>(n * one))  {
		// TODO: assert in range!
	}

	Fixed(const Fixed &o) : data_(o.data_) {
	}

	Fixed& operator=(const Fixed &o) {
		data_ = o.data_;
		return *this;
	}

private:
	// this makes it simpler to create a fixed point object from
	// a native type without scaling
	// use "Fixed::from_base" in order to perform this.
	struct no_scale {};

	Fixed(base_type n, const no_scale &) : data_(n) {
	}

public:
	static Fixed from_base(base_type n) {
		return Fixed(n, no_scale());
	}

public:	// comparison operators
	bool operator==(const Fixed &o) const {
		return data_ == o.data_;
	}

	bool operator<(const Fixed &o) const {
		return data_ < o.data_;
	}

public:	// unary operators
	bool operator!() const {
		return !data_;
	}

	Fixed operator~() const {
		Fixed t(*this);
		t.data_ = ~t.data_;
		return t;
	}

	Fixed operator-() const {
		Fixed t(*this);
		t.data_ = -t.data_;
		return t;
	}

	Fixed& operator++() {
		data_ += one;
		return *this;
	}

	Fixed& operator--() {
		data_ -= one;
		return *this;
	}

public:	// basic math operators
	Fixed& operator+=(const Fixed &n) {
		data_ += n.data_;
		return *this;
	}

	Fixed& operator-=(const Fixed &n) {
		data_ -= n.data_;
		return *this;
	}

	Fixed& operator&=(const Fixed &n) {
		data_ &= n.data_;
		return *this;
	}

	Fixed& operator|=(const Fixed &n) {
		data_ |= n.data_;
		return *this;
	}

	Fixed& operator^=(const Fixed &n) {
		data_ ^= n.data_;
		return *this;
	}

	Fixed& operator*=(const Fixed &n) {
		detail::multiply(*this, n, *this);
		return *this;
	}

	Fixed& operator/=(const Fixed &n) {
		Fixed temp;
		detail::divide(*this, n, *this, temp);
		return *this;
	}

	Fixed& operator>>=(const Fixed &n) {
		data_ >>= n.to_int();
		return *this;
	}

	Fixed& operator<<=(const Fixed &n) {
		data_ <<= n.to_int();
		return *this;
	}

public: // conversion to basic types
	int to_int() const {
		return (data_ & integer_mask) >> fractional_bits;
	}

	unsigned int to_uint() const {
		return (data_ & integer_mask) >> fractional_bits;
	}

	float to_float() const {
		return static_cast<float>(data_) / Fixed::one;
	}

	double to_double() const		{
		return static_cast<double>(data_) / Fixed::one;
	}

	base_type to_raw() const {
		return data_;
	}

public:
	void swap(Fixed &rhs) {
		using std::swap;
		swap(data_, rhs.data_);
	}

public:
	base_type data_;
};

template <std::size_t I, std::size_t F>
std::ostream &operator<<(std::ostream &os, const Fixed<I,F> &f) {
	os << f.to_double();
	return os;
}

template <std::size_t I, std::size_t F>
const std::size_t Fixed<I,F>::fractional_bits;

template <std::size_t I, std::size_t F>
const std::size_t Fixed<I,F>::integer_bits;

template <std::size_t I, std::size_t F>
const std::size_t Fixed<I,F>::total_bits;

}
#endif

