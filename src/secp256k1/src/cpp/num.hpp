#ifndef SECP256K1_CPP_NUM_HPP
#define SECP256K1_CPP_NUM_HPP

#include <algorithm>
#include <array>
#include <iterator>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <stddef.h>

namespace secp256k1 {

/**
 * Do a negation on a range that represents an integer in a big-endian form.
 *
 * @return true if negation success without overflow; otherwise false.
 **/
template<typename Iterator>
bool negate(Iterator first, Iterator last) {
    // first, flip all bits
    for (auto it = first; it != last; it++) {
        *it ^= 0xFF;
    }

    // second, increase integer by 1
    unsigned carry = 1;

    for (auto it = last; it-- != first && carry > 0;) {
        auto total = carry + *it;
        *it = total % 256;
        carry = total / 256;
    }

    // if there is remaining value to carry to the next byte that mean it is overflow
    return carry ? false : true;
}

/**
 * Convert an integer with each byte represent one digit in a binary form to another bases.
 *
 * @param from base of the number in each input digit, must be 2 to 256.
 * @param to base of the number in  each output digit, must be 2 to 256.
 *
 * @return A binary represents an integer with each digit in the converted base in a binary form.
 **/
template<typename Iterator, typename Allocator = std::allocator<typename std::iterator_traits<Iterator>::value_type>>
std::vector<typename std::iterator_traits<Iterator>::value_type, Allocator> convert_numeric_base(Iterator first, Iterator last, unsigned from, unsigned to) {
    if (from < 2 || from > 256 || to < 2 || to > 256) {
        throw std::invalid_argument("Invalid base number");
    }

    std::vector<typename std::iterator_traits<Iterator>::value_type, Allocator> result;

    for (auto it = first; it != last; it++) {
        unsigned carry = *it;

        for (size_t i = 0; i < result.size() || carry != 0; i++) {
            if (i == result.size()) {
                result.push_back(0);
            }

            unsigned total = carry + from * result[i];
            result[i] = total % to;
            carry = total / to;
        }
    }

    // the above operations produced a reversed order so we need to reverse it back
    std::reverse(result.begin(), result.end());

    return result;
}

/**
 * Parse a string that represent an 256-bits integer.
 *
 * @return An 256-bits integer in big-endian form.
 **/
template<typename Iterator>
std::array<unsigned char, 32> parse_int(Iterator first, Iterator last, unsigned base) {
    if (first == last) {
        throw std::invalid_argument("String is empty");
    }

    auto negative = (base != 16 && *first == '-');

    if (negative) {
        first++;
    }

    // get binary representation for each digit
    std::vector<unsigned char> bin;

    bin.reserve(std::distance(first, last));

    for (auto it = first; it != last; it++) {
        auto ch = *it;

        switch (base) {
        case 10:
            if (ch >= '0' && ch <= '9') {
                bin.push_back(ch - '0');
            } else {
                throw std::invalid_argument("String is not a valid base 10 integer");
            }
            break;
        case 16:
            if (ch >= '0' && ch <= '9') {
                bin.push_back(ch - '0');
            } else if (ch >= 'a' && ch <= 'f') {
                bin.push_back(10 + (ch - 'a'));
            } else if (ch >= 'A' && ch <= 'F') {
                bin.push_back(10 + (ch - 'A'));
            } else {
                throw std::invalid_argument("String is not a valid base 10 integer");
            }
            break;
        default:
            throw std::invalid_argument("The specified base is not supported");
        }
    }

    if (bin.empty()) {
        throw std::invalid_argument("String is not a valid integer");
    }

    // convert the binary representation of the integer to the big-endian form
    auto data = convert_numeric_base(bin.begin(), bin.end(), base, 256);

    if (data.size() > 32) {
        throw std::overflow_error("Value of the string is too large");
    } else if (data.size() < 32) {
        // prefixes with zeroes up to 256 bits
        data.insert(data.begin(), 32 - data.size(), 0);
    }

    if (negative) {
        negate(data.begin(), data.end());
    }

    // construct result
    std::array<unsigned char, 32> result;

    std::copy(data.begin(), data.end(), result.begin());

    return result;
}

/**
 * Convert an integer in a big-endian form into human-readable string.
 **/
template<typename Iterator>
std::string int_to_string(Iterator first, Iterator last, unsigned base, bool sign = true) {
    static const char digits_base10[] = "0123456789";
    static const char digits_base16[] = "0123456789abcdef";
    static const char *zero_base10 = "0";
    static const char *zero_base16 = "0x00";

    const char *digits, *zero;

    switch (base) {
    case 10:
        digits = digits_base10;
        zero = zero_base10;
        break;
    case 16:
        digits = digits_base16;
        zero = zero_base16;
        break;
    default:
        throw std::invalid_argument("Invalid base");
    }

    // make a copy of value due to we need to modify it
    std::vector<unsigned char> v;

    v.reserve(std::distance(first, last));

    std::copy(first, last, std::back_inserter(v));

    if (v.empty()) {
        return "";
    }

    // prefix with minus sign if it is negative
    std::stringstream s;

    if (sign && base != 16 && v[0] & 0x80) {
        s << '-';
        negate(v.begin(), v.end());
    }

    // get the binary representation of each digit
    auto bin = convert_numeric_base(v.begin(), v.end(), 256, base);

    if (bin.empty()) {
        s << zero;
    } else {
        for (auto v : bin) {
            s << digits[v];
        }
    }

    return s.str();
}

} // namespace secp256k1

#endif // SECP256K1_CPP_NUM_HPP
