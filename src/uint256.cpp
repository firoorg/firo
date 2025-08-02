// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "uint256.h"

#include "utilstrencodings.h"

#include <stdio.h>
#include <string.h>

template <unsigned int BITS>
base_blob<BITS>::base_blob(const std::vector<unsigned char>& vch)
{
    assert(vch.size() == sizeof(data));
    memcpy(data, &vch[0], sizeof(data));
}

template<unsigned int BITS>
base_blob<BITS>::base_blob(const std::array<unsigned char, WIDTH>& vch)
{
    memcpy(data, &vch[0], sizeof(data));
}

template <unsigned int BITS>
std::string base_blob<BITS>::GetHex() const
{
    char psz[sizeof(data) * 2 + 1];
    for (unsigned int i = 0; i < sizeof(data); i++)
        snprintf(psz + i * 2, 3, "%02x", data[sizeof(data) - i - 1]);
    return std::string(psz, psz + sizeof(data) * 2);
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(const char* psz)
{
    memset(data, 0, sizeof(data));

    // skip leading spaces
    while (isspace(*psz))
        psz++;

    // skip 0x
    if (psz[0] == '0' && tolower(psz[1]) == 'x')
        psz += 2;

    // hex string to uint
    const char* pbegin = psz;
    while (::HexDigit(*psz) != -1)
        psz++;
    psz--;
    unsigned char* p1 = (unsigned char*)data;
    unsigned char* pend = p1 + WIDTH;
    while (psz >= pbegin && p1 < pend) {
        *p1 = ::HexDigit(*psz--);
        if (psz >= pbegin) {
            *p1 |= ((unsigned char)::HexDigit(*psz--) << 4);
            p1++;
        }
    }
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(const std::string& str)
{
    SetHex(str.c_str());
}

template <unsigned int BITS>
std::string base_blob<BITS>::ToString() const
{
    return (GetHex());
}

/* base_blob<BITS> from const char *.
 * This is a separate function because the constructor base_blob<BITS>(const char*) can result
 * in dangerously catching base_blob<BITS>(0).
 */
template <unsigned int BITS>
base_blob<BITS> base_blob<BITS>::uintS(const char *str) const
{
    base_blob<BITS> rv;
    rv.SetHex(str);
    return rv;
}
/* base_blob<BITS> from std::string.
 * This is a separate function because the constructor base_blob<BITS>(const std::string &str) can result
 * in dangerously catching base_blob<BITS>(0) via std::string(const char*).
 */
template <unsigned int BITS>
base_blob<BITS> base_blob<BITS>::uintS(const std::string& str) const
{
    base_blob<BITS> rv;
    rv.SetHex(str);
    return rv;
}

// Explicit instantiations for base_blob<160>
template base_blob<160>::base_blob(const std::vector<unsigned char>&);
template base_blob<160>::base_blob(const std::array<unsigned char, 20>&);
template std::string base_blob<160>::GetHex() const;
template std::string base_blob<160>::ToString() const;
template base_blob<160> base_blob<160>::uintS(const char *str) const;
template base_blob<160> base_blob<160>::uintS(const std::string& str) const;
template void base_blob<160>::SetHex(const char*);
template void base_blob<160>::SetHex(const std::string&);

// Explicit instantiations for base_blob<256>
template base_blob<256>::base_blob(const std::vector<unsigned char>&);
template base_blob<256>::base_blob(const std::array<unsigned char, 32>&);
template std::string base_blob<256>::GetHex() const;
template std::string base_blob<256>::ToString() const;
template base_blob<256> base_blob<256>::uintS(const char *str) const;
template base_blob<256> base_blob<256>::uintS(const std::string& str) const;
template void base_blob<256>::SetHex(const char*);
template void base_blob<256>::SetHex(const std::string&);

// Explicit instantiations for base_blob<512>
template base_blob<512>::base_blob(const std::vector<unsigned char>&);
template base_blob<512>::base_blob(const std::array<unsigned char, 64>&);
template std::string base_blob<512>::GetHex() const;
template std::string base_blob<512>::ToString() const;
template base_blob<512> base_blob<512>::uintS(const char *str) const;
template base_blob<512> base_blob<512>::uintS(const std::string& str) const;
template void base_blob<512>::SetHex(const char*);
template void base_blob<512>::SetHex(const std::string&);