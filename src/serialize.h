// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SERIALIZE_H
#define BITCOIN_SERIALIZE_H

#include "compat/endian.h"

#include <algorithm>
#include <assert.h>
#include <ios>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdint.h>
#include <string>
#include <string.h>
#include <unordered_set>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>
#include <deque>
#include "prevector.h"
#include "definition.h"

#include <boost/optional.hpp>

#include "utils/enum.hpp"
#include "utils/traits.hpp"

static const unsigned int MAX_SIZE = 0x02000000;

/**
 * Dummy data type to identify deserializing constructors.
 *
 * By convention, a constructor of a type T with signature
 *
 *   template <typename Stream> T::T(deserialize_type, Stream& s)
 *
 * is a deserializing constructor, which builds the type by
 * deserializing it from s. If T contains const fields, this
 * is likely the only way to do so.
 */
struct deserialize_type {};
constexpr deserialize_type deserialize {};

#define ADD_DESERIALIZE_CTOR(CLASS_NAME)                              \
template <typename Stream>                                            \
CLASS_NAME(deserialize_type, Stream& s) {                             \
    Unserialize(s);                                                   \
}                                                                     \

/**
 * Used to bypass the rule against non-const reference to temporary
 * where it makes sense with wrappers such as CFlatData or CTxDB
 */
template<typename T>
inline T& REF(const T& val)
{
    return const_cast<T&>(val);
}

/**
 * Used to acquire a non-const pointer "this" to generate bodies
 * of const serialization operations from a template
 */
template<typename T>
inline T* NCONST_PTR(const T* val)
{
    return const_cast<T*>(val);
}

/**
 * Get begin pointer of vector (non-const version).
 * @note These functions avoid the undefined case of indexing into an empty
 * vector, as well as that of indexing after the end of the vector.
 */
template <typename V>
inline typename V::value_type* begin_ptr(V& v)
{
    return v.empty() ? NULL : &v[0];
}
/** Get begin pointer of vector (const version) */
template <typename V>
inline const typename V::value_type* begin_ptr(const V& v)
{
    return v.empty() ? NULL : &v[0];
}
/** Get end pointer of vector (non-const version) */
template <typename V>
inline typename V::value_type* end_ptr(V& v)
{
    return v.empty() ? NULL : (&v[0] + v.size());
}
/** Get end pointer of vector (const version) */
template <typename V>
inline const typename V::value_type* end_ptr(const V& v)
{
    return v.empty() ? NULL : (&v[0] + v.size());
}

/*
 * Lowest-level serialization and conversion.
 * @note Sizes of these types are verified in the tests
 */
template<typename Stream> inline void ser_writedata8(Stream &s, uint8_t obj)
{
    s.write((char*)&obj, 1);
}
template<typename Stream> inline void ser_writedata16(Stream &s, uint16_t obj)
{
    obj = htole16(obj);
    s.write((char*)&obj, 2);
}
template<typename Stream> inline void ser_writedata32(Stream &s, uint32_t obj)
{
    obj = htole32(obj);
    s.write((char*)&obj, 4);
}
template<typename Stream> inline void ser_writedata64(Stream &s, uint64_t obj)
{
    obj = htole64(obj);
    s.write((char*)&obj, 8);
}

template<typename Stream> inline void ser_writedata32be(Stream &s, uint32_t obj)
{
    obj = htobe32(obj);
    s.write((char*)&obj, 4);
}

template<typename Stream> inline uint8_t ser_readdata8(Stream &s)
{
    uint8_t obj;
    s.read((char*)&obj, 1);
    return obj;
}
template<typename Stream> inline uint16_t ser_readdata16(Stream &s)
{
    uint16_t obj;
    s.read((char*)&obj, 2);
    return le16toh(obj);
}
template<typename Stream> inline uint32_t ser_readdata32(Stream &s)
{
    uint32_t obj;
    s.read((char*)&obj, 4);
    return le32toh(obj);
}
template<typename Stream> inline uint64_t ser_readdata64(Stream &s)
{
    uint64_t obj;
    s.read((char*)&obj, 8);
    return le64toh(obj);
}
template<typename Stream> inline uint32_t ser_readdata32be(Stream &s)
{
    uint32_t obj;
    s.read((char*)&obj, 4);
    return be32toh(obj);
}
inline uint64_t ser_double_to_uint64(double x)
{
    union { double x; uint64_t y; } tmp;
    tmp.x = x;
    return tmp.y;
}
inline uint32_t ser_float_to_uint32(float x)
{
    union { float x; uint32_t y; } tmp;
    tmp.x = x;
    return tmp.y;
}
inline double ser_uint64_to_double(uint64_t y)
{
    union { double x; uint64_t y; } tmp;
    tmp.y = y;
    return tmp.x;
}
inline float ser_uint32_to_float(uint32_t y)
{
    union { float x; uint32_t y; } tmp;
    tmp.y = y;
    return tmp.x;
}


/////////////////////////////////////////////////////////////////
//
// Templates for serializing to anything that looks like a stream,
// i.e. anything that supports .read(char*, size_t) and .write(char*, size_t)
//

class CSizeComputer;

enum
{
    // primary actions
    SER_NETWORK         = (1 << 0),
    SER_DISK            = (1 << 1),
    SER_GETHASH         = (1 << 2),
};

#define READWRITE(obj)      (::SerReadWrite(s, (obj), ser_action))
#define READWRITEMANY(...)      (::SerReadWriteMany(s, ser_action, __VA_ARGS__))

/**
 * Implement three methods for serializable objects. These are actually wrappers over
 * "SerializationOp" template, which implements the body of each class' serialization
 * code. Adding "ADD_SERIALIZE_METHODS" in the body of the class causes these wrappers to be
 * added as members.
 */
#define ADD_SERIALIZE_METHODS                                         \
    template<typename Stream>                                         \
    void Serialize(Stream& s) const {                                 \
        NCONST_PTR(this)->SerializationOp(s, CSerActionSerialize());  \
    }                                                                 \
    template<typename Stream>                                         \
    void Unserialize(Stream& s) {                                     \
        SerializationOp(s, CSerActionUnserialize());                  \
    }

template<typename Stream> inline void Serialize(Stream& s, char a    ) { ser_writedata8(s, a); } // TODO Get rid of bare char
template<typename Stream> inline void Serialize(Stream& s, int8_t a  ) { ser_writedata8(s, a); }
template<typename Stream> inline void Serialize(Stream& s, uint8_t a ) { ser_writedata8(s, a); }
template<typename Stream> inline void Serialize(Stream& s, int16_t a ) { ser_writedata16(s, a); }
template<typename Stream> inline void Serialize(Stream& s, uint16_t a) { ser_writedata16(s, a); }
template<typename Stream> inline void Serialize(Stream& s, int32_t a ) { ser_writedata32(s, a); }
template<typename Stream> inline void Serialize(Stream& s, uint32_t a) { ser_writedata32(s, a); }
template<typename Stream> inline void Serialize(Stream& s, int64_t a ) { ser_writedata64(s, a); }
template<typename Stream> inline void Serialize(Stream& s, uint64_t a) { ser_writedata64(s, a); }
template<typename Stream> inline void Serialize(Stream& s, float a   ) { ser_writedata32(s, ser_float_to_uint32(a)); }
template<typename Stream> inline void Serialize(Stream& s, double a  ) { ser_writedata64(s, ser_double_to_uint64(a)); }

template<typename Stream> inline void Unserialize(Stream& s, char& a    ) { a = ser_readdata8(s); } // TODO Get rid of bare char
template<typename Stream> inline void Unserialize(Stream& s, int8_t& a  ) { a = ser_readdata8(s); }
template<typename Stream> inline void Unserialize(Stream& s, uint8_t& a ) { a = ser_readdata8(s); }
template<typename Stream> inline void Unserialize(Stream& s, int16_t& a ) { a = ser_readdata16(s); }
template<typename Stream> inline void Unserialize(Stream& s, uint16_t& a) { a = ser_readdata16(s); }
template<typename Stream> inline void Unserialize(Stream& s, int32_t& a ) { a = ser_readdata32(s); }
template<typename Stream> inline void Unserialize(Stream& s, uint32_t& a) { a = ser_readdata32(s); }
template<typename Stream> inline void Unserialize(Stream& s, int64_t& a ) { a = ser_readdata64(s); }
template<typename Stream> inline void Unserialize(Stream& s, uint64_t& a) { a = ser_readdata64(s); }
template<typename Stream> inline void Unserialize(Stream& s, float& a   ) { a = ser_uint32_to_float(ser_readdata32(s)); }
template<typename Stream> inline void Unserialize(Stream& s, double& a  ) { a = ser_uint64_to_double(ser_readdata64(s)); }

template<typename Stream> inline void Serialize(Stream& s, bool a)    { char f=a; ser_writedata8(s, f); }
template<typename Stream> inline void Unserialize(Stream& s, bool& a) { char f=ser_readdata8(s); a=f; }

template <typename T> size_t GetSerializeSize(const T& t, int nType, int nVersion = 0);
template <typename S, typename T> size_t GetSerializeSize(const S& s, const T& t);

/**
 * Enums
 */

using utils::concepts::Enum;

void Serialize(auto& s, Enum auto e) { Serialize(s, utils::to_underlying(e)); }

template <typename Stream, Enum E>
void Unserialize(Stream& s, E& e)
{
    std::underlying_type_t<E> u;
    Unserialize(s, u);
    e = static_cast<E>(u);
}

/**
 * Please note that Firo drops support for big-endian architectures and thus these functions are simple read/writes
 * It significantly improves MTP structures serialization performance
 */

template <typename ItemType>
using CArithType = typename std::enable_if<std::is_arithmetic<ItemType>::value>::type;

template<typename Stream, typename ItemType, int ArraySize, typename = CArithType<ItemType>>
inline void Serialize(Stream &s, const ItemType (&a) [ArraySize]) { s.write((const char *)&a, sizeof(a)); }

template<typename Stream, typename ItemType, int ArraySize, typename = CArithType<ItemType>>
inline void Unserialize(Stream &s, ItemType (&a)[ArraySize]) { s.read((char *)&a, sizeof(a)); }

template<typename Stream, typename ItemType, int ArraySize1, int ArraySize2, typename = CArithType<ItemType>>
inline void Serialize(Stream &s, const ItemType (&a)[ArraySize1][ArraySize2]) { s.write((const char *)&a, sizeof(a)); }

template<typename Stream, typename ItemType, int ArraySize1, int ArraySize2, typename = CArithType<ItemType>>
inline void Unserialize(Stream &s, ItemType (&a)[ArraySize1][ArraySize2]) { s.read((char *)&a, sizeof(a)); }

/**
 * Compact Size
 * size <  253        -- 1 byte
 * size <= USHRT_MAX  -- 3 bytes  (253 + 2 bytes)
 * size <= UINT_MAX   -- 5 bytes  (254 + 4 bytes)
 * size >  UINT_MAX   -- 9 bytes  (255 + 8 bytes)
 */
inline unsigned int GetSizeOfCompactSize(uint64_t nSize)
{
    if (nSize < 253)             return sizeof(unsigned char);
    else if (nSize <= std::numeric_limits<unsigned short>::max()) return sizeof(unsigned char) + sizeof(unsigned short);
    else if (nSize <= std::numeric_limits<unsigned int>::max())  return sizeof(unsigned char) + sizeof(unsigned int);
    else                         return sizeof(unsigned char) + sizeof(uint64_t);
}

inline void WriteCompactSize(CSizeComputer& os, uint64_t nSize);

template<typename Stream>
void WriteCompactSize(Stream& os, uint64_t nSize)
{
    if (nSize < 253)
    {
        ser_writedata8(os, nSize);
    }
    else if (nSize <= std::numeric_limits<unsigned short>::max())
    {
        ser_writedata8(os, 253);
        ser_writedata16(os, nSize);
    }
    else if (nSize <= std::numeric_limits<unsigned int>::max())
    {
        ser_writedata8(os, 254);
        ser_writedata32(os, nSize);
    }
    else
    {
        ser_writedata8(os, 255);
        ser_writedata64(os, nSize);
    }
    return;
}

template<typename Stream>
uint64_t ReadCompactSize(Stream& is)
{
    uint8_t chSize = ser_readdata8(is);
    uint64_t nSizeRet = 0;
    if (chSize < 253)
    {
        nSizeRet = chSize;
    }
    else if (chSize == 253)
    {
        nSizeRet = ser_readdata16(is);
        if (nSizeRet < 253)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    else if (chSize == 254)
    {
        nSizeRet = ser_readdata32(is);
        if (nSizeRet < 0x10000u)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    else
    {
        nSizeRet = ser_readdata64(is);
        if (nSizeRet < 0x100000000ULL)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    if (nSizeRet > (uint64_t)MAX_SIZE)
        throw std::ios_base::failure("ReadCompactSize(): size too large");
    return nSizeRet;
}

/**
 * Variable-length integers: bytes are a MSB base-128 encoding of the number.
 * The high bit in each byte signifies whether another digit follows. To make
 * sure the encoding is one-to-one, one is subtracted from all but the last digit.
 * Thus, the byte sequence a[] with length len, where all but the last byte
 * has bit 128 set, encodes the number:
 *
 *  (a[len-1] & 0x7F) + sum(i=1..len-1, 128^i*((a[len-i-1] & 0x7F)+1))
 *
 * Properties:
 * * Very small (0-127: 1 byte, 128-16511: 2 bytes, 16512-2113663: 3 bytes)
 * * Every integer has exactly one encoding
 * * Encoding does not depend on size of original integer type
 * * No redundancy: every (infinite) byte sequence corresponds to a list
 *   of encoded integers.
 *
 * 0:         [0x00]  256:        [0x81 0x00]
 * 1:         [0x01]  16383:      [0xFE 0x7F]
 * 127:       [0x7F]  16384:      [0xFF 0x00]
 * 128:  [0x80 0x00]  16511:      [0xFF 0x7F]
 * 255:  [0x80 0x7F]  65535: [0x82 0xFE 0x7F]
 * 2^32:           [0x8E 0xFE 0xFE 0xFF 0x00]
 */

template<typename I>
inline unsigned int GetSizeOfVarInt(I n)
{
    int nRet = 0;
    while(true) {
        nRet++;
        if (n <= 0x7F)
            break;
        n = (n >> 7) - 1;
    }
    return nRet;
}

template<typename I>
inline void WriteVarInt(CSizeComputer& os, I n);

template<typename Stream, typename I>
void WriteVarInt(Stream& os, I n)
{
    unsigned char tmp[(sizeof(n)*8+6)/7];
    int len=0;
    while(true) {
        tmp[len] = (n & 0x7F) | (len ? 0x80 : 0x00);
        if (n <= 0x7F)
            break;
        n = (n >> 7) - 1;
        len++;
    }
    do {
        ser_writedata8(os, tmp[len]);
    } while(len--);
}

template<typename Stream, typename I>
I ReadVarInt(Stream& is)
{
    I n = 0;
    while(true) {
        unsigned char chData = ser_readdata8(is);
        n = (n << 7) | (chData & 0x7F);
        if (chData & 0x80)
            n++;
        else
            return n;
    }
}

#define FLATDATA(obj) REF(CFlatData((char*)&(obj), (char*)&(obj) + sizeof(obj)))
#define FIXEDBITSET(obj, size) REF(CFixedBitSet(REF(obj), (size)))
#define DYNBITSET(obj) REF(CDynamicBitSet(REF(obj)))
#define FIXEDVARINTSBITSET(obj, size) REF(CFixedVarIntsBitSet(REF(obj), (size)))
#define AUTOBITSET(obj, size) REF(CAutoBitSet(REF(obj), (size)))
#define VARINT(obj) REF(WrapVarInt(REF(obj)))
#define COMPACTSIZE(obj) REF(CCompactSize(REF(obj)))
#define LIMITED_STRING(obj,n) REF(LimitedString< n >(REF(obj)))

/**
 * Wrapper for serializing arrays and POD.
 */
class CFlatData
{
protected:
    char* pbegin;
    char* pend;
public:
    CFlatData(void* pbeginIn, void* pendIn) : pbegin((char*)pbeginIn), pend((char*)pendIn) { }
    template <class T, class TAl>
    explicit CFlatData(std::vector<T,TAl> &v)
    {
        pbegin = (char*)v.data();
        pend = (char*)(v.data() + v.size());
    }
    template <unsigned int N, typename T, typename S, typename D>
    explicit CFlatData(prevector<N, T, S, D> &v)
    {
        pbegin = (char*)v.data();
        pend = (char*)(v.data() + v.size());
    }
    char* begin() { return pbegin; }
    const char* begin() const { return pbegin; }
    char* end() { return pend; }
    const char* end() const { return pend; }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s.write(pbegin, pend - pbegin);
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s.read(pbegin, pend - pbegin);
    }
};

class CFixedBitSet
{
protected:
    std::vector<bool>& vec;
    size_t size;

public:
    CFixedBitSet(std::vector<bool>& vecIn, size_t sizeIn) : vec(vecIn), size(sizeIn) {}

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        std::vector<unsigned char> vBytes((size + 7) / 8);
        size_t ms = std::min(size, vec.size());
        for (size_t p = 0; p < ms; p++)
            vBytes[p / 8] |= vec[p] << (p % 8);
        s.write((char*)vBytes.data(), vBytes.size());
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        vec.resize(size);

        std::vector<unsigned char> vBytes((size + 7) / 8);
        s.read((char*)vBytes.data(), vBytes.size());
        for (size_t p = 0; p < size; p++)
            vec[p] = (vBytes[p / 8] & (1 << (p % 8))) != 0;
        if (vBytes.size() * 8 != size) {
            size_t rem = vBytes.size() * 8 - size;
            uint8_t m = ~(uint8_t)(0xff >> rem);
            if (vBytes[vBytes.size() - 1] & m) {
                throw std::ios_base::failure("Out-of-range bits set");
            }
        }
    }
};

class CDynamicBitSet
{
protected:
    std::vector<bool>& vec;

public:
    explicit CDynamicBitSet(std::vector<bool>& vecIn) : vec(vecIn) {}

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        WriteCompactSize(s, vec.size());
        CFixedBitSet(REF(vec), vec.size()).Serialize(s);
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        vec.resize(ReadCompactSize(s));
        CFixedBitSet(vec, vec.size()).Unserialize(s);
    }
};

/**
 * Stores a fixed size bitset as a series of VarInts. Each VarInt is an offset from the last entry and the sum of the
 * last entry and the offset gives an index into the bitset for a set bit. The series of VarInts ends with a 0.
 */
class CFixedVarIntsBitSet
{
protected:
    std::vector<bool>& vec;
    size_t size;

public:
    CFixedVarIntsBitSet(std::vector<bool>& vecIn, size_t sizeIn) : vec(vecIn), size(sizeIn) {}

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        int32_t last = -1;
        for (int32_t i = 0; i < (int32_t)vec.size(); i++) {
            if (vec[i]) {
                WriteVarInt<Stream, uint32_t>(s, (uint32_t)(i - last));
                last = i;
            }
        }
        WriteVarInt(s, 0); // stopper
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        vec.assign(size, false);

        int32_t last = -1;
        while(true) {
            uint32_t offset = ReadVarInt<Stream, uint32_t>(s);
            if (offset == 0) {
                break;
            }
            int32_t idx = last + offset;
            if (idx >= (int32_t)size) {
                throw std::ios_base::failure("out of bounds index");
            }
            if (last != -1 && idx <= last) {
                throw std::ios_base::failure("offset overflow");
            }
            vec[idx] = true;
            last = idx;
        }
    }
};

/**
 * Serializes either as a CFixedBitSet or CFixedVarIntsBitSet, depending on which would give a smaller size
 */
class CAutoBitSet
{
protected:
    std::vector<bool>& vec;
    size_t size;

public:
    explicit CAutoBitSet(std::vector<bool>& vecIn, size_t sizeIn) : vec(vecIn), size(sizeIn) {}

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        assert(vec.size() == size);

        size_t size1 = ::GetSerializeSize(s, CFixedBitSet(vec, size));
        size_t size2 = ::GetSerializeSize(s, CFixedVarIntsBitSet(vec, size));

        if (size1 < size2) {
            ser_writedata8(s, 0);
            s << FIXEDBITSET(vec, vec.size());
        } else {
            ser_writedata8(s, 1);
            s << FIXEDVARINTSBITSET(vec, vec.size());
        }
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t isVarInts = ser_readdata8(s);
        if (isVarInts != 0 && isVarInts != 1) {
            throw std::ios_base::failure("invalid value for isVarInts byte");
        }

        if (!isVarInts) {
            s >> FIXEDBITSET(vec, size);
        } else {
            s >> FIXEDVARINTSBITSET(vec, size);
        }
    }
};

template<typename I>
class CVarInt
{
protected:
    I &n;
public:
    CVarInt(I& nIn) : n(nIn) { }

    template<typename Stream>
    void Serialize(Stream &s) const {
        WriteVarInt<Stream,I>(s, n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        n = ReadVarInt<Stream,I>(s);
    }
};

class CCompactSize
{
protected:
    uint64_t &n;
public:
    CCompactSize(uint64_t& nIn) : n(nIn) { }

    template<typename Stream>
    void Serialize(Stream &s) const {
        WriteCompactSize<Stream>(s, n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        n = ReadCompactSize<Stream>(s);
    }
};

template<size_t Limit>
class LimitedString
{
protected:
    std::string& string;
public:
    LimitedString(std::string& _string) : string(_string) {}

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        size_t size = ReadCompactSize(s);
        if (size > Limit) {
            throw std::ios_base::failure("String length limit exceeded");
        }
        string.resize(size);
        if (size != 0)
            s.read((char*)&string[0], size);
    }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        WriteCompactSize(s, string.size());
        if (!string.empty())
            s.write((char*)&string[0], string.size());
    }
};

template<typename I>
CVarInt<I> WrapVarInt(I& n) { return CVarInt<I>(n); }

/**
 * Forward declarations
 */
// TODO GV #Review: Why are these forward declarations needed at all? Most, if not all, can be eliminated given proper ordering of the definitions and liberal use of `if constexpr`.

/**
 *  string
 */
template<typename Stream, typename C> void Serialize(Stream& os, const std::basic_string<C>& str);
template<typename Stream, typename C> void Unserialize(Stream& is, std::basic_string<C>& str);

/**
 * prevector
 * prevectors of unsigned char are a special case and are intended to be serialized as a single opaque blob.
 */
template<typename Stream, unsigned int N, typename T> void Serialize_impl(Stream& os, const prevector<N, T>& v, const unsigned char&);
template<typename Stream, unsigned int N, typename T, typename V> void Serialize_impl(Stream& os, const prevector<N, T>& v, const V&);
template<typename Stream, unsigned int N, typename T> inline void Serialize(Stream& os, const prevector<N, T>& v);
template<typename Stream, unsigned int N, typename T> void Unserialize_impl(Stream& is, prevector<N, T>& v, const unsigned char&);
template<typename Stream, unsigned int N, typename T, typename V> void Unserialize_impl(Stream& is, prevector<N, T>& v, const V&);
template<typename Stream, unsigned int N, typename T> inline void Unserialize(Stream& is, prevector<N, T>& v);

/**
 * vector
 * vectors of unsigned char are a special case and are intended to be serialized as a single opaque blob.
 */

template<typename Stream, typename T, typename A>
requires(std::is_same_v<T, unsigned char>)  // TODO expand to include other trivial types, as appropriate
void Serialize_impl(Stream& os, const std::vector<T, A>& v);

template<typename Stream, typename T, typename A>
requires(!std::is_same_v<T, unsigned char>)
void Serialize_impl(Stream& os, const std::vector<T, A>& v);

template<typename Stream, typename T, typename A>
inline void Serialize(Stream& os, const std::vector<T, A>& v);

template<typename Stream, typename T, typename A>
requires(std::is_same_v<T, unsigned char>)  // TODO expand to include other trivial types, as appropriate
void Unserialize_impl(Stream& is, std::vector<T, A>& v);

template<typename Stream, typename T, typename A>
requires(!std::is_same_v<T, unsigned char>)
void Unserialize_impl(Stream& is, std::vector<T, A>& v);

template<typename Stream, typename T, typename A>
inline void Unserialize(Stream& is, std::vector<T, A>& v);

/**
 * pair
 */
template<typename Stream, typename K, typename T> void Serialize(Stream& os, const std::pair<K, T>& item);
template<typename Stream, typename K, typename T> void Unserialize(Stream& is, std::pair<K, T>& item);

/**
 * tuple
 */
template<typename Stream, int index, typename... Ts>
struct SerializeTuple {
    void operator() (Stream&s, std::tuple<Ts...>& t) {
        SerializeTuple<Stream, index - 1, Ts...>{}(s, t);
        s << std::get<index>(t);
    }
};

template<typename Stream, typename... Ts>
struct SerializeTuple<Stream, 0, Ts...> {
    void operator() (Stream&s, std::tuple<Ts...>& t) {
        s << std::get<0>(t);
    }
};

template<typename Stream, int index, typename... Ts>
struct DeserializeTuple {
    void operator() (Stream&s, std::tuple<Ts...>& t) {
        DeserializeTuple<Stream, index - 1, Ts...>{}(s, t);
        s >> std::get<index>(t);
    }
};

template<typename Stream, typename... Ts>
struct DeserializeTuple<Stream, 0, Ts...> {
    void operator() (Stream&s, std::tuple<Ts...>& t) {
        s >> std::get<0>(t);
    }
};


template<typename Stream, typename... Elements>
void Serialize(Stream& os, const std::tuple<Elements...>& item)
{
    const auto size = std::tuple_size<std::tuple<Elements...>>::value;
    SerializeTuple<Stream, size - 1, Elements...>{}(os, const_cast<std::tuple<Elements...>&>(item));
}

template<typename Stream, typename... Elements>
void Unserialize(Stream& is, std::tuple<Elements...>& item)
{
    const auto size = std::tuple_size<std::tuple<Elements...>>::value;
    DeserializeTuple<Stream, size - 1, Elements...>{}(is, item);
}

/**
 * shared_ptr
 */
template<typename Stream, typename T> void Serialize(Stream& os, const std::shared_ptr<const T>& p);
template<typename Stream, typename T> void Unserialize(Stream& is, std::shared_ptr<const T>& p);

/**
 * unique_ptr
 */
template<typename Stream, typename T> void Serialize(Stream& os, const std::unique_ptr<const T>& p);
template<typename Stream, typename T> void Unserialize(Stream& is, std::unique_ptr<const T>& p);

/**
 * optional
 */
template<typename Stream, typename T> void Serialize(Stream& os, const boost::optional<T>& p);
template<typename Stream, typename T> void Unserialize(Stream& is, boost::optional<T>& p);
template<typename Stream, typename T> void Serialize(Stream& os, const std::optional<T>& p);
template<typename Stream, typename T> void Unserialize(Stream& is, std::optional<T>& p);

/**
 * variant
 */
template<typename Stream, typename ... T> void Serialize(Stream& os, const std::variant<T...>& v);
template<typename Stream, typename ... T> void Unserialize(Stream& is, std::variant<T...>& v);

template<utils::concepts::variant V, typename Stream> V UnserializeVariant(Stream& is);

template<typename Stream> void Serialize(Stream& os, std::monostate) {} // no-op, by definition
template<typename Stream> void Unserialize(Stream& is, std::monostate) {} // no-op, by definition

/**
 * If none of the specialized versions above matched, default to calling member function.
 */
template<typename Stream, typename T>
inline auto Serialize(Stream& os, const T& a) -> decltype(a.Serialize(os))
{
    a.Serialize(os);
}

template<typename Stream, typename T>
inline auto Unserialize(Stream& is, T& a) -> decltype(a.Unserialize(is))
{
    a.Unserialize(is);
}





/**
 * string
 */
template<typename Stream, typename C>
void Serialize(Stream& os, const std::basic_string<C>& str)
{
    WriteCompactSize(os, str.size());
    if (!str.empty())
        os.write((char*)&str[0], str.size() * sizeof(str[0]));
}

template<typename Stream, typename C>
void Unserialize(Stream& is, std::basic_string<C>& str)
{
    unsigned int nSize = ReadCompactSize(is);
    str.resize(nSize);
    if (nSize != 0)
        is.read((char*)&str[0], nSize * sizeof(str[0]));
}



/**
 * prevector
 */
template<typename Stream, unsigned int N, typename T>
void Serialize_impl(Stream& os, const prevector<N, T>& v, const unsigned char&)
{
    WriteCompactSize(os, v.size());
    if (!v.empty())
        os.write((char*)&v[0], v.size() * sizeof(T));
}

template<typename Stream, unsigned int N, typename T, typename V>
void Serialize_impl(Stream& os, const prevector<N, T>& v, const V&)
{
    WriteCompactSize(os, v.size());
    for (typename prevector<N, T>::const_iterator vi = v.begin(); vi != v.end(); ++vi)
        ::Serialize(os, (*vi));
}

template<typename Stream, unsigned int N, typename T>
inline void Serialize(Stream& os, const prevector<N, T>& v)
{
    Serialize_impl(os, v, T());
}


template<typename Stream, unsigned int N, typename T>
void Unserialize_impl(Stream& is, prevector<N, T>& v, const unsigned char&)
{
    // Limit size per read so bogus size value won't cause out of memory
    v.clear();
    unsigned int nSize = ReadCompactSize(is);
    unsigned int i = 0;
    while (i < nSize)
    {
        unsigned int blk = std::min(nSize - i, (unsigned int)(1 + 4999999 / sizeof(T)));
        v.resize(i + blk);
        is.read((char*)&v[i], blk * sizeof(T));
        i += blk;
    }
}

template<typename Stream, unsigned int N, typename T, typename V>
void Unserialize_impl(Stream& is, prevector<N, T>& v, const V&)
{
    v.clear();
    unsigned int nSize = ReadCompactSize(is);
    unsigned int i = 0;
    unsigned int nMid = 0;
    while (nMid < nSize)
    {
        nMid += 5000000 / sizeof(T);
        if (nMid > nSize)
            nMid = nSize;
        v.resize(nMid);
        for (; i < nMid; i++)
            Unserialize(is, v[i]);
    }
}

template<typename Stream, unsigned int N, typename T>
inline void Unserialize(Stream& is, prevector<N, T>& v)
{
    Unserialize_impl(is, v, T());
}



/**
 * vector
 */
template<typename Stream, typename T, typename A>
requires(std::is_same_v<T, unsigned char>)  // TODO expand to include other trivial types, as appropriate
void Serialize_impl(Stream& os, const std::vector<T, A>& v)
{
    WriteCompactSize(os, v.size());
    if (!v.empty())
        os.write((char*)&v[0], v.size() * sizeof(T));
}

template<typename Stream, typename T, typename A>
requires(!std::is_same_v<T, unsigned char>)
void Serialize_impl(Stream& os, const std::vector<T, A>& v)
{
    WriteCompactSize(os, v.size());
    for (const T& t : v)
        ::Serialize(os, t);
}

template<typename Stream, typename T, typename A>
inline void Serialize(Stream& os, const std::vector<T, A>& v)
{
    Serialize_impl(os, v);
}


template<typename Stream, typename T, typename A>
requires(std::is_same_v<T, unsigned char>)  // TODO expand to include other trivial types, as appropriate
void Unserialize_impl(Stream& is, std::vector<T, A>& v)
{
    // Limit size per read so bogus size value won't cause out of memory
    v.clear();
    const unsigned int nSize = ReadCompactSize(is);
    unsigned int i = 0;
    while (i < nSize)
    {
        const unsigned int blk = std::min(nSize - i, (unsigned int)(1 + 4999999 / sizeof(T)));
        v.resize(i + blk);
        is.read((char*)&v[i], blk * sizeof(T));
        i += blk;
    }
}

template<typename Stream, typename T, typename A>
requires(!std::is_same_v<T, unsigned char>)
void Unserialize_impl(Stream& is, std::vector<T, A>& v)
{
    v.clear();
    const unsigned int nSize = ReadCompactSize(is);
    unsigned int i = 0;
    unsigned int nMid = 0;
    while (nMid < nSize)
    {
        nMid += 5000000 / sizeof(T);
        if (nMid > nSize)
            nMid = nSize;
        v.reserve(nMid);
        for (; i < nMid; i++)
            if constexpr (std::is_default_constructible_v<T>) {
                T t;
                Unserialize(is, t);
                v.push_back(std::move(t));
            }
            else if constexpr (utils::concepts::variant<T>)
                v.push_back(UnserializeVariant<T>(is));
            else
                v.emplace_back(deserialize, is);
    }
}

template<typename Stream, typename T, typename A>
inline void Unserialize(Stream& is, std::vector<T, A>& v)
{
    Unserialize_impl(is, v);
}



/**
 * pair
 */
template<typename Stream, typename K, typename T>
void Serialize(Stream& os, const std::pair<K, T>& item)
{
    Serialize(os, item.first);
    Serialize(os, item.second);
}

template<typename Stream, typename K, typename T>
void Unserialize(Stream& is, std::pair<K, T>& item)
{
    Unserialize(is, item.first);
    Unserialize(is, item.second);
}

/**
* 3 tuples
*/

template<typename Stream, typename T0, typename T1, typename T2>
void Serialize(Stream& os, const std::tuple<T0, T1, T2>& item)
{
    Serialize(os, std::get<0>(item));
    Serialize(os, std::get<1>(item));
    Serialize(os, std::get<2>(item));
}

template<typename Stream, typename T0, typename T1, typename T2>
void Unserialize(Stream& is, std::tuple<T0, T1, T2>& item)
{
    Unserialize(is, std::get<0>(item));
    Unserialize(is, std::get<1>(item));
    Unserialize(is, std::get<2>(item));
}

/**
* 4 tuples
*/
template<typename Stream, typename T0, typename T1, typename T2, typename T3>
void Serialize(Stream& os, const std::tuple<T0, T1, T2, T3>& item)
{
    Serialize(os, std::get<0>(item));
    Serialize(os, std::get<1>(item));
    Serialize(os, std::get<2>(item));
    Serialize(os, std::get<3>(item));
}

template<typename Stream, typename T0, typename T1, typename T2, typename T3>
void Unserialize(Stream& is, std::tuple<T0, T1, T2, T3>& item)
{
    Unserialize(is, std::get<0>(item));
    Unserialize(is, std::get<1>(item));
    Unserialize(is, std::get<2>(item));
    Unserialize(is, std::get<3>(item));
}

/**
 * map
 */

template <typename Stream, typename MapType, typename K = typename MapType::key_type, typename T = typename MapType::mapped_type>
void Serialize(Stream& os, MapType const &m)
{
    WriteCompactSize(os, m.size());
    for (typename MapType::const_iterator mi = m.begin(); mi != m.end(); ++mi)
        Serialize(os, (*mi));
}

template <typename Stream, typename MapType, typename K = typename MapType::key_type, typename T = typename MapType::mapped_type>
void Unserialize(Stream& is, MapType & m)
{
    m.clear();
    unsigned int nSize = ReadCompactSize(is);
    typename MapType::iterator mi = m.begin();
    for (unsigned int i = 0; i < nSize; i++)
    {
        std::pair<K, T> item;
        Unserialize(is, item);
        mi = m.insert(mi, item);
    }
}


/**
 * set
 */

template <typename SetType>
using CIsSet = typename std::enable_if<std::is_same<typename SetType::key_type, typename SetType::value_type>::value, SetType>::type;

template<typename Stream, typename SetType, typename Enabled = CIsSet<SetType>>
void Serialize(Stream& os, const SetType & m)
{
    WriteCompactSize(os, m.size());
    for (typename SetType::const_iterator it = m.begin(); it != m.end(); ++it)
        Serialize(os, (*it));
}

template<typename Stream, typename SetType, typename Enabled = CIsSet<SetType>>
void Unserialize(Stream& is, SetType & m)
{
    m.clear();
    unsigned int nSize = ReadCompactSize(is);
    typename SetType::iterator it = m.begin();
    for (unsigned int i = 0; i < nSize; i++)
    {
        typename SetType::key_type key;
        Unserialize(is, key);
        it = m.insert(it, key);
    }
}



/**
 * unique_ptr
 */
template<typename Stream, typename T> void
Serialize(Stream& os, const std::unique_ptr<const T>& p)
{
    Serialize(os, *p);
}

template<typename Stream, typename T>
void Unserialize(Stream& is, std::unique_ptr<const T>& p)
{
    p.reset(new T(deserialize, is));
}



/**
 * shared_ptr
 */
template<typename Stream, typename T>
void Serialize(Stream& os, const std::shared_ptr<const T>& p)
{
    Serialize(os, *p);
}

template<typename Stream, typename T>
void Unserialize(Stream& is, std::shared_ptr<const T>& p)
{
    p = std::make_shared<const T>(deserialize, is);
}



/**
 * optional
 */
template<typename Stream, typename T>
void Serialize(Stream& os, const boost::optional<T>& p)
{
    bool exists(p);
    Serialize(os, exists);
    if (exists)
        Serialize(os, *p);
}

template<typename Stream, typename T>
void Unserialize(Stream& is, boost::optional<T>& p)
{
    bool exists;
    Unserialize(is, exists);
    if (exists)
        p.emplace(deserialize, is);
}

template<typename Stream, typename T>
void Serialize(Stream& os, const std::optional<T>& p)
{
    bool exists(p);
    Serialize(os, exists);
    if (exists)
        Serialize(os, *p);
}

template<typename Stream, typename T>
void Unserialize(Stream& is, std::optional<T>& p)
{
    bool exists;
    Unserialize(is, exists);
    if (exists)
        if constexpr (std::is_default_constructible_v<T>) {
            T t;
            Unserialize(is, t);
            p = std::move(t);
        }
        else
            p.emplace(deserialize, is);
}

/**
 * variant
 */
template<typename Stream, typename ... T>
void Serialize(Stream& os, const std::variant<T...>& v)
{
    WriteCompactSize(os, v.index());
    std::visit([&os](const auto& t) { Serialize(os, t); }, v);
}

template<typename ... T, typename Stream>
std::variant<T...> UnserializeVariantOf(Stream& is)
{
    const auto index = ReadCompactSize(is);
    if (index >= sizeof...(T))
        throw std::ios_base::failure("out of bounds index while deserializing variant");    // TODO details
    using optvar_t = std::optional< std::variant<T...> >;
    const auto f = [index, &is] < typename U, std::size_t I > (optvar_t& x) {
       if ( I == index ) {
           assert(!x);
           if constexpr (std::is_default_constructible_v<U>) {
               U u;
               Unserialize(is, u);
               x = u;
           }
           else
               x = U(deserialize, is);
       }
    };
    optvar_t v;
    const auto deserializer = [&] < std::size_t ... I >( const std::index_sequence<I...> ) { ( f.template operator()<T, I>(v), ... ); };
    deserializer(std::index_sequence_for<T...>());
    assert(v);
    return std::move(*v);
}

template<utils::concepts::variant V, typename Stream>
V UnserializeVariant(Stream& is)
{
#if 0 // TODO consider removing
    const auto f = [&]<typename... T> { return UnserializeVariantOf<T...>(is); };
    return utils::variant_types_unpacker<V>()(f);
#endif
   return [&is]< typename... T >( std::type_identity< std::variant< T... > > ) { return UnserializeVariantOf< T... >( is ); }( std::type_identity< V >() );
}

template<typename Stream, typename ... T>
void Unserialize(Stream& is, std::variant<T...>& v)
{
    v = UnserializeVariantOf<T...>(is);
}


/**
 * Support for ADD_SERIALIZE_METHODS and READWRITE macro
 */
struct CSerActionSerialize
{
    constexpr bool ForRead() const { return false; }
};
struct CSerActionUnserialize
{
    constexpr bool ForRead() const { return true; }
};

template<typename Stream, typename T>
inline void SerReadWrite(Stream& s, const T& obj, CSerActionSerialize ser_action)
{
    ::Serialize(s, obj);
}

template<typename Stream, typename T>
inline void SerReadWrite(Stream& s, T& obj, CSerActionUnserialize ser_action)
{
    ::Unserialize(s, obj);
}









/* ::GetSerializeSize implementations
 *
 * Computing the serialized size of objects is done through a special stream
 * object of type CSizeComputer, which only records the number of bytes written
 * to it.
 *
 * If your Serialize or SerializationOp method has non-trivial overhead for
 * serialization, it may be worthwhile to implement a specialized version for
 * CSizeComputer, which uses the s.seek() method to record bytes that would
 * be written instead.
 */
class CSizeComputer
{
protected:
    size_t nSize;

    const int nType;
    const int nVersion;
public:
    CSizeComputer(int nTypeIn, int nVersionIn) : nSize(0), nType(nTypeIn), nVersion(nVersionIn) {}

    void write(const char *psz, size_t _nSize)
    {
        this->nSize += _nSize;
    }

    /** Pretend _nSize bytes are written, without specifying them. */
    void seek(size_t _nSize)
    {
        this->nSize += _nSize;
    }

    template<typename T>
    CSizeComputer& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return (*this);
    }

    size_t size() const {
        return nSize;
    }

    int GetVersion() const { return nVersion; }
    int GetType() const { return nType; }
};

template<typename Stream>
void SerializeMany(Stream& s)
{
}

template<typename Stream, typename Arg>
void SerializeMany(Stream& s, Arg&& arg)
{
    ::Serialize(s, std::forward<Arg>(arg));
}

template<typename Stream, typename Arg, typename... Args>
void SerializeMany(Stream& s, Arg&& arg, Args&&... args)
{
    ::Serialize(s, std::forward<Arg>(arg));
    ::SerializeMany(s, std::forward<Args>(args)...);
}

template<typename Stream>
inline void UnserializeMany(Stream& s)
{
}

template<typename Stream, typename Arg>
inline void UnserializeMany(Stream& s, Arg& arg)
{
    ::Unserialize(s, arg);
}

template<typename Stream, typename Arg, typename... Args>
inline void UnserializeMany(Stream& s, Arg& arg, Args&... args)
{
    ::Unserialize(s, arg);
    ::UnserializeMany(s, args...);
}

template<typename Stream, typename... Args>
inline void SerReadWriteMany(Stream& s, CSerActionSerialize ser_action, Args&&... args)
{
    ::SerializeMany(s, std::forward<Args>(args)...);
}

template<typename Stream, typename... Args>
inline void SerReadWriteMany(Stream& s, CSerActionUnserialize ser_action, Args&... args)
{
    ::UnserializeMany(s, args...);
}

template<typename I>
inline void WriteVarInt(CSizeComputer &s, I n)
{
    s.seek(GetSizeOfVarInt<I>(n));
}

inline void WriteCompactSize(CSizeComputer &s, uint64_t nSize)
{
    s.seek(GetSizeOfCompactSize(nSize));
}

template <typename T>
size_t GetSerializeSize(const T& t, int nType, int nVersion)
{
    return (CSizeComputer(nType, nVersion) << t).size();
}

template <typename S, typename T>
size_t GetSerializeSize(const S& s, const T& t)
{
    return (CSizeComputer(s.GetType(), s.GetVersion()) << t).size();
}

#endif // BITCOIN_SERIALIZE_H
