#ifndef EXODUS_CONVERT_H
#define EXODUS_CONVERT_H

#include <stdint.h>

namespace exodus
{

/**
 * Converts numbers to 64 bit wide unsigned integer whereby
 * any signedness is ignored. If absolute value of the number
 * is greater or equal than .5, then the result is rounded
 * up and down otherwise.
 */
uint64_t rounduint64(double);

/**
 * Swaps byte order on little-endian systems and does nothing
 * otherwise. swapByteOrder cycles on LE systems.
 */
void swapByteOrder16(uint16_t&);
void swapByteOrder32(uint32_t&);
void swapByteOrder64(uint64_t&);

template<typename T>
void swapByteOrder(T& t)
{
  switch (sizeof(t)) {
  case sizeof(uint16_t):
    swapByteOrder16(reinterpret_cast<uint16_t &>(t));
    break;
  case sizeof(uint32_t):
    swapByteOrder32(reinterpret_cast<uint32_t &>(t));
    break;
  case sizeof(uint64_t):
    swapByteOrder64(reinterpret_cast<uint64_t &>(t));
    break;
  }
}

}


#endif // EXODUS_CONVERT_H
