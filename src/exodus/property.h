#ifndef ZCOIN_EXODUS_PROPERTY_H
#define ZCOIN_EXODUS_PROPERTY_H

#include <cinttypes>

namespace exodus {

#define TEST_ECO_PROPERTY_1 (0x80000003UL)

// could probably also use: int64_t maxInt64 = std::numeric_limits<int64_t>::max();
// maximum numeric values from the spec:
#define MAX_INT_8_BYTES (9223372036854775807UL)

typedef std::uint32_t PropertyId;

enum class SigmaStatus : uint8_t {
    SoftDisabled    = 0,
    SoftEnabled     = 1,
    HardDisabled    = 2,
    HardEnabled     = 3
};

bool IsEnabledFlag(SigmaStatus status);

}

#endif // ZCOIN_EXODUS_PROPERTY_H
