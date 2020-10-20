#ifndef ZCOIN_ELYSIUM_PROPERTY_H
#define ZCOIN_ELYSIUM_PROPERTY_H

#include <string>

#include <inttypes.h>

namespace elysium {

#define TEST_ECO_PROPERTY_1 (0x80000003UL)

// could probably also use: int64_t maxInt64 = std::numeric_limits<int64_t>::max();
// maximum numeric values from the spec:
#define MAX_INT_8_BYTES (9223372036854775807UL)

typedef uint8_t EcosystemId;
typedef uint32_t PropertyId;

enum class SigmaStatus : uint8_t {
    SoftDisabled    = 0,
    SoftEnabled     = 1,
    HardDisabled    = 2,
    HardEnabled     = 3
};

enum class LelantusStatus : uint8_t {
    SoftDisabled    = 0,
    SoftEnabled     = 1,
    HardDisabled    = 2,
    HardEnabled     = 3
};

bool IsEnabledFlag(SigmaStatus status);
bool IsEnabledFlag(LelantusStatus status);
bool IsRequireCreationFee(EcosystemId ecosystem);
bool IsRequireCreationFee(EcosystemId ecosystem, int block);
bool IsRequireCreationFee(EcosystemId ecosystem, int block, const std::string& network);

} // namespace elysium

#endif // ZCOIN_ELYSIUM_PROPERTY_H
