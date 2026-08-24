#include "../../libspark/spend_transaction.h"

#include "../../streams.h"
#include "../../version.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <vector>

// Exercises the bounded inner V2 wire parser and canonical reserializer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return 0;
    }

    const std::size_t expected_outputs =
        1 + (data[0] % spark::MAX_SPARK_V2_OUTPUTS);
    CDataStream stream(
        std::vector<unsigned char>(data + 1, data + size),
        SER_NETWORK,
        PROTOCOL_VERSION);
    spark::SpendTransaction transaction(
        spark::Params::get_default(),
        spark::SpendTransactionVersion::V2,
        expected_outputs);
    try {
        stream >> transaction;
        if (!stream.empty()) {
            return 0;
        }
        CDataStream canonical(SER_NETWORK, PROTOCOL_VERSION);
        canonical << transaction;
        if (canonical.size() != size - 1 ||
            !std::equal(
                canonical.begin(), canonical.end(), data + 1,
                [](char left, uint8_t right) {
                    return static_cast<uint8_t>(left) == right;
                })) {
            std::abort();
        }
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
    }
    return 0;
}
