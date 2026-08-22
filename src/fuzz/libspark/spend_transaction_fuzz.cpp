#include "../../libspark/spend_transaction.h"

#include "../../streams.h"
#include "../../version.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    CDataStream stream(
        std::vector<unsigned char>(data, data + size),
        SER_NETWORK,
        PROTOCOL_VERSION);
    spark::SpendTransaction transaction(
        spark::Params::get_default(),
        spark::SpendTransactionVersion::V1,
        0);
    try {
        stream >> transaction;
        if (!stream.empty()) {
            return 0;
        }

        CDataStream canonical(SER_NETWORK, PROTOCOL_VERSION);
        canonical << transaction;
        if (canonical.size() != size ||
            !std::equal(
                canonical.begin(), canonical.end(), data,
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
