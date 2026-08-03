#include "key.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "spark/state.h"
#include "streams.h"
#include "version.h"

#include <cstddef>
#include <cstdint>
#include <new>
#include <vector>

namespace {
ECCVerifyHandle verifyHandle;
constexpr std::size_t MAX_FUZZ_TRANSACTION_SIZE = 4 * 1024 * 1024;
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size)
{
    if (size > MAX_FUZZ_TRANSACTION_SIZE) {
        return 0;
    }

    try {
        CDataStream stream(
            std::vector<unsigned char>(data, data + size),
            SER_NETWORK,
            PROTOCOL_VERSION);
        CMutableTransaction mutableTransaction;
        stream >> mutableTransaction;
        if (!stream.empty()) {
            return 0;
        }

        const CTransaction transaction(mutableTransaction);
        if (transaction.IsSparkSpend()) {
            spark::ParseSparkSpend(transaction);
        }
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
    }
    return 0;
}
