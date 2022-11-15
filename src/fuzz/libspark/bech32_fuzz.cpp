#include "../../libspark/bech32.h"
#include "../FuzzedDataProvider.h"
#include <stdint.h>
#include <cassert>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    FuzzedDataProvider fuzzed_data(buf, len);

    std::string test_string = fuzzed_data.ConsumeBytesAsString(len);
    std::vector<uint8_t> test_vec = fuzzed_data.ConsumeBytes<uint8_t>(len);
    bech32::Encoding test_enc = fuzzed_data.ConsumeEnum<bech32::Encoding>();
    std::string test_string_res;
    test_string_res = bech32::encode(test_string, test_vec, test_enc);
    bech32::DecodeResult dr;
    dr = bech32::decode(test_string_res);
    assert(dr.hrp == test_string);
    assert(dr.encoding == test_enc);
    assert(dr.data == test_vec);

    std::vector<uint8_t> test_vec1 = fuzzed_data.ConsumeBytes<uint8_t>(len);
    std::vector<uint8_t> test_vec2 = fuzzed_data.ConsumeBytes<uint8_t>(len);
    int test_frombits = fuzzed_data.ConsumeIntegral<int>();
    int test_to_bits = fuzzed_data.ConsumeIntegral<int>();
    bool test_pad = fuzzed_data.ConsumeBool();
    bech32::convertbits(test_vec1, test_vec2, test_frombits, test_to_bits, test_pad);
    return 0;
}