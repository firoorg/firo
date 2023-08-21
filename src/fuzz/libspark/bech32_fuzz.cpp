#include "../../libspark/bech32.h"
#include "../FuzzedDataProvider.h"
#include <stdint.h>
#include <cassert>

enum class Bech32EncodingForFuzzing {
    INVALID,
    BECH32,
    BECH32M,
    kMaxValue = BECH32M
};

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    FuzzedDataProvider fuzzed_data(buf, len);

    std::string test_string = fuzzed_data.ConsumeBytesAsString(len);
    std::vector<uint8_t> test_vec = fuzzed_data.ConsumeBytes<uint8_t>(len);
    Bech32EncodingForFuzzing test_encoding_helper = fuzzed_data.ConsumeEnum<Bech32EncodingForFuzzing>();
    bech32::Encoding test_encoding;
    switch (test_encoding_helper) {
        case Bech32EncodingForFuzzing::INVALID:
            test_encoding = bech32::Encoding::INVALID;
            break;
        case Bech32EncodingForFuzzing::BECH32:
            test_encoding = bech32::Encoding::BECH32;
            break;
        case Bech32EncodingForFuzzing::BECH32M:
            test_encoding = bech32::Encoding::BECH32M;
            break;
    }
    std::string test_string_res;
    test_string_res = bech32::encode(test_string, test_vec, test_encoding);
    bech32::DecodeResult dr;
    dr = bech32::decode(test_string_res);
    assert(dr.hrp == test_string);
    assert(dr.encoding == test_encoding);
    assert(dr.data == test_vec);

    std::vector<uint8_t> test_vec1 = fuzzed_data.ConsumeBytes<uint8_t>(len);
    std::vector<uint8_t> test_vec2 = fuzzed_data.ConsumeBytes<uint8_t>(len);
    int test_frombits = fuzzed_data.ConsumeIntegral<int>();
    int test_to_bits = fuzzed_data.ConsumeIntegral<int>();
    bool test_pad = fuzzed_data.ConsumeBool();
    bech32::convertbits(test_vec1, test_vec2, test_frombits, test_to_bits, test_pad);
    return 0;
}
