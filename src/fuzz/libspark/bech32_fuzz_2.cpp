#include "../../libspark/bech32.h"
#include "../FuzzedDataProvider.h"
#include <stdint.h>
#include <cassert>
#include <string>

// enum class Bech32EncodingForFuzzing {
//     INVALID,
//     BECH32,
//     BECH32M,
//     kMaxValue = BECH32M
// };

bool CaseInsensitiveEqual(const std::string& s1, const std::string& s2)
{
    if (s1.size() != s2.size()) return false;
    for (size_t i = 0; i < s1.size(); ++i) {
        char c1 = s1[i];
        if (c1 >= 'A' && c1 <= 'Z') c1 -= ('A' - 'a');
        char c2 = s2[i];
        if (c2 >= 'A' && c2 <= 'Z') c2 -= ('A' - 'a');
        if (c1 != c2) return false;
    }
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    FuzzedDataProvider fuzzed_data(buf, len);

    std::string test_string = fuzzed_data.ConsumeBytesAsString(len);

    const auto r1 = bech32::decode(test_string);
    if(r1.hrp.empty()) {
        assert(r1.encoding == bech32::Encoding::INVALID);
        assert(r1.data.empty());
    } else {
        assert(r1.encoding != bech32::Encoding::INVALID);
        const std::string reencoded = bech32::encode(r1.hrp, r1.data, r1.encoding);
        assert(CaseInsensitiveEqual(test_string, reencoded));
    }

    std::vector<uint8_t> input = fuzzed_data.ConsumeBytes<uint8_t>(len);
    std::vector<uint8_t> test_vec2 = fuzzed_data.ConsumeBytes<uint8_t>(len);
    int test_frombits = fuzzed_data.ConsumeIntegral<int>();
    int test_to_bits = fuzzed_data.ConsumeIntegral<int>();
    bool test_pad = fuzzed_data.ConsumeBool();
    bech32::convertbits(input, test_vec2, test_frombits, test_to_bits, test_pad);

    if(input.size() + 3 + 6 <= 90) {
        for (auto encoding: {bech32::Encoding::BECH32, bech32::Encoding::BECH32M}) {
            const std::string encoded = bech32::encode("bc",  input, encoding );
            assert(!encoded.empty());

            const auto r2 = bech32::decode(encoded);
            assert(r2.encoding == encoding);
            assert(r2.hrp == "bc");
            assert(r2.data == input);
        }
    }

    return 0;
}
