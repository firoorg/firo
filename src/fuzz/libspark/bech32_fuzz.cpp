#include "../libspark/bech32.h"
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    std::string test_string = std::string((char *) buf);
    std::vector<uint8_t> test_vec;
    for(int i=0; i < len; i++) {
        test_vec.push_back(buf[i]);
    }
    bech32::Encoding test_enc = static_cast<bech32::Encoding>(rand() % 3);
    std::string test_string_res = std::string((char *) buf);
    test_string_res = bech32::encode(test_string, test_vec, test_enc);
    const std::string& test_const_string = test_string;
    bech32::decode(test_const_string);
    bech32::convertbits(test_vec, test_vec, len, len, (bool)(rand() % 2));
    return 0;
}