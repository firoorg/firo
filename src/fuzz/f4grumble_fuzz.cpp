#include "../libspark/f4grumble.h"
#include <stdint.h>

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    std::string test_string = std::string((char *) buf);
    std::vector<unsigned char> test_char_vec;
    for (int i=0; i < len; i++) {
        test_char_vec.push_back(test_string[i]);
    }
    spark::F4Grumble f4grumble_fuzz = spark::F4Grumble(test_string[0], len);
    f4grumble_fuzz.encode(test_char_vec);
    f4grumble_fuzz.decode(test_char_vec);
}