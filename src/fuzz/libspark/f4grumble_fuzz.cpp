#include "../../libspark/f4grumble.h"
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    std::string test_string = std::string((char *) buf);
    std::vector<unsigned char> test_char_vec;
    test_char_vec.reserve(len);

    for (int i=0; i < len; i++) {
        test_char_vec.push_back(test_string[i]);
    }

    // too_long_size 
    bool exception_thrown_size = false;
    bool exception_thrown_encode = false;
    bool exception_thrown_decode = false;

    if(len > spark::F4Grumble::get_max_size()){

        try {
            spark::F4Grumble grumble(test_string[0], len);
        } catch(const std::exception& ) {
            exception_thrown_size = true;
        }
        assert(exception_thrown_size);

        spark::F4Grumble grumble = spark::F4Grumble(test_string[0], len);

        try {
            grumble.encode(test_char_vec);
        } catch (const std::exception& ) {
            exception_thrown_encode = true;
        }       

        assert(exception_thrown_encode);
        try {
            grumble.decode(test_char_vec);
        } catch (const std::exception& ) {
            exception_thrown_decode = true;
        }     
        assert(exception_thrown_decode);
        return 0;
    }

    spark::F4Grumble f4grumble_fuzz = spark::F4Grumble(test_string[0], len);
    std::vector<unsigned char> scrambled = f4grumble_fuzz.encode(test_char_vec);
    std::vector<unsigned char> unscrambled = f4grumble_fuzz.decode(scrambled);

    assert(scrambled.size() == test_char_vec.size());
    assert(unscrambled == test_char_vec);

    // bad_network
    unsigned char evil_network = ~test_string[0];
    assert(test_string[0] != evil_network);

    spark::F4Grumble evil_grumble(evil_network, len);
    //decoding with a different network
    std::vector<unsigned char> evil_unscrambled = evil_grumble.decode(scrambled);
    assert(evil_unscrambled.size() == scrambled.size());
    assert(evil_unscrambled != test_char_vec);
    return 0;
}