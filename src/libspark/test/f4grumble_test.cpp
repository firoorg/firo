#include "../f4grumble.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

#include <random>

namespace spark {

BOOST_FIXTURE_TEST_SUITE(spark_f4grumble_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(complete)
{
    // Test all sizes of interest
    const int MIN_SIZE = 0; // sure, why not
    const int MAX_SIZE = 128;

    // Set up the randomizer
    std::random_device rand;
    std::uniform_int_distribution<int> dist(0, 0xFF);

    for (int i = MIN_SIZE; i <= MAX_SIZE; i++) {
        // Generate a random byte array
        std::vector<unsigned char> input;
        input.reserve(i);

        for (int j = 0; j < i; j++) {
            input.emplace_back(static_cast<unsigned char>(dist(rand)));
        }

        // Pick a network byte and set up the encoder 
        unsigned char network = static_cast<unsigned char>(dist(rand));
        F4Grumble grumble(network, i);

        // Encode the byte array
        std::vector<unsigned char> scrambled = grumble.encode(input);

        // Check that the length has not changed
        BOOST_CHECK_EQUAL(scrambled.size(), input.size());

        // Decode and check correctness
        std::vector<unsigned char> unscrambled = grumble.decode(scrambled);
        BOOST_CHECK_EQUAL_COLLECTIONS(unscrambled.begin(), unscrambled.end(), input.begin(), input.end());
    }
}

BOOST_AUTO_TEST_CASE(too_long)
{
    // This size is invalid!
    int size = F4Grumble::get_max_size() + 1;

    // Set up the randomizer
    std::random_device rand;
    std::uniform_int_distribution<int> dist(0, 0xFF);

    // Generate a random byte array
    std::vector<unsigned char> input;
    input.reserve(size);

    for (int j = 0; j < size; j++) {
        input.emplace_back(static_cast<unsigned char>(dist(rand)));
    }

    // Pick a network byte
    unsigned char network = static_cast<unsigned char>(dist(rand));

    // We can't even instantiate this!
    BOOST_CHECK_THROW(F4Grumble grumble(network, size), std::invalid_argument);

    // But pretend we can
    F4Grumble grumble(network, F4Grumble::get_max_size());

    // We should not be able to encode this...
    BOOST_CHECK_THROW(grumble.encode(input), std::invalid_argument);

    // ... nor decode it
    BOOST_CHECK_THROW(grumble.decode(input), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(bad_network)
{
    // Choose a large input size (such that collisions are unlikely)
    int size = F4Grumble::get_max_size();

    // Set up the randomizer
    std::random_device rand;
    std::uniform_int_distribution<int> dist(0, 0xFF);

    // Generate a random byte array
    std::vector<unsigned char> input;
    input.reserve(size);

    for (int j = 0; j < size; j++) {
        input.emplace_back(static_cast<unsigned char>(dist(rand)));
    }

    // Pick a network byte
    unsigned char network = static_cast<unsigned char>(dist(rand));

    // Pick an evil network byte
    unsigned char evil_network = ~network;
    BOOST_CHECK_NE(network, evil_network);

    // Encode with the original network
    F4Grumble grumble(network, size);
    std::vector<unsigned char> scrambled = grumble.encode(input);

    // Encode with the evil network
    F4Grumble evil_grumble(evil_network, size);
    std::vector<unsigned char> evil_scrambled = evil_grumble.decode(input);

    // They should be distinct
    bool equal = true;
    BOOST_CHECK_EQUAL(scrambled.size(), evil_scrambled.size());
    for (std::size_t i = 0; i < scrambled.size(); i++) {
        if (scrambled[i] != evil_scrambled[i]) {
            equal = false;
        }
    }
    BOOST_CHECK(!equal);
}

BOOST_AUTO_TEST_SUITE_END()

}