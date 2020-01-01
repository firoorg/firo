#ifdef HAVE_CONFIG_H
#include "../libsecp256k1-config.h"
#endif

#ifndef ENABLE_OPENSSL_TESTS
#error C++ tests required OpenSSL
#endif

#include <secp256k1.hpp>
#include <secp256k1_ecmult.hpp>
#include <secp256k1_group.hpp>
#include <secp256k1_scalar.hpp>

#include <openssl/rand.h>

#include <exception>
#include <iostream>
#include <ostream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#include <stddef.h>
#include <stdlib.h>

namespace {

struct assertion_failed : public std::runtime_error {
    assertion_failed(const std::string& reason) : runtime_error("Assertion failed: " + reason) {}
    assertion_failed(const std::string& expected, const std::string& actual) : assertion_failed("Expected = " + expected + ", Actual = " + actual) {}
};

template<typename Exception, typename Statement>
void assert_throw(const std::string& err, Statement statement) {
    try {
        statement();
        throw assertion_failed(err);
    } catch (Exception&) {
    }
}

void ecmult_multiple_multiplication() {
    static const size_t sizes[] = {1, 4, 20, 57, 136, 235, 1260, 4420, 7880, 16050, 10, 100, 1000, 5000};

    for (auto size : sizes) {
        std::vector<secp_primitives::GroupElement> gens;
        std::vector<secp_primitives::Scalar> scalars;
        secp_primitives::GroupElement expect;

        gens.reserve(size);
        scalars.reserve(size);

        for (size_t i = 0; i < size; i++) {
            gens.emplace_back();
            scalars.emplace_back();

            gens[i].randomize();
            scalars[i].randomize();

            expect += gens[i] * scalars[i];
        }

        secp_primitives::MultiExponent multiexponent(gens, scalars);
        auto actual = multiexponent.get_multiple();

        if (actual != expect) {
            throw assertion_failed(expect.tostring(), actual.tostring());
        }
    }
}

void ge_construct_default() {
    secp_primitives::GroupElement v;
    auto actual = v.tostring();

    if (actual != "O") {
        throw assertion_failed("O", actual);
    }
}

void ge_construct_from_string() {
    struct testcase {
        unsigned base;
        const char *x;
        const char *y;
    };

    static const testcase cases[] = {
        {
            .base = 10,
            .x = "9216064434961179932092223867844635691966339998754536116709681652691785432045",
            .y = "33986433546870000256104618635743654523665060392313886665479090285075695067131"
        },
        {
            .base = 10,
            .x = "50204771751011461524623624559944050110546921468100198079190811223951215371253",
            .y = "33986433546870000256104618635743654523665060392313886665479090285075695067131"
        },
        {
            .base = 10,
            .x = "7143275630583997983432964947790981761478339235433352888289260750805571589245",
            .y = "11700086115751491157288596384709446578503357013980342842588483174733971680454"
        },
        {
            .base = 10,
            .x = "7143275630583997983432964947790981761478339235433352888289260750805571589245",
            .y = "-11700086115751491157288596384709446578503357013980342842588483174733971680454"
        },
        {
            .base = 16,
            .x = "14601b8cdf761d4ed94554865ef0ef5c451e275f3dfc0a667fea04fa5a833bed",
            .y = "4b23a3c385114c40cb4fbf02d1a52f731b4edf61c247372d038470eea90edffb"
        },
        {
            .base = 16,
            .x = "6efee4d1ba231acfee2391dc5ded838cee89235af14b8a4f494e4734cb1323f5",
            .y = "4b23a3c385114c40cb4fbf02d1a52f731b4edf61c247372d038470eea90edffb"
        },
        {
            .base = 16,
            .x = "fcaf3630cd86c0b9dc6b122aeca20b065a14f861c291cd53a989f0e9fe1d47d",
            .y = "19de0399d7578731a20abff9283e66117f8cc02be53c4cc86eb5ac3378c36cc6"
        },
        {
            .base = 16,
            .x = "fcaf3630cd86c0b9dc6b122aeca20b065a14f861c291cd53a989f0e9fe1d47d",
            .y = "e621fc6628a878ce5df54006d7c199ee80733fd41ac3b337914a53cc873c933a"
        }
    };

    for (auto& c : cases) {
        secp_primitives::GroupElement v(c.x, c.y, c.base);
        auto expect = std::string("(") + c.x + ',' + c.y + ')';
        auto actual = v.tostring(c.base);

        if (actual != expect) {
            throw assertion_failed(expect, actual);
        }
    }
}

void ge_construct_from_other() {
    secp_primitives::GroupElement v;

    v.randomize();

    secp_primitives::GroupElement c(v);

    if (c != v) {
        throw assertion_failed(v.tostring(), c.tostring());
    }
}

void scalar_construct_default() {
    secp_primitives::Scalar v;
    auto actual = v.tostring();

    if (actual != "0") {
        throw assertion_failed("0", actual);
    }
}

void scalar_construct_from_int() {
    secp_primitives::Scalar v(50000);
    auto actual = v.tostring();

    if (actual != "50000") {
        throw assertion_failed("50000", actual);
    }
}

void scalar_construct_from_bin() {
    static const unsigned char zero[32] = { 0 };
    static const unsigned char one[32] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    static const unsigned char max_positive[32] = { 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    static const unsigned char max_negative[32] = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static const unsigned char overflow[32] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    std::string actual;

    if ((actual = secp_primitives::Scalar(zero).tostring()) != "0") {
        throw assertion_failed("0", actual);
    }

    if ((actual = secp_primitives::Scalar(one).tostring()) != "1") {
        throw assertion_failed("1", actual);
    }

    if ((actual = secp_primitives::Scalar(max_positive).tostring()) != "57896044618658097711785492504343953926634992332820282019728792003956564819967") {
        throw assertion_failed("57896044618658097711785492504343953926634992332820282019728792003956564819967", actual);
    }

    if ((actual = secp_primitives::Scalar(max_negative).tostring()) != "57896044618658097711785492504343953926634992332820282019728792003956564819968") {
        throw assertion_failed("57896044618658097711785492504343953926634992332820282019728792003956564819968", actual);
    }

    assert_throw<std::overflow_error>("Not overflowed", [] () {
        secp_primitives::Scalar v(overflow);
    });
}

void scalar_construct_from_other() {
    secp_primitives::Scalar v(99);
    secp_primitives::Scalar c(v);

    if (c != v) {
        throw assertion_failed(v.tostring(), c.tostring());
    }
}

void scalar_multiplication() {
    secp_primitives::Scalar v(50000), m(2), r;
    std::string actual;

    r = v * m;
    v *= m;
    v *= m;

    if ((actual = r.tostring()) != "100000") {
        throw assertion_failed("100000", actual);
    }

    if ((actual = v.tostring()) != "200000") {
        throw assertion_failed("200000", actual);
    }
}

} // unnamed namespace

int main(int argc, char *argv[]) {
    std::unordered_set<std::string> selected;
    secp256k1_context *ctx;
    size_t total;
    std::string current;

    for (int i = 1; i < argc; i++) {
        selected.insert(argv[i]);
    }

    // setup test environment
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    if (!ctx) {
        std::cerr << "Failed to create secp256k1's context." << std::endl;
        return EXIT_FAILURE;
    }

    try {
        secp256k1::initialize(ctx, [] (unsigned char *buf, size_t size) {
            while (!RAND_bytes(buf, size));
        });
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        secp256k1_context_destroy(ctx);
        return EXIT_FAILURE;
    }

    // execute tests
    struct testcase {
        const char *name;
        void (*func) ();
    };

    #define TESTCASE(func) { #func, func }

    static const testcase cases[] = {
        TESTCASE(ecmult_multiple_multiplication),
        TESTCASE(ge_construct_default),
        TESTCASE(ge_construct_from_string),
        TESTCASE(ge_construct_from_other),
        TESTCASE(scalar_construct_default),
        TESTCASE(scalar_construct_from_int),
        TESTCASE(scalar_construct_from_bin),
        TESTCASE(scalar_construct_from_other),
        TESTCASE(scalar_multiplication)
    };

    total = 0;

    try {
        for (auto& c : cases) {
            if (!selected.empty() && !selected.count(c.name)) {
                continue;
            }

            std::cout << "Running " << c.name << "..." << std::endl;

            current = c.name;
            c.func();

            total++;
        }
    } catch (std::exception& e) {
        std::cerr << '[' << current << "] " << e.what() << std::endl;
        secp256k1::terminate();
        secp256k1_context_destroy(ctx);
        return EXIT_FAILURE;
    }

    secp256k1::terminate();
    secp256k1_context_destroy(ctx);

    std::cout << std::endl << "Total tests: " << total << '.' << std::endl;

    return EXIT_SUCCESS;
}
