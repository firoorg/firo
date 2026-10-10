#include "test/testutil.h"
#include "test/fixtures.h"

#include <boost/test/unit_test.hpp>
#include <crypto/progpow.h>
#include <crypto/progpow/firopow_test_vectors.hpp>
#include <crypto/progpow/lib/ethash/ethash-internal.hpp>
#include <crypto/progpow/include/ethash/progpow.hpp>
#include <crypto/progpow/helpers.hpp>
#include <hash.h>

#include <array>
#include <future>
#include <latch>

BOOST_FIXTURE_TEST_SUITE(firpow_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(firopow_hash_and_verify) {

    ethash::epoch_context_ptr context{nullptr, nullptr};
    for(auto& t : firopow_hash_test_cases) {

        const auto epoch_number{ethash::get_epoch_number(t.block_number)};
        if (!context || context->epoch_number != epoch_number) {
            context = ethash::create_epoch_context(epoch_number);
        }

        const ethash::hash256 header{to_hash256(t.header_hash_hex)};
        const ethash::hash256 boundary{to_hash256(t.boundary_hex)};
        const uint64_t nonce{std::stoull(t.nonce_hex, nullptr, 16)};
        ethash::hash256 mix_hash{to_hash256(t.mix_hash_hex)};
        const ethash::hash256 final_hash{to_hash256(t.final_hash_hex)};

        auto result{progpow::hash(*context, t.block_number, header, nonce)};
        BOOST_CHECK(ethash::is_less_or_equal(result.final_hash, boundary)); // Must be below boundary
        BOOST_CHECK(ethash::is_equal(result.final_hash, final_hash));       // Must be equal to test case final_hash
        BOOST_CHECK(ethash::is_equal(result.mix_hash, mix_hash));           // Must be equal to test case mix_hash

        // Run verification
        BOOST_CHECK(progpow::verify(*context, t.block_number, header, mix_hash, nonce, boundary));

        // Tamper mix and rerun verification
        ++mix_hash.bytes[3];
        BOOST_CHECK_EQUAL(progpow::verify(*context, t.block_number, header, mix_hash, nonce, boundary), false);

    }
}

BOOST_AUTO_TEST_CASE(firopow_prepared_header)
{
    const CProgPowHeader original{1, uint256S("12"), uint256S("34"), 123456, 0x207fffff, 1, 42, uint256()};
    std::array<CProgPowHeader, 9> headers;
    headers.fill(original);
    ++headers[1].nVersion;
    ++headers[2].hashPrevBlock.begin()[0];
    ++headers[3].hashMerkleRoot.begin()[0];
    ++headers[4].nTime;
    ++headers[5].nBits;
    ++headers[6].nHeight;
    ++headers[7].nNonce64;
    headers[8].mix_hash = uint256S("56");

    auto context = ethash::create_epoch_context(0);
    BOOST_REQUIRE(context);
    const auto original_hash = progpow_header_hash(original);
    for (size_t i = 0; i < headers.size(); ++i) {
        const auto& header = headers[i];
        // Encode the consensus header independently of CProgPowHeader's serializer.
        std::array<unsigned char, 80> bytes{};
        WriteLE32(bytes.data(), header.nVersion);
        std::copy(header.hashPrevBlock.begin(), header.hashPrevBlock.end(), bytes.begin() + 4);
        std::copy(header.hashMerkleRoot.begin(), header.hashMerkleRoot.end(), bytes.begin() + 36);
        WriteLE32(bytes.data() + 68, header.nTime);
        WriteLE32(bytes.data() + 72, header.nBits);
        WriteLE32(bytes.data() + 76, header.nHeight);
        uint256 serialized_hash;
        CHash256().Write(bytes.data(), bytes.size()).Finalize(serialized_hash.begin());
        const auto reference_header = to_hash256(serialized_hash.GetHex());
        const auto prepared_header = progpow_header_hash(header);
        BOOST_CHECK(ethash::is_equal(prepared_header, reference_header));
        BOOST_CHECK_EQUAL(ethash::is_equal(prepared_header, original_hash), i == 0 || i >= 7);

        const auto reference = progpow::hash(*context, header.nHeight, reference_header, header.nNonce64);
        uint256 prepared_mix, wrapper_mix;
        const auto prepared = progpow_hash_full(prepared_header, header.nHeight, header.nNonce64, prepared_mix);
        const auto wrapped = progpow_hash_full(header, wrapper_mix);
        BOOST_CHECK_EQUAL(prepared.GetHex(), to_hex(reference.final_hash));
        BOOST_CHECK_EQUAL(prepared_mix.GetHex(), to_hex(reference.mix_hash));
        BOOST_CHECK(prepared == wrapped);
        BOOST_CHECK(prepared_mix == wrapper_mix);
    }
}

BOOST_AUTO_TEST_CASE(firopow_concurrent_epochs)
{
    const std::array<const firopow_hash_test_case*, 2> cases{
        &firopow_hash_test_cases[4], &firopow_hash_test_cases[5]};
    BOOST_REQUIRE_EQUAL(cases[0]->block_number, ethash::epoch_length - 1);
    BOOST_REQUIRE_EQUAL(cases[1]->block_number, ethash::epoch_length);
    std::array<std::future<bool>, 4> workers;
    std::latch start{workers.size()};
    for (size_t worker = 0; worker < workers.size(); ++worker) {
        workers[worker] = std::async(std::launch::async, [&, worker] {
            start.arrive_and_wait();
            for (size_t offset = 0; offset < cases.size(); ++offset) {
                const auto& t = *cases[(worker + offset) % cases.size()];
                uint256 mix;
                const auto result = progpow_hash_full(to_hash256(t.header_hash_hex), t.block_number,
                    std::stoull(t.nonce_hex, nullptr, 16), mix);
                if (result.GetHex() != t.final_hash_hex || mix.GetHex() != t.mix_hash_hex)
                    return false;
            }
            return true;
        });
    }
    for (auto& worker : workers)
        BOOST_CHECK(worker.get());
}

BOOST_AUTO_TEST_SUITE_END()
