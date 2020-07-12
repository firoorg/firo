#include "lelantus_test_fixture.h"

#include "../range_prover.h"
#include "../range_verifier.h"

#include <boost/test/unit_test.hpp>

namespace lelantus {

BOOST_FIXTURE_TEST_SUITE(lelantus_range_proof_tests, LelantusTestingSetup)

BOOST_AUTO_TEST_CASE(prove_verify)
{
    uint64_t n = 64;
    uint64_t m = 4;
    secp_primitives::GroupElement g_gen, h_gen1, h_gen2;
    g_gen.randomize();
    h_gen1.randomize();
    h_gen2.randomize();

    //creating generators g, h vectors
    auto g_ = RandomizeGroupElements(n * m);
    auto h_ = RandomizeGroupElements(n * m);

    auto serials = RandomizeScalars(m);
    auto randoms = RandomizeScalars(m);

    std::vector<secp_primitives::Scalar> v_s;
    std::vector<secp_primitives::GroupElement> V;
    for(uint64_t i = 0; i < m; ++i){
        v_s.emplace_back(701 + i);
        V.push_back(g_gen * v_s.back() +  h_gen1 * randoms[i] + h_gen2 * serials[i]);
    }

    RangeProver<Scalar, GroupElement> rangeProver(g_gen, h_gen1, h_gen2, g_, h_, n);
    RangeProof<Scalar, GroupElement> proof;
    rangeProver.batch_proof(v_s, serials, randoms, proof);

    RangeVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> rangeVerifier(g_gen, h_gen1, h_gen2, g_, h_, n);
    BOOST_CHECK(rangeVerifier.verify_batch(V, proof));
}

BOOST_AUTO_TEST_CASE(out_of_range_notVerify)
{
    uint64_t n = 4;
    uint64_t m = 4;
    secp_primitives::GroupElement g_gen, h_gen1, h_gen2;
    g_gen.randomize();
    h_gen1.randomize();
    h_gen2.randomize();

    //creating generators g, h vectors
    auto g_ = RandomizeGroupElements(n * m);
    auto h_ = RandomizeGroupElements(n * m);

    auto randoms = RandomizeScalars(m);
    auto serials = RandomizeScalars(m);

    auto testF = [&] (std::vector<Scalar> const v_s) {
        std::vector<GroupElement> V;
        for (uint64_t i = 0; i < m; ++i) {
            V.push_back(g_gen * v_s[i] +  h_gen1 * randoms[i] + h_gen2 * serials[i]);
        }

        lelantus::RangeProver<Scalar, GroupElement> rangeProver(g_gen, h_gen1, h_gen2, g_, h_, n);
        lelantus::RangeProof<Scalar, GroupElement> proof;
        rangeProver.batch_proof(v_s, serials, randoms, proof);

        lelantus::RangeVerifier<Scalar, GroupElement> rangeVerifier(g_gen, h_gen1, h_gen2, g_, h_, n);
        BOOST_CHECK(!rangeVerifier.verify_batch(V, proof));
    };

    // All values are out of range
    std::vector<Scalar> vs;
    for(uint64_t i = 0; i < m; ++i){
        vs.emplace_back(17 + i);
    }
    testF(vs);

    // [0, 2 ^ n - 1]
    Scalar l(uint64_t(0));
    Scalar r((1 << n) - 1);

    // One value is out of range
    vs = {l, l + 1, r, r + 1};
    testF(vs);

    vs = {l - 1, l, r - 1, r};
    testF(vs);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus