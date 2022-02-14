#include "../grootle.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

static std::vector<GroupElement> random_group_vector(const std::size_t n) {
    std::vector<GroupElement> result;
    result.resize(n);
    for (std::size_t i = 0; i < n; i++) {
        result[i].randomize();
    }
    return result;
}

BOOST_FIXTURE_TEST_SUITE(spark_grootle_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(batch)
{
    // Parameters
    const std::size_t n = 4;
    const std::size_t m = 3;
    const std::size_t N = (std::size_t) std::pow(n, m); // N = 64

    // Generators
    GroupElement H;
    H.randomize();
    std::vector<GroupElement> Gi = random_group_vector(n*m);
    std::vector<GroupElement> Hi = random_group_vector(n*m);

    // Commitments
    std::size_t commit_size = 60; // require padding
    std::vector<GroupElement> S = random_group_vector(commit_size);
    std::vector<GroupElement> V = random_group_vector(commit_size);

    // Generate valid commitments to zero
    std::vector<std::size_t> indexes = { 0, 1, 3, 59 };
    std::vector<std::size_t> sizes = { 60, 60, 59, 16 };
    std::vector<GroupElement> S1, V1;
    std::vector<std::vector<unsigned char>> roots;
    std::vector<Scalar> s, v;
    for (std::size_t index : indexes) {
        Scalar s_, v_;
        s_.randomize();
        v_.randomize();
        s.emplace_back(s_);
        v.emplace_back(v_);

        S1.emplace_back(S[index]);
        V1.emplace_back(V[index]);

        S[index] += H*s_;
        V[index] += H*v_;

        // Prepare random data in place of Merkle root
        Scalar temp;
        temp.randomize();
        std::vector<unsigned char> root;
        root.reserve(SCALAR_ENCODING);
        temp.serialize(root.data());
        roots.emplace_back(root);
    }

    // Prepare proving system
    Grootle grootle(H, Gi, Hi, n, m);
    std::vector<GrootleProof> proofs;

    for (std::size_t i = 0; i < indexes.size(); i++) {
        proofs.emplace_back();
        std::vector<GroupElement> S_(S.begin() + commit_size - sizes[i], S.end());
        std::vector<GroupElement> V_(V.begin() + commit_size - sizes[i], V.end());
        grootle.prove(
            indexes[i] - (commit_size - sizes[i]),
            s[i],
            S_,
            S1[i],
            v[i],
            V_,
            V1[i],
            roots[i],
            proofs.back()
        );

        // Verify single proof
        BOOST_CHECK(grootle.verify(S, S1[i], V, V1[i], roots[i], sizes[i], proofs.back()));
    }

    BOOST_CHECK(grootle.verify(S, S1, V, V1, roots, sizes, proofs));
}

BOOST_AUTO_TEST_CASE(invalid_batch)
{
    // Parameters
    const std::size_t n = 4;
    const std::size_t m = 3;
    const std::size_t N = (std::size_t) std::pow(n, m); // N = 64

    // Generators
    GroupElement H;
    H.randomize();
    std::vector<GroupElement> Gi = random_group_vector(n*m);
    std::vector<GroupElement> Hi = random_group_vector(n*m);

    // Commitments
    std::size_t commit_size = 60; // require padding
    std::vector<GroupElement> S = random_group_vector(commit_size);
    std::vector<GroupElement> V = random_group_vector(commit_size);

    // Generate valid commitments to zero
    std::vector<std::size_t> indexes = { 0, 1, 3, 59 };
    std::vector<std::size_t> sizes = { 60, 60, 59, 16 };
    std::vector<GroupElement> S1, V1;
    std::vector<std::vector<unsigned char>> roots;
    std::vector<Scalar> s, v;
    for (std::size_t index : indexes) {
        Scalar s_, v_;
        s_.randomize();
        v_.randomize();
        s.emplace_back(s_);
        v.emplace_back(v_);

        S1.emplace_back(S[index]);
        V1.emplace_back(V[index]);

        S[index] += H*s_;
        V[index] += H*v_;

        // Prepare random data in place of Merkle root
        Scalar temp;
        temp.randomize();
        std::vector<unsigned char> root;
        root.reserve(SCALAR_ENCODING);
        temp.serialize(root.data());
        roots.emplace_back(root);
    }

    // Prepare proving system
    Grootle grootle(H, Gi, Hi, n, m);
    std::vector<GrootleProof> proofs;

    for (std::size_t i = 0; i < indexes.size(); i++) {
        proofs.emplace_back();
        std::vector<GroupElement> S_(S.begin() + commit_size - sizes[i], S.end());
        std::vector<GroupElement> V_(V.begin() + commit_size - sizes[i], V.end());
        grootle.prove(
            indexes[i] - (commit_size - sizes[i]),
            s[i],
            S_,
            S1[i],
            v[i],
            V_,
            V1[i],
            roots[i],
            proofs.back()
        );
    }

    BOOST_CHECK(grootle.verify(S, S1, V, V1, roots, sizes, proofs));

    // Add an invalid proof
    proofs.emplace_back(proofs.back());
    S1.emplace_back(S1.back());
    V1.emplace_back(V1.back());
    S1.back().randomize();
    sizes.emplace_back(sizes.back());

    BOOST_CHECK(!grootle.verify(S, S1, V, V1, roots, sizes, proofs));
}

BOOST_AUTO_TEST_SUITE_END()

}