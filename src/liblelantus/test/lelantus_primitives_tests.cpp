#include "lelantus_test_fixture.h"

#include "../lelantus_primitives.h"

#include "../../test/test_bitcoin.h"
#include "../../utilstrencodings.h"

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/hex.hpp>

namespace lelantus {

typedef LelantusPrimitives<Scalar, GroupElement> Primitives;

BOOST_FIXTURE_TEST_SUITE(lelantus_primitives_tests, LelantusTestingSetup)

BOOST_AUTO_TEST_CASE(generate_challenge)
{
    auto gs0 = GenerateGroupElements(10);
    auto gs1 = GenerateGroupElements(5);

    secp_primitives::Scalar s0, s1;
    Primitives::generate_challenge(gs0, s0);
    Primitives::generate_challenge(gs1, s1);

    BOOST_CHECK_EQUAL(
        "7486c200ca76a53a40715a64982705276181c4c8fe6335425607ddc696ca739f",
        s0.GetHex());

    BOOST_CHECK_EQUAL(
        "b2eb32c975a2bde90afa85812aea832744f7905759b4edf56b10cf420f848b1e",
        s1.GetHex());
}

BOOST_AUTO_TEST_CASE(multi_commit)
{
    auto h = GenerateGroupElements(3);
    auto g = h.back();
    h.resize(2);

    std::vector<Scalar> exps;
    for (int i = 0; i != 3; i++) {
        exps.emplace_back(i + 10);
    }
    auto r = exps.back();
    exps.resize(2);

    GroupElement out;
    Primitives::commit(g, h, exps, r, out);

    BOOST_CHECK_EQUAL(
        "(6185bcfc7e56b1a66b6a64176c5474befa11047acac0d96043399d729c2523e4,"
        "4d1930b2ef5d097e0c6f390f7b3818419131a43a15b5d699c9ece70ef162683a)",
        out.GetHex());
}

BOOST_AUTO_TEST_CASE(commit)
{
    auto gs = GenerateGroupElements(2);
    auto g = gs[0];
    auto h = gs[1];

    Scalar m(10), r(11);

    auto commitment = Primitives::commit(g, m, h, r);
    BOOST_CHECK_EQUAL(
        "(ef2c9e683a4985e7435993d7b6637254aa5acbd20501aa896815976d35d7bb6e,"
        "5e84e985869a661f9241dfff097c28eb9deda97fc945f27eadf8adea8c6ae929)",
        commitment.GetHex());
}

BOOST_AUTO_TEST_CASE(double_commit)
{
    auto gs = GenerateGroupElements(3);
    auto g = gs[0];
    auto hV = gs[1];
    auto hR = gs[2];

    Scalar m(10), v(11), r(12);

    auto commitment = Primitives::double_commit(g, m, hV, v, hR, r);
    BOOST_CHECK_EQUAL(
        "(6185bcfc7e56b1a66b6a64176c5474befa11047acac0d96043399d729c2523e4,"
        "4d1930b2ef5d097e0c6f390f7b3818419131a43a15b5d699c9ece70ef162683a)",
        commitment.GetHex());
}

BOOST_AUTO_TEST_CASE(convert_to_sigma)
{
    uint64_t n = 4, m = 6;
    uint64_t num =
        2 + n + 0 +
        3 * std::pow(n, 3) +
        2 * std::pow(n, 4) +
        1 * std::pow(n, 5);

    std::vector<uint8_t> rawExpected =
    {
        0, 0, 1, 0,
        0, 1, 0, 0,
        1, 0, 0, 0,
        0, 0, 0, 1,
        0, 0, 1, 0,
        0, 1, 0, 0
    };

    Scalar one(1), zero(uint64_t(0));
    std::vector<Scalar> expected;
    expected.reserve(rawExpected.size());
    for (auto const &d : rawExpected) {
        expected.push_back(d == 0 ? zero : one);
    }

    std::vector<Scalar> out;
    Primitives::convert_to_sigma(num, n, m, out);

    BOOST_CHECK(expected == out);
}

BOOST_AUTO_TEST_CASE(convert_to_nal)
{
    uint64_t n = 4, m = 6;
    uint64_t num =
        2 + 3 * n + 0 +
        1 * std::pow(n, 3) +
        2 * std::pow(n, 4);

    std::vector<uint64_t> expected = {2, 3, 0, 1, 2, 0};
    auto result = Primitives::convert_to_nal(num, n, m);

    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected.begin(), expected.end(),
        result.begin(), result.end());
}

BOOST_AUTO_TEST_CASE(generate_lelantus_challange)
{
    std::vector<SigmaPlusProof<Scalar, GroupElement>> proofs(2);
    auto gs = GenerateGroupElements(proofs.size() * 8);
    auto it = gs.begin();

    for (auto &proof : proofs) {
        proof.A_ = *it++;
        proof.B_ = *it++;
        proof.C_ = *it++;
        proof.D_ = *it++;
        proof.Gk_ = {*it++, *it++};
        proof.Qk = {*it++, *it++};
    }

    Scalar out;
    Primitives::generate_Lelantus_challange(proofs, out);

    BOOST_CHECK_EQUAL(
        "0739d8484b29d53410510c38ffd5b6a43187fa0775175f97d12c61e81147245b",
        out.GetHex());
}

BOOST_AUTO_TEST_CASE(new_factor)
{
    std::vector<Scalar> coefs = {6, 5, 4, 3, 2, 1};
    Scalar x = 2, a = 4;

    std::vector<Scalar> expected = {24, 32, 26, 20, 14, 8, 2};

    Primitives::new_factor(x, a, coefs);

    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected.begin(), expected.end(),
        coefs.begin(), coefs.end());
}

BOOST_AUTO_TEST_CASE(commit_two_generators)
{
    auto items = GenerateGroupElements(5);
    auto h = items[0];
    std::vector<GroupElement> g_(items.begin() + 1, items.begin() + 3);
    std::vector<GroupElement> h_(items.begin() + 3, items.end());

    Scalar exp = 10;
    std::vector<Scalar> l = {Scalar(11), Scalar(12)};
    std::vector<Scalar> r = {Scalar(13), Scalar(14)};

    GroupElement out;
    Primitives::commit(h, exp, g_, l, h_, r, out);

    BOOST_CHECK_EQUAL(
        "(ab6a35cc172ce38d52ad2b5eeda2de4d2c22d18a7dd8bfadbcb839c368a1d8d,75e7dd7a4e098d5eb8f46ad57eb72da067ed826d307d4bff9faea1715d58289a)",
        out.GetHex());
}

BOOST_AUTO_TEST_CASE(scalar_dot_product)
{
    Scalar x0 = 10, x1 = 20, x2 = 30;
    Scalar y0 = 11, y1 = 21, y2 = 31;

    std::vector<Scalar> x = {x0, x1, x2};
    std::vector<Scalar> y = {y0, y1, y2};

    auto result = Primitives::scalar_dot_product(x.begin(), x.end(), y.begin(), y.end());

    BOOST_CHECK_EQUAL(x0 * y0 + x1 * y1 + x2 * y2, result);
}

BOOST_AUTO_TEST_CASE(g_prime)
{
    auto gs = GenerateGroupElements(4);
    Scalar x(10);

    auto raw0 = ParseHex("1eddd58977aab5a476bc82ea0f48e11fa5a79419476ddfe5b764540eac7947000100");
    auto raw1 = ParseHex("72771902e20dda39200116e694385fc520b82150fcf8cff12671cdcff68e23f70000");
    std::vector<GroupElement> expected(2);
    expected[0].deserialize(raw0.data());
    expected[1].deserialize(raw1.data());

    std::vector<GroupElement> result;
    Primitives::g_prime(gs, x, result);

    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(), result.begin(), result.end());
}

BOOST_AUTO_TEST_CASE(h_prime)
{
    auto h = GenerateGroupElements(4);
    Scalar x(10);

    auto raw0 = ParseHex("289d10cc8571a829839c9df9607fc5cc38c06f4d4a0dba069fc384bffc8ae3560000");
    auto raw1 = ParseHex("ceb87b21b9be8161c6200bbd54931582d586e4075819f601bb685b26e7707e280100");
    std::vector<GroupElement> expected(2);
    expected[0].deserialize(raw0.data());
    expected[1].deserialize(raw1.data());

    std::vector<GroupElement> result;
    Primitives::h_prime(h, x, result);

    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(), result.begin(), result.end());
}

BOOST_AUTO_TEST_CASE(p_prime)
{
    auto gs = GenerateGroupElements(3);
    auto P = gs[0];
    auto L = gs[1];
    auto R = gs[2];

    Scalar x(10);

    auto result = Primitives::p_prime(P, L, R, x);

    auto raw = ParseHex("7fb5138c96f0e994eb2fca28480e5d6e572fa07ed1b49b6d87d1e475164cac900100");
    GroupElement expected;
    expected.deserialize(raw.data());

    BOOST_CHECK_EQUAL(expected, result);
}

BOOST_AUTO_TEST_CASE(delta)
{
    Scalar y = 100, z = 200, one = 1, two = 2;
    uint64_t n = 4, m = 6;

    auto y_ = (y.exponent(m * n) - 1) * ((y - 1).inverse()); // 1 + y + y^2 + ... + y^(mn - 1)
    auto z_ = (z.exponent(m + 3) - 1) * ((z - 1).inverse()) - 1 - z - z * z; // 1 + z + z^2 + z^3 + ... + z^m+2 - 1 - z - z^2
    auto two_ = (two.exponent(n) - 1); // 1 + 2 + 2^2 + ... + 2^(n-1)

    auto expected = (z - z * z) * y_ - z_ * two_;
    auto result = Primitives::delta(y, z, n, m);

    BOOST_CHECK_EQUAL(expected, result);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus