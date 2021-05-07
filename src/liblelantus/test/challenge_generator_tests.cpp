#include "lelantus_test_fixture.h"

#include "../challenge_generator_impl.h"

#include <GroupElement.h>
#include <Scalar.h>

#include <boost/test/unit_test.hpp>

namespace lelantus {

class ChallengeGeneratorTests : public LelantusTestingSetup {
public:
    ChallengeGeneratorImpl<CSHA256> generator;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_challenge_generator_tests, ChallengeGeneratorTests)

BOOST_AUTO_TEST_CASE(no_input)
{
    Scalar out;

    generator.get_challenge(out);

    // hash of empty
    BOOST_CHECK_EQUAL(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        out.GetHex());
}

BOOST_AUTO_TEST_CASE(add_one_at_a_time)
{
    auto gs = GenerateGroupElements(2);

    generator.add(gs[0]);
    generator.add(gs[1]);

    Scalar out;
    generator.get_challenge(out);

    // hash of gs[0] and gs[1]
    BOOST_CHECK_EQUAL(
        "e89ba7cb6379a9b940ed9ed3cda18e0f2177019938fbac57e38e5e541e080fc3",
        out.GetHex());
}

BOOST_AUTO_TEST_CASE(add_bulk)
{
    auto gs = GenerateGroupElements(2);

    generator.add(gs);

    Scalar out;
    generator.get_challenge(out);

    // hash of gs[0] and gs[1]
    BOOST_CHECK_EQUAL(
        "e89ba7cb6379a9b940ed9ed3cda18e0f2177019938fbac57e38e5e541e080fc3",
        out.GetHex());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus