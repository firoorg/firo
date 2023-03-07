#include "../transcript.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

BOOST_FIXTURE_TEST_SUITE(spark_transcript_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(init)
{
    // Identical domain separators
    Transcript transcript_1("Spam");
    Transcript transcript_2("Spam");
    BOOST_CHECK_EQUAL(transcript_1.challenge("x"), transcript_2.challenge("x"));

    // Distinct domain separators
    transcript_1 = Transcript("Spam");
    transcript_2 = Transcript("Eggs");
    BOOST_CHECK_NE(transcript_1.challenge("x"), transcript_2.challenge("x"));
}

BOOST_AUTO_TEST_CASE(challenge_labels)
{
    Transcript transcript_1("Spam");
    Transcript transcript_2("Spam");

    // Identical challenge labels
    BOOST_CHECK_EQUAL(transcript_1.challenge("x"), transcript_2.challenge("x"));

    // Distinct challenge labels
    BOOST_CHECK_NE(transcript_1.challenge("x"), transcript_2.challenge("y"));
}

BOOST_AUTO_TEST_CASE(add_types)
{
    // Add all fixed types and assert distinct challenges
    const std::string domain = "Spam";
    Transcript transcript(domain);

    Scalar scalar;
    scalar.randomize();
    transcript.add("Scalar", scalar);
    Scalar ch_1 = transcript.challenge("x");
    
    GroupElement group;
    group.randomize();
    transcript.add("Group", group);
    Scalar ch_2 = transcript.challenge("x");
    BOOST_CHECK_NE(ch_1, ch_2);

    std::vector<Scalar> scalars;
    for (std::size_t i = 0; i < 3; i++) {
        scalar.randomize();
        scalars.emplace_back(scalar);
    }
    Scalar ch_3 = transcript.challenge("x");
    BOOST_CHECK_NE(ch_2, ch_3);

    std::vector<GroupElement> groups;
    for (std::size_t i = 0; i < 3; i++) {
        group.randomize();
        groups.emplace_back(group);
    }
    Scalar ch_4 = transcript.challenge("x");
    BOOST_CHECK_NE(ch_3, ch_4);

    const std::string data = "Arbitrary string";
    const std::vector<unsigned char> data_char(data.begin(), data.end());
    transcript.add("Data", data_char);
    Scalar ch_5 = transcript.challenge("x");
    BOOST_CHECK_NE(ch_4, ch_5);
}

BOOST_AUTO_TEST_CASE(repeated_challenge)
{
    // Repeated challenges must be distinct, even with the same label
    Transcript transcript("Eggs");

    Scalar ch_1 = transcript.challenge("x");
    Scalar ch_2 = transcript.challenge("x");

    BOOST_CHECK_NE(ch_1, ch_2);
}

BOOST_AUTO_TEST_CASE(repeated_challenge_ordering)
{
    // Repeated challenges must respect ordering
    Transcript prover("Spam");
    Transcript verifier("Spam");

    Scalar prover_x = prover.challenge("x");
    Scalar prover_y = prover.challenge("y");

    // Oh no, we mixed up the order
    Scalar verifier_y = verifier.challenge("y");
    Scalar verifier_x = verifier.challenge("x");

    BOOST_CHECK_NE(prover_x, verifier_x);
    BOOST_CHECK_NE(prover_y, verifier_y);
}

BOOST_AUTO_TEST_CASE(identical_transcripts)
{
    // Ensure that identical transcripts yield identical challenges
    Transcript prover("Beer");
    Transcript verifier("Beer");

    Scalar scalar;
    scalar.randomize();
    GroupElement group;
    group.randomize();

    prover.add("Scalar", scalar);
    verifier.add("Scalar", scalar);
    prover.add("Group", group);
    verifier.add("Group", group);

    BOOST_CHECK_EQUAL(prover.challenge("x"), verifier.challenge("x"));
}

BOOST_AUTO_TEST_CASE(distinct_values)
{
    // Ensure that distinct transcript values yield distinct challenges
    Transcript prover("Soda");
    Transcript verifier("Soda");

    Scalar prover_scalar;
    prover_scalar.randomize();
    Scalar verifier_scalar;
    verifier_scalar.randomize();

    prover.add("Scalar", prover_scalar);
    verifier.add("Scalar", verifier_scalar);

    BOOST_CHECK_NE(prover.challenge("x"), verifier.challenge("x"));
}

BOOST_AUTO_TEST_CASE(distinct_labels)
{
    // Ensure that distinct transcript labels yield distinct challenges
    Transcript prover("Soda");
    Transcript verifier("Soda");

    Scalar scalar;
    scalar.randomize();

    prover.add("Prover scalar", scalar);
    verifier.add("Verifier scalar", scalar);

    BOOST_CHECK_NE(prover.challenge("x"), verifier.challenge("y"));
}

BOOST_AUTO_TEST_CASE(converging)
{
    // Transcripts with distinct initial states but common post-challenge elements
    Transcript transcript_1("Spam");
    Transcript transcript_2("Eggs");

    Scalar ch_1 = transcript_1.challenge("x");
    Scalar ch_2 = transcript_1.challenge("x");

    // Add a common element and assert the states still differ
    Scalar scalar;
    scalar.randomize();
    transcript_1.add("Scalar", scalar);
    transcript_2.add("Scalar", scalar);

    BOOST_CHECK_NE(transcript_1.challenge("x"), transcript_2.challenge("x"));
}

BOOST_AUTO_TEST_SUITE_END()

}
