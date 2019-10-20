#include "../GroupElement.h"
#include "../Scalar.h"

#include <iostream>

#include <boost/test/unit_test.hpp>

#include "../../test/fixtures.h"

BOOST_FIXTURE_TEST_SUITE(wrapper_tests, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(groupelement_scalar_wrapper_tests)
{
       std::vector<std::pair<const char*, const char*>> testcases;
    testcases.push_back(std::make_pair("9216064434961179932092223867844635691966339998754536116709681652691785432045",
        "33986433546870000256104618635743654523665060392313886665479090285075695067131"));
    testcases.push_back(std::make_pair("50204771751011461524623624559944050110546921468100198079190811223951215371253",
        "33986433546870000256104618635743654523665060392313886665479090285075695067131"));
    testcases.push_back(std::make_pair("7143275630583997983432964947790981761478339235433352888289260750805571589245",
        "11700086115751491157288596384709446578503357013980342842588483174733971680454"));
    testcases.push_back(std::make_pair("7143275630583997983432964947790981761478339235433352888289260750805571589245",
        "-11700086115751491157288596384709446578503357013980342842588483174733971680454"));

    std::vector<std::pair<const char*, const char*>> hexTestcases;
    hexTestcases.push_back(std::make_pair("14601b8cdf761d4ed94554865ef0ef5c451e275f3dfc0a667fea04fa5a833bed",
        "4b23a3c385114c40cb4fbf02d1a52f731b4edf61c247372d038470eea90edffb"));
    hexTestcases.push_back(std::make_pair("6efee4d1ba231acfee2391dc5ded838cee89235af14b8a4f494e4734cb1323f5",
        "4b23a3c385114c40cb4fbf02d1a52f731b4edf61c247372d038470eea90edffb"));
    hexTestcases.push_back(std::make_pair("fcaf3630cd86c0b9dc6b122aeca20b065a14f861c291cd53a989f0e9fe1d47d",
        "19de0399d7578731a20abff9283e66117f8cc02be53c4cc86eb5ac3378c36cc6"));
    hexTestcases.push_back(std::make_pair("fcaf3630cd86c0b9dc6b122aeca20b065a14f861c291cd53a989f0e9fe1d47d",
        "e621fc6628a878ce5df54006d7c199ee80733fd41ac3b337914a53cc873c933a"));

    std::vector<const char*> expecteds;
    expecteds.push_back(
        "(9216064434961179932092223867844635691966339998754536116709681652691785432045,"
        "33986433546870000256104618635743654523665060392313886665479090285075695067131)");
    expecteds.push_back(
        "(50204771751011461524623624559944050110546921468100198079190811223951215371253,"
        "33986433546870000256104618635743654523665060392313886665479090285075695067131)");
    expecteds.push_back(
        "(7143275630583997983432964947790981761478339235433352888289260750805571589245,"
        "11700086115751491157288596384709446578503357013980342842588483174733971680454)");
    expecteds.push_back(
        "(7143275630583997983432964947790981761478339235433352888289260750805571589245,"
        "-11700086115751491157288596384709446578503357013980342842588483174733971680454)");


    std::vector<const char*> expectedHexs;
    expectedHexs.push_back(
        "(14601b8cdf761d4ed94554865ef0ef5c451e275f3dfc0a667fea04fa5a833bed,"
        "4b23a3c385114c40cb4fbf02d1a52f731b4edf61c247372d038470eea90edffb)");
    expectedHexs.push_back(
        "(6efee4d1ba231acfee2391dc5ded838cee89235af14b8a4f494e4734cb1323f5,"
        "4b23a3c385114c40cb4fbf02d1a52f731b4edf61c247372d038470eea90edffb)");
    expectedHexs.push_back(
        "(fcaf3630cd86c0b9dc6b122aeca20b065a14f861c291cd53a989f0e9fe1d47d,"
        "19de0399d7578731a20abff9283e66117f8cc02be53c4cc86eb5ac3378c36cc6)");
    expectedHexs.push_back(
        "(fcaf3630cd86c0b9dc6b122aeca20b065a14f861c291cd53a989f0e9fe1d47d,"
        "e621fc6628a878ce5df54006d7c199ee80733fd41ac3b337914a53cc873c933a)");

    for (unsigned int i = 0; i < testcases.size(); i++) {
        auto& t = testcases[i];
        secp_primitives::GroupElement g(t.first, t.second);

        BOOST_CHECK(expecteds[i] == g.tostring());

        BOOST_CHECK(expectedHexs[i] == g.GetHex());
    }

    for (unsigned int i = 0; i < hexTestcases.size(); i++) {
        auto& t = hexTestcases[i];
        secp_primitives::GroupElement g(t.first, t.second, 16);

        BOOST_CHECK(expecteds[i] == g.tostring());

        BOOST_CHECK(expectedHexs[i] == g.GetHex());

    }

    // test scalar infinite loop bugs on GCC 8
    secp_primitives::Scalar scalar;
    scalar.randomize();
}

BOOST_AUTO_TEST_SUITE_END()