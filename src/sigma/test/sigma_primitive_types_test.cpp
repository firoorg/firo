#include <boost/test/unit_test.hpp>

#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include <secp256k1/include/MultiExponent.h>

#include <chainparams.h>
#include <sigma/params.h>

BOOST_AUTO_TEST_SUITE(sigma_primitive_types)

BOOST_AUTO_TEST_CASE(scalar_test)
{
    // Create a large scalar value.
    secp_primitives::Scalar s(123456789);
    s *= s;
    s *= s;
    s *= s;
    s *= s;
    s *= s;
    secp_primitives::Scalar s2(s);
    
    // Make sure that copy constructor works correctly.
    BOOST_CHECK(s == s2);
}

BOOST_AUTO_TEST_CASE(get_multiple_multi_thread)
{
    SelectParams(CBaseChainParams::REGTEST);
    auto sigmaParams = sigma::Params::get_default();

    // Test if MultiExponent::get_multiple gets the correct result if run with multi-core optimization
    for (int s=1000; s<5000; s+=500)
    {
        std::vector<secp_primitives::GroupElement> ge_array;
        std::vector<secp_primitives::Scalar> e_array;

        for (int i=0; i<s; i++) {
            secp_primitives::Scalar e;
            e.randomize();
            ge_array.push_back(sigmaParams->get_h0() * e);
            e_array.push_back(e);
        }

        secp_primitives::MultiExponent m_test(ge_array, e_array);
        BOOST_CHECK(m_test.get_multiple() == m_test.get_multiple_single_thread());
    }
}

BOOST_AUTO_TEST_SUITE_END()
