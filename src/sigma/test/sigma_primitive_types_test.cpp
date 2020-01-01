#include <boost/test/unit_test.hpp>

#include "../secp256k1/include/secp256k1_scalar.hpp"
#include "../secp256k1/include/secp256k1_group.hpp"

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

BOOST_AUTO_TEST_SUITE_END()
