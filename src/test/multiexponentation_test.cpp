#include "../secp256k1/include/MultiExponent.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

BOOST_AUTO_TEST_CASE(multiexponentation_test)
{
    std::vector<int> sizes = {10, 100, 1000, 5000};

    for(unsigned int j = 0; j < sizes.size(); ++j){
        int size = sizes[j];
        std::vector<secp_primitives::GroupElement> gens;
        std::vector<secp_primitives::Scalar> scalars;

        secp_primitives::GroupElement r;
        gens.resize(size);
        scalars.resize(size);
        for (int i = 0; i < size; ++i) {
            gens[i].randomize();
            scalars[i].randomize();

            r += gens[i] * scalars[i];
        }

        secp_primitives::MultiExponent multiexponent(gens, scalars);
        secp_primitives::GroupElement result = multiexponent.get_multiple();

        BOOST_CHECK_EQUAL(r,result);
    }
}

