#ifndef ZCOIN_LIBLELANTUS_TEST_FIXTURE_H
#define ZCOIN_LIBLELANTUS_TEST_FIXTURE_H

#include "../../test/test_bitcoin.h"

#include "../lelantus_primitives.h"

#include <secp256k1/include/MultiExponent.h>

namespace lelantus {

class LelantusTestingSetup {
protected:
    typedef LelantusPrimitives<Scalar, GroupElement> Primitives;

public:
    LelantusTestingSetup() : params(Params::get_default()) {
    }

public:
    GroupElement ComputeMultiExponent(std::vector<GroupElement> const &gs, std::vector<Scalar> const &s) const {
        return secp_primitives::MultiExponent(gs, s).get_multiple();
    }

    template<class Output>
    void GenerateGroupElements(size_t size, Output output) const {

        std::array<uint8_t, 32> seed;
        std::fill(seed.begin(), seed.end(), 0);

        for (size_t i = 0; i != size; i++) {
            // 'LE'
            std::copy(
                reinterpret_cast<unsigned char*>(&i),
                reinterpret_cast<unsigned char*>(&i) + sizeof(i),
                seed.begin());

            GroupElement e;
            e.generate(seed.begin());

            if (!e.isMember() || e.isInfinity()) {
                throw std::runtime_error("Fail to generate group elements");
            }

            *output++ = e;
        }
    }

    // Generate group elements deterministically
    std::vector<GroupElement> GenerateGroupElements(size_t size) const;
    std::vector<GroupElement> RandomizeGroupElements(size_t size) const;
    std::vector<Scalar> RandomizeScalars(size_t size) const;
public:
    Params const *params;
};

} // namespace lelantus

#endif // ZCOIN_LIBLELANTUS_TEST_FIXTURE_H