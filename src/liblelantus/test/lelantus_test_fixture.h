#ifndef ZCOIN_LIBLELANTUS_TEST_FIXTURE_H
#define ZCOIN_LIBLELANTUS_TEST_FIXTURE_H

#include "../../test/test_bitcoin.h"

namespace lelantus {

class LelantusTestingSetup {
public:
    template<class Output>
    void GenerateGroupElements(size_t size, Output output) {

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

    std::vector<GroupElement> GenerateGroupElements(size_t size);
    std::vector<GroupElement> RandomizeGroupElements(size_t size);
    std::vector<Scalar> RandomizeScalars(size_t size);
};

} // namespace lelantus

#endif // ZCOIN_LIBLELANTUS_TEST_FIXTURE_H