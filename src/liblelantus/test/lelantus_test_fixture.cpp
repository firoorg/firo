#include "lelantus_test_fixture.h"

namespace lelantus {

std::vector<GroupElement> LelantusTestingSetup::GenerateGroupElements(size_t size) const {
    std::vector<GroupElement> gs;
    GenerateGroupElements(size, std::back_inserter(gs));

    return gs;
}

std::vector<GroupElement> LelantusTestingSetup::RandomizeGroupElements(size_t size) const {
    std::vector<GroupElement> gs(size);
    for (auto &g : gs) {
        g.randomize();
    }

    return gs;
}

std::vector<Scalar> LelantusTestingSetup::RandomizeScalars(size_t size) const {
    std::vector<Scalar> ss(size);
    for (auto &s : ss) {
        s.randomize();
    }

    return ss;
}

} // namespace lelantus