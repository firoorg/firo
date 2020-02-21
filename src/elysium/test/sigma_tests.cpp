#include "../sigma.h"
#include "../sigmadb.h"
#include "../sigmaprimitives.h"

#include "../../test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <stddef.h>
#include <vector>

namespace elysium {
namespace {

struct SigmaDatabaseFixture : TestingSetup
{
    SigmaDatabaseFixture()
    {
        sigmaDb = new SigmaDatabase(pathTemp / "exodus-sigmadb", true, 10);
    }

    ~SigmaDatabaseFixture()
    {
        delete sigmaDb; sigmaDb = nullptr;
    }
};

SigmaPublicKey CreateMint()
{
    SigmaPrivateKey key;
    key.Generate();
    return SigmaPublicKey(key, DefaultSigmaParams);
}

std::vector<SigmaPublicKey> CreateMints(size_t n)
{
    std::vector<SigmaPublicKey> mints;

    while (n--) {
        mints.push_back(CreateMint());
    }

    return mints;
}

} // unnamed namespace

BOOST_AUTO_TEST_SUITE(exodus_sigma_tests)

BOOST_FIXTURE_TEST_CASE(verify_spend, SigmaDatabaseFixture)
{
    auto& params = DefaultSigmaParams;
    SigmaPrivateKey key;
    SigmaProof proof(params);
    std::vector<SigmaPublicKey> anonimitySet;
    bool increaseBlock = false;
    int block = 100;

    // Create set of mint that contains our spendable mint.
    key.Generate();

    anonimitySet.push_back(SigmaPublicKey(key, params));

    for (auto& mint : CreateMints(sigmaDb->groupSize - 2)) { // -2 to make anonimitySet not a full group.
        anonimitySet.push_back(mint);
    }

    proof.Generate(key, anonimitySet.begin(), anonimitySet.end(), false);

    // Generate spendable group.
    for (unsigned i = 0; i < sigmaDb->groupSize; i++) {
        if (i < anonimitySet.size()) {
            sigmaDb->RecordMint(3, 0, anonimitySet[i], block);
        } else {
            sigmaDb->RecordMint(3, 0, CreateMint(), block);
        }

        sigmaDb->RecordMint(3, 1, CreateMint(), block);
        sigmaDb->RecordMint(4, 0, CreateMint(), block);

        if (increaseBlock) {
            block++;
            increaseBlock = false;
        } else {
            increaseBlock = true;
        }
    }

    // Generate non-spendable group.
    for (auto& mint : CreateMints(sigmaDb->groupSize)) {
        sigmaDb->RecordMint(3, 0, mint, block);
    }

    BOOST_CHECK_EQUAL(VerifySigmaSpend(3, 0, 0, anonimitySet.size(), proof, false), true);
    BOOST_CHECK_EQUAL(VerifySigmaSpend(3, 0, 0, anonimitySet.size() - 1, proof, false), false);
    BOOST_CHECK_EQUAL(VerifySigmaSpend(3, 0, 0, anonimitySet.size() + 1, proof, false), false);
    BOOST_CHECK_EQUAL(VerifySigmaSpend(3, 0, 0, sigmaDb->groupSize + 1, proof, false), false);
    BOOST_CHECK_EQUAL(VerifySigmaSpend(3, 1, 0, sigmaDb->groupSize, proof, false), false);
    BOOST_CHECK_EQUAL(VerifySigmaSpend(4, 0, 0, sigmaDb->groupSize, proof, false), false);
    BOOST_CHECK_EQUAL(VerifySigmaSpend(3, 0, 1, sigmaDb->groupSize, proof, false), false);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium
