#include "crypto/MerkleTreeProof/mtp.h"
#include "test/test_bitcoin.h"
#include <iostream>
#include <boost/test/unit_test.hpp>

using namespace std;

struct MtpTestingSetup : public TestingSetup
{
    MtpTestingSetup() : TestingSetup(CBaseChainParams::REGTEST, "1")
    {
    }
};

BOOST_FIXTURE_TEST_SUITE(mtp_tests, MtpTestingSetup)

BOOST_AUTO_TEST_CASE(mtp_test)
{
    char input[] = {
        (char)0x00, (char)0x00, (char)0x00, (char)0x20, (char)0x7f, (char)0xda,
        (char)0x1a, (char)0xbd, (char)0xca, (char)0x0f, (char)0x11, (char)0xc3,
        (char)0xca, (char)0xd5, (char)0xf6, (char)0x7e, (char)0x73, (char)0xd8,
        (char)0x48, (char)0x59, (char)0x22, (char)0xe2, (char)0x56, (char)0xa1,
        (char)0x94, (char)0xa9, (char)0x22, (char)0x90, (char)0xb0, (char)0x00,
        (char)0x85, (char)0x51, (char)0x5d, (char)0xf4, (char)0x64, (char)0xdd,
        (char)0x1d, (char)0xe2, (char)0x9e, (char)0xeb, (char)0x54, (char)0x46,
        (char)0x23, (char)0x0c, (char)0x0a, (char)0x17, (char)0xeb, (char)0x84,
        (char)0x11, (char)0x59, (char)0xd4, (char)0x1a, (char)0xc0, (char)0x63,
        (char)0x6c, (char)0x52, (char)0x18, (char)0xc8, (char)0xef, (char)0xaf,
        (char)0x78, (char)0x0b, (char)0x96, (char)0xcf, (char)0xca, (char)0x94,
        (char)0x88, (char)0x54, (char)0x3d, (char)0x13, (char)0x32, (char)0x5b,
        (char)0xff, (char)0xff, (char)0x00, (char)0x20, (char)0x00, (char)0x10,
        (char)0x00, (char)0x00 };

    uint32_t target = 0x2000fffful;

    uint256 pow_limit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    uint8_t hash_root_mtp[16];
    unsigned int nonce;
    uint64_t block_mtp[72*2][128];
    std::deque<std::vector<uint8_t>> proof_mtp[72*3];
    uint256 output;

    mtp_hash(input, target, hash_root_mtp, &nonce, block_mtp, proof_mtp,
            pow_limit, &output);
    BOOST_CHECK_MESSAGE(nonce == 143u, "wrong nonce");

    bool ok = mtp_verify(input, target, hash_root_mtp, &nonce, block_mtp,
            proof_mtp, pow_limit);
    BOOST_CHECK_MESSAGE(ok, "mtp_verify() failed");
}

BOOST_AUTO_TEST_SUITE_END()
