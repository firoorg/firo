#include "crypto/MerkleTreeProof/mtp.h"
#include "test/test_bitcoin.h"
#include "random.h"
#include <iostream>
#include <boost/test/unit_test.hpp>

//#include <univalue.h>
//#include "wallet/wallet.h"
//
//extern UniValue generate(const UniValue& params, bool fHelp);
//extern UniValue keypoolrefill(const UniValue& params, bool fHelp);
//extern CRPCTable tableRPC;

using namespace std;

struct MtpTestingSetup : public TestingSetup
{
    MtpTestingSetup() : TestingSetup(CBaseChainParams::REGTEST, "1")
    {
    }
};



BOOST_FIXTURE_TEST_SUITE(mtp_tests, MtpTestingSetup)

BOOST_AUTO_TEST_CASE(mtp_impl_integrity_test)
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

    mtp::impl::mtp_hash(input, target, hash_root_mtp, nonce, block_mtp, proof_mtp,
            pow_limit, output);
    BOOST_CHECK_MESSAGE(nonce == 143u, "wrong nonce");

    bool ok = mtp::impl::mtp_verify(input, target, hash_root_mtp, nonce, block_mtp,
            proof_mtp, pow_limit);
    BOOST_CHECK_MESSAGE(ok, "mtp_verify() failed");
}


BOOST_AUTO_TEST_CASE(mtp_block_integrity_test)
{
    RandAddSeed();

    CBlock block1;

    block1.nVersion = CBlock::CURRENT_VERSION;
    block1.hashPrevBlock = GetRandHash();
    block1.hashMerkleRoot = GetRandHash();
    block1.nTime = GetRandInt(std::numeric_limits<decltype(block1.nTime)>::max());
    block1.nBits = 0x2000ffffUL;
    block1.mtpHashData = std::shared_ptr<CMTPHashData>(new CMTPHashData);
    block1.nVersionMTP = 1;

    CBlock block2(block1); block2.mtpHashData = std::shared_ptr<CMTPHashData>(new CMTPHashData); block2.nVersionMTP = 1;
    CBlock block3(block1); block3.mtpHashData = std::shared_ptr<CMTPHashData>(new CMTPHashData); block3. nVersionMTP = 1;

    uint256 const pow_limit = Params(CBaseChainParams::REGTEST).GetConsensus().powLimit ;

    auto hash1 = mtp::hash(block1, pow_limit);

    auto hash2 = mtp::hash(block2, pow_limit);

    BOOST_CHECK(hash1 == hash2);
    BOOST_CHECK(block1.nNonce == block2.nNonce);

    ++block3.nVersion;
    auto hash3 = mtp::hash(block3, pow_limit);

    BOOST_CHECK(hash1 != hash3);
    BOOST_CHECK(block1.nNonce != block3.nNonce);

    BOOST_CHECK(mtp::verify(block1.nNonce, block1, pow_limit));
    BOOST_CHECK(mtp::verify(block2.nNonce, block2, pow_limit));
    BOOST_CHECK(mtp::verify(block3.nNonce, block3, pow_limit));

    BOOST_CHECK(false == mtp::verify(block1.nNonce+1, block1, pow_limit));
    BOOST_CHECK(false == mtp::verify(block2.nNonce-1, block2, pow_limit));
    BOOST_CHECK(false == mtp::verify(block3.nNonce+1, block3, pow_limit));
}

//std::ostream & print_what_should(std::ostream &  ostr,  std::string const & addr)
//{
//    ostr << "sed -ri 's/" << addr << "/" << bitcoin_address_to_zcoin(addr) << "/g'" << std::endl;
//    return ostr;
//}
//
//BOOST_AUTO_TEST_CASE(mtp_printer)
//{
//    print_what_should(std::cout, "cSFpb16iAbS9KP63UnHv6XjPxWBqmAgTa4U3SeAxyHRvsLimyfNk") << std::endl;
//}
//
//BOOST_AUTO_TEST_CASE(mtp_temp)
//{
//    CWallet * pwalletMain = new CWallet("wallet_test.dat");
//    bool fFirstRun = true;
//    pwalletMain->LoadWallet(fFirstRun);
//    RegisterValidationInterface(pwalletMain);
//
//    RegisterWalletRPCCommands(tableRPC);
//
//
//    UniValue v(UniValue::VARR), v1;
//    v1.setInt(1);
//    v.push_back(v1);
//
//    keypoolrefill(v, false);
//
//    generate(v, false);
//
//}


BOOST_AUTO_TEST_SUITE_END()
