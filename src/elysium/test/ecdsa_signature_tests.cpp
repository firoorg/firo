#include "../ecdsa_signature.h"

#include "../../test/fixtures.h"

#include <boost/test/unit_test.hpp>

namespace std {

template<typename Char, typename Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const vector<unsigned char>& vch)
{
    return os << HexStr(vch);
}

} // namespace std

namespace elysium {

class ECDSASignatureTestingSetup : public BasicTestingSetup
{
public:
    std::vector<unsigned char> rawSig;
    std::vector<unsigned char> compact;
    ECDSAContext context;

public:
    ECDSASignatureTestingSetup()
        : context(ECDSAContext::CreateVerifyContext())
    {
        rawSig = ParseHex("30440220741a563fc29ff077533d74a10940fc9a2a397c6f12bb482142d16d0bac2330ad0220698346e9dedd390c2691878336ced8f3f21452aa6346e677fdbf68a1094fbd94");
        compact = ParseHex("741a563fc29ff077533d74a10940fc9a2a397c6f12bb482142d16d0bac2330ad698346e9dedd390c2691878336ced8f3f21452aa6346e677fdbf68a1094fbd94");
    }

public:
    ECDSASignature GetSignature() const
    {
        return ECDSASignature::ParseDER(context, rawSig.data(), rawSig.size());
    }
};

BOOST_FIXTURE_TEST_SUITE(elysium_ecdsa_signature, ECDSASignatureTestingSetup)

BOOST_AUTO_TEST_CASE(default_contruct_should_invalid)
{
    ECDSASignature sig;
    auto valid = sig.Valid();

    BOOST_CHECK(!valid);
}

BOOST_AUTO_TEST_CASE(construct_and_get_data)
{
    auto sig = GetSignature();
    auto sigVec = sig.GetDER(context);

    std::vector<unsigned char> expected;
    expected.insert(expected.end(), rawSig.begin(), rawSig.end());
    expected.push_back(0x00);
    expected.push_back(0x00);

    BOOST_CHECK_EQUAL(expected, sigVec);
    BOOST_CHECK(sig.Valid());
}

BOOST_AUTO_TEST_CASE(parse_signature)
{
    auto sig = ECDSASignature::ParseCompact(context, compact.data(), compact.size());
    auto derSig = ECDSASignature::ParseDER(context, rawSig.data(), rawSig.size());
    auto sigVec = sig.GetDER(context);
    auto derSigVec = derSig.GetDER(context);

    std::vector<unsigned char> expected;
    expected.insert(expected.end(), rawSig.begin(), rawSig.end());
    expected.push_back(0x00);
    expected.push_back(0x00);

    BOOST_CHECK_EQUAL(expected, sigVec);
    BOOST_CHECK(sig.Valid());

    BOOST_CHECK_EQUAL(expected, derSigVec);
    BOOST_CHECK(derSig.Valid());
}

BOOST_AUTO_TEST_CASE(serialize)
{
    auto sig = GetSignature();

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << sig;

    std::vector<unsigned char> serialized(ss.begin(), ss.end());

    BOOST_CHECK_EQUAL(compact, serialized);
}

BOOST_AUTO_TEST_CASE(serialize_invalid)
{
    ECDSASignature sig;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

    BOOST_CHECK_THROW(ss << sig, std::logic_error);
}

BOOST_AUTO_TEST_CASE(unserialize)
{
    ECDSASignature sig;

    CDataStream ss(compact, SER_NETWORK, PROTOCOL_VERSION);
    ss >> sig;

    std::vector<unsigned char> expected;
    expected.insert(expected.end(), rawSig.begin(), rawSig.end());
    expected.push_back(0x00);
    expected.push_back(0x00);

    BOOST_CHECK_EQUAL(expected, sig.GetDER(context));
    BOOST_CHECK(sig.Valid());
}

BOOST_AUTO_TEST_CASE(unserialize_non_compact)
{
    std::vector<unsigned char> shrinkedCompact;
    shrinkedCompact.insert(shrinkedCompact.end(), compact.begin(), compact.end());
    shrinkedCompact.resize(shrinkedCompact.size() - 1);

    ECDSASignature sig;
    CDataStream ss(shrinkedCompact, SER_NETWORK, PROTOCOL_VERSION);

    BOOST_CHECK_THROW(ss >> sig, std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium