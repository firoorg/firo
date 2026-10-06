#include "../chainparams.h"
#include "../spark/sparkmessage.h"
#include "../spark/state.h"
#include "../utilstrencodings.h"
#include "../validation.h"
#include "../wallet/wallet.h"
#include "../wallet/walletexcept.h"

#include "test_bitcoin.h"
#include "fixtures.h"

#include <boost/test/unit_test.hpp>

namespace spark {

class SparkMessageTests : public SparkTestingSetup
{
public:
    // An address belonging to the test wallet, in its encoded form.
    std::string MyAddress()
    {
        LOCK(pwalletMain->cs_wallet);
        return pwalletMain->sparkWallet->generateNewAddress().encode(GetNetworkType());
    }

    std::string Sign(const std::string &encodedAddress, const std::string &message)
    {
        Address address(params);
        address.decode(encodedAddress);
        LOCK(pwalletMain->cs_wallet);
        return pwalletMain->sparkWallet->SignMessage(address, message);
    }
};

BOOST_FIXTURE_TEST_SUITE(sparkmessage, spark::SparkMessageTests)

BOOST_AUTO_TEST_CASE(sign_then_verify_round_trip)
{
    std::string addr = MyAddress();
    std::string message = "firo-forum-spark-name/v1|example|round trip";

    std::string signature = Sign(addr, message);
    BOOST_CHECK(!signature.empty());
    BOOST_CHECK(IsHex(signature));

    BOOST_CHECK(VerifyMessage(addr, signature, message) == VerifyResult::Ok);
}

BOOST_AUTO_TEST_CASE(verify_rejects_tampered_message)
{
    std::string addr = MyAddress();
    std::string signature = Sign(addr, "the original message");

    BOOST_CHECK(VerifyMessage(addr, signature, "the original message ") == VerifyResult::Mismatch);
    BOOST_CHECK(VerifyMessage(addr, signature, "a different message") == VerifyResult::Mismatch);
    BOOST_CHECK(VerifyMessage(addr, signature, "") == VerifyResult::Mismatch);
}

BOOST_AUTO_TEST_CASE(verify_rejects_a_proof_made_for_another_address)
{
    std::string message = "same message, two addresses";
    std::string addrA = MyAddress();
    std::string addrB = MyAddress();
    BOOST_REQUIRE(addrA != addrB);

    BOOST_CHECK(VerifyMessage(addrB, Sign(addrA, message), message) == VerifyResult::Mismatch);
}

BOOST_AUTO_TEST_CASE(verify_reports_malformed_input)
{
    std::string addr = MyAddress();
    std::string signature = Sign(addr, "a message");

    // Not hex at all.
    BOOST_CHECK(VerifyMessage(addr, "not a hex string", "a message") == VerifyResult::NotHex);
    // Hex, but far too short to deserialize into an ownership proof.
    BOOST_CHECK(VerifyMessage(addr, "abcd", "a message") == VerifyResult::MalformedProof);
    // A truncated proof still fails to deserialize rather than being treated as a mismatch.
    // Drop one whole byte so the input stays valid hex and the failure is the truncation
    // rather than an odd digit count.
    BOOST_REQUIRE(signature.size() > 2);
    BOOST_CHECK(VerifyMessage(addr, signature.substr(0, signature.size() - 2), "a message")
                == VerifyResult::MalformedProof);

    BOOST_CHECK(VerifyMessage("not an address", signature, "a message") == VerifyResult::InvalidAddress);
    BOOST_CHECK(VerifyMessage("", signature, "a message") == VerifyResult::InvalidAddress);
}

BOOST_AUTO_TEST_CASE(verify_requires_a_canonical_proof)
{
    std::string addr = MyAddress();
    std::string message = "a message";
    std::string signature = Sign(addr, message);

    BOOST_REQUIRE(VerifyMessage(addr, signature, message) == VerifyResult::Ok);

    // Deserialization stops as soon as the proof is complete, so trailing bytes have to be
    // rejected explicitly or a valid signature stays valid with junk appended.
    BOOST_CHECK(VerifyMessage(addr, signature + "00", message) == VerifyResult::MalformedProof);
    BOOST_CHECK(VerifyMessage(addr, signature + "deadbeef", message) == VerifyResult::MalformedProof);

    // OwnershipProof begins with a GroupElement whose byte 32 is a y-oddness flag.
    // Its serializer emits only 0 or 1, but its deserializer accepts other values.
    std::string nonCanonical = signature;
    BOOST_REQUIRE(nonCanonical.size() >= 66);
    nonCanonical.replace(64, 2, "02");
    BOOST_CHECK(VerifyMessage(addr, nonCanonical, message) == VerifyResult::MalformedProof);
}

BOOST_AUTO_TEST_CASE(verify_rejects_an_address_from_another_network)
{
    Address address(params);
    {
        LOCK(pwalletMain->cs_wallet);
        address = pwalletMain->sparkWallet->generateNewAddress();
    }

    // Encode the very same address for a different network: it decodes cleanly, so it has
    // to be turned away on the network byte rather than as an invalid address.
    unsigned char foreignNetwork = GetNetworkType() == ADDRESS_NETWORK_MAINNET
                                       ? ADDRESS_NETWORK_TESTNET
                                       : ADDRESS_NETWORK_MAINNET;
    std::string signature = Sign(address.encode(GetNetworkType()), "a message");

    BOOST_CHECK(VerifyMessage(address.encode(foreignNetwork), signature, "a message")
                == VerifyResult::WrongNetwork);
}

BOOST_AUTO_TEST_CASE(sign_rejects_an_address_we_do_not_own)
{
    // A well formed address derived from a spend key that is not the wallet's.
    SpendKey foreignSpendKey(params);
    IncomingViewKey foreignViewKey(FullViewKey{foreignSpendKey});
    Address foreign(foreignViewKey, 0);

    BOOST_CHECK_THROW(
        {
            LOCK(pwalletMain->cs_wallet);
            pwalletMain->sparkWallet->SignMessage(foreign, "a message");
        },
        std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace spark
