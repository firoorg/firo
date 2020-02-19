#include "../sigmaprimitives.h"
#include "../signaturebuilder.h"

#include "../../test/test_bitcoin.h"

#include "../../wallet/test/wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>

namespace exodus {

class TestSignatureSigmaV1Builder : public SigmaV1SignatureBuilder
{
public:
    TestSignatureSigmaV1Builder(
        CBitcoinAddress const &receiver,
        int64_t referenceAmount,
        SigmaProof const &proof,
        ECDSAPublicKey publicKey)
        : SigmaV1SignatureBuilder(receiver, referenceAmount, proof, publicKey)
    {
    }

public:
    uint256 GetHash()
    {
        return this->hasher.GetHash();
    }
};

struct SignatureBuilderSigmaV1Setup : BasicTestingSetup
{
public:
    CBitcoinAddress address;
    SigmaProof proof;

    ECDSAPrivateKey secret;
    ECDSAPublicKey publicKey;

public:
    SignatureBuilderSigmaV1Setup()
        : address("a8ULhhDgfdSiXJhSZVdhb8EuDc6R3ogsaM"), proof(DefaultSigmaParams)
    {
        auto rawProof = ParseHex("e8792d49b74be7795c9bafa8b49159d4b0bc24e1ac4955d82a8d0b3f076069210881ac0a8392734a66179ed5f06b0fcc90804776e2194e2537c83abab1b0a8cf01007fa57fdf9caecf435ad51f8fdd5062a3360063954098026efea1041d51843d7700005785485b9c61950299f98850894ee101497ff0c5e60f70ca6468dc05a2f6757c010045b2e2575c32363fdc7eb4c0fcfd925f4ca196b2e1a5e8bea76b34e819e4fcc7000015f0c997162cf54ca1ca376e5b417fe04c2900888fb50c70598ca5f11229afbdb1faa42ca7c5734730f9e733b010556592619f29730159d79985798db97d268f1a882c8947a0e2da27534490efa2021e51f8b398d2e3e7d07debd17fc76e599ce4f9ea28886054d00103f0764ad193c89eecdce65f53e4603db2bffe0c9beae474afa96fb8d23f17eef92b32b56bd44716b8393443c63b78f93ed42fb2a1b6df0e0eb5c799ba2cc8dfe4b92cbd98cc98e7d0f7b4370413b442b8421b8de820dafae6271b51ab8f923eead1f81e32f85ea9075d905523e25fa6bd64dbf5cfcf5fe3bdaa663c762179aeda6361edf17424c3d0e96ebd5d628d52fbcd6df294e178fd9a1ab33b36e66e294f551de6d0dda865b6556ce72eac65b31a96d30d0c2225e7491830ab8aae2d7323efebe503b6cd9b0f7a3c6780dc446c2a198d88d0f805fc7e0fef6bf04ba413360ed73a6957be311269aabe4a5193182a7e0fc7b332e5320faa7ec20ea29ac7d348f6c3fb997e0c916c2e249ba6a1677f7a464eb5db817a9a063e85f0a0017b6e90e2e9e5b668360d49420429750043cee9f2f4be8c89c9f3daa6e353e2b800f8ca530e924df891d6eb6a33897d4551440d721e808757eaa83747003479e6b1f19e5f7a1cc8bd4bf54008cad7ff49f8d53e232772a2fd30576115c3d10f941cb8a49fe4d144dc0977e6f7f197f25d39ebfd5333cdfd71bad101637e8470470dc1d59b21ef16b5bf3150473bc5736cff706c59c82363acadd0b6d311c12944692825ae6eded3b0ac92d333862f85a516b59dbdab6dcd858322907412b8301fd3e5a1a737e86734abb363cc1fdc33635776bcf5adb69e16fc02b00ccbd90e37178375934740a8daa986294a2f0f4f44a7a73ad57611dce568c1a4b51542c202019527b77d4231869c26f7b44e6190933ed372391dd7cf09c3c6a522cb7dcf09a1344b64c597ab887e3840c642a07e3561b8ead98f152eee2a120912e31eb75c337e16a57adfc6b48ceb4c887473756aeba1ca94040c9546b20756551df2f116695e9b1a00eb28ce357a3beaeb62006241fde992aa33b2fbfec20000bf44451073162633dd4c690b75aaf6fd796c5dea3f29e775e3739673e529abc90100ad4907d4dfb26812b29def0167b1234fcbfcbdbb4f6dda8e45322d4a32e0555a010091f92a2ae22c5a9e1c3bbd3a9ff1c4a5aec7718080cbe06601021e0a082e07970000d57157ea9edfc6165cb40d122b9967fc64fbd74c7b7edfa75d990475040e67f40000fb32e10c853f44b877693ddf55be4cca53a54209956f68dbfb77034f16348281000008515c1f54a4cfe87cc7d06c548cc0119b5c9e0e04b8b604cd35d069ebadf6ca000004a805cb321df988b32acda8d5c8e60b0d17e0df5fe3c577990eb873f47d46b7");
        CDataStream ss(rawProof, SER_NETWORK, PROTOCOL_VERSION);

        proof.Unserialize(ss, SER_NETWORK, PROTOCOL_VERSION);

        std::fill(secret.begin(), secret.end(), 0x11);

        auto rawPublicKey = ParseHex("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
        std::copy(rawPublicKey.begin(), rawPublicKey.end(), publicKey.begin());
    }

public:
    CoinSigner GetCoinSigner()
    {
        return CoinSigner(secret);
    }
};

BOOST_FIXTURE_TEST_SUITE(exodus_signaturebuilder_sigmav1_tests, SignatureBuilderSigmaV1Setup)

BOOST_AUTO_TEST_CASE(construct_withvalidkey_verify_hash)
{
    std::unique_ptr<TestSignatureSigmaV1Builder> builder;

    BOOST_CHECK_NO_THROW(
        builder.reset(new TestSignatureSigmaV1Builder(address, 10, proof, publicKey)));

    auto hash = builder->GetHash();
    BOOST_CHECK_EQUAL(
        "ee7bc07d171b60b62b3a9eba25c62dbf0c320180cef860469ba1dbf9e5387d93",
        HexStr(hash.begin(), hash.end()));
}

BOOST_AUTO_TEST_CASE(sign)
{
    TestSignatureSigmaV1Builder builder(address, 10, proof, publicKey);
    auto signer = GetCoinSigner();

    auto signature = builder.Sign(signer);

    BOOST_CHECK_EQUAL(
        "f4f3070c8dbf329449331fc055bdfc3786994e1547e6ce11246d152db10981a456df5adfe7aae942637ed9e1655f447cc7aa050504c54cfb7a07bac01df84731",
        HexStr(signature.begin(), signature.end()));
}

BOOST_AUTO_TEST_CASE(verify)
{
    TestSignatureSigmaV1Builder builder(address, 10, proof, publicKey);
    std::array<uint8_t, 64> signature;
    auto validSig = ParseHex("f4f3070c8dbf329449331fc055bdfc3786994e1547e6ce11246d152db10981a456df5adfe7aae942637ed9e1655f447cc7aa050504c54cfb7a07bac01df84731");
    auto invalidSig = ParseHex("f4f3070c8dbf329449331fc055bdfc3786994e1547e6ce11246d152db10981a456df5adfe7aae942637ed9e1655f447cc7aa050504c54cfb7a07bac01df84730");

    std::copy(validSig.begin(), validSig.end(), signature.begin());
    BOOST_CHECK_EQUAL(true, builder.Verify(signature));

    std::copy(invalidSig.begin(), invalidSig.end(), signature.begin());
    BOOST_CHECK_EQUAL(false, builder.Verify(signature));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace exodus