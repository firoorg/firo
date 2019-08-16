#include "exodus.h"
#include "sigma.h"

#include "../sigma/sigma_primitives.h"

#include <stdexcept>

#include <assert.h>

namespace exodus {

std::size_t PairDenominationScalarHash::operator()(
    std::pair<uint8_t, secp_primitives::Scalar> const &p) const noexcept
{
    std::vector<uint8_t> data;
    data.resize(p.second.memoryRequired());
    p.second.serialize(data.data());

    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().
        Write(reinterpret_cast<const uint8_t*>(&(p.first)), sizeof(p.first)).
        Write(data.data(), data.size()).
        Finalize(hash);

    std::size_t result;
    std::memcpy(&result, hash, sizeof(result));
    return result;
}

// SigmaPrivateKey Implementation.

SigmaPrivateKey::SigmaPrivateKey(const sigma::Params *params) : params(params)
{
    assert(params != nullptr);
}

bool SigmaPrivateKey::IsValid() const
{
    return serial.isMember() && randomness.isMember();
}

void SigmaPrivateKey::SetSerial(const secp_primitives::Scalar& v)
{
    serial = v;
}

void SigmaPrivateKey::SetRandomness(const secp_primitives::Scalar& v)
{
    randomness = v;
}

bool SigmaPrivateKey::operator==(const SigmaPrivateKey& other) const
{
    return serial == other.serial && randomness == other.randomness;
}

bool SigmaPrivateKey::operator!=(const SigmaPrivateKey& other) const
{
    return !(*this == other);
}

void SigmaPrivateKey::Set(const secp_primitives::Scalar& serial, const secp_primitives::Scalar& randomness)
{
    SetSerial(serial);
    SetRandomness(randomness);
}

void SigmaPrivateKey::Generate()
{
    do {
        serial.randomize();
        randomness.randomize();
    } while (!IsValid());
}

// SigmaPublicKey Implementation.

SigmaPublicKey::SigmaPublicKey()
{
}

SigmaPublicKey::SigmaPublicKey(const SigmaPrivateKey& pkey)
{
    Generate(pkey);
}

bool SigmaPublicKey::operator==(const SigmaPublicKey& other) const
{
    return commitment == other.commitment;
}

bool SigmaPublicKey::IsValid() const
{
    return commitment.isMember();
}

void SigmaPublicKey::SetCommitment(const secp_primitives::GroupElement& v)
{
    commitment = v;
}

void SigmaPublicKey::Generate(const SigmaPrivateKey& pkey)
{
    if (!pkey.IsValid()) {
        throw std::invalid_argument("The private key is not valid");
    }

    commitment = sigma::SigmaPrimitives<secp_primitives::Scalar, secp_primitives::GroupElement>::commit(
        pkey.GetParams()->get_g(),
        pkey.GetSerial(),
        pkey.GetParams()->get_h0(),
        pkey.GetRandomness()
    );
}

// SigmaProof Implementation.

SigmaProof::SigmaProof() : proof(nullptr)
{
}

void SigmaProof::SetSerial(const secp_primitives::Scalar& v)
{
    serial = v;
}

void SigmaProof::SetProof(const sigma::SigmaPlusProof<secp_primitives::Scalar, secp_primitives::GroupElement>& v)
{
    proof = v;
}

SigmaSpend Spend(SigmaPrivateKey const &priv, uint32_t propertyId, uint8_t denomination, uint32_t group)
{
    LOCK(cs_tally);
    auto coinAmount = p_mintlistdb->GetMintCount(propertyId, denomination, group);

    if (coinAmount > UINT16_MAX) {
        throw std::runtime_error("amount of coins in group is invalid");
    }

    std::vector<SigmaPublicKey> coins;
    coins.reserve(coinAmount);
    p_mintlistdb->GetAnonimityGroup(
        propertyId, denomination, group, coinAmount, std::back_inserter(coins)
    );

    SigmaProof p;
    p.Generate(priv, coins.begin(), coins.end());

    return SigmaSpend(denomination, group, static_cast<uint16_t>(coinAmount), p);
}

bool VerifySigmaSpend(uint32_t propertyId, SigmaSpend const &spend)
{
    LOCK(cs_tally);

    std::vector<SigmaPublicKey> coins;
    coins.reserve(spend.index);
    p_mintlistdb->GetAnonimityGroup(
        propertyId, spend.denomination, spend.group, spend.index, std::back_inserter(coins)
    );

    auto proof = spend.proof;
    return proof.Verify(sigma::Params::get_default(), coins.begin(), coins.end());
}

} // namespace exodus
