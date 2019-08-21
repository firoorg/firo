#include "exodus.h"
#include "sigma.h"

#include "../sigma/sigma_primitives.h"

#include <stdexcept>

#include <assert.h>

namespace exodus {

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

std::pair<SigmaProof, uint16_t> Spend(
    SigmaPrivateKey const &priv, uint32_t propertyId, uint8_t denomination, uint32_t group)
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

    return {p, coinAmount};
}

bool VerifySigmaSpend(uint32_t propertyId, uint8_t denomination, uint32_t group,
    uint16_t coinsInAnonimityGroup, SigmaProof &proof)
{
    LOCK(cs_tally);

    std::vector<SigmaPublicKey> coins;
    coins.reserve(coinsInAnonimityGroup);
    p_mintlistdb->GetAnonimityGroup(
        propertyId, denomination, group, coinsInAnonimityGroup, std::back_inserter(coins)
    );

    return proof.Verify(sigma::Params::get_default(), coins.begin(), coins.end());
}

} // namespace exodus
