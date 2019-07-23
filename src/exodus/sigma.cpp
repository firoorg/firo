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

void SigmaPrivateKey::Set(const secp_primitives::Scalar& serial, const secp_primitives::Scalar& randomness)
{
    SetSerial(serial);
    SetRandomness(randomness);
}

void SigmaPrivateKey::Generate()
{
    serial.randomize();
    randomness.randomize();
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

} // namespace exodus
