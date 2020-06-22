#include "sigmaprimitives.h"

#include "../hash.h"
#include "../sigma/sigma_primitives.h"

#include <openssl/rand.h>

#include <array>
#include <stdexcept>

namespace elysium {

uint160 GetSerialId(const secp_primitives::Scalar &serial)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << serial;
    return Hash160(ss.begin(), ss.end());
}

const SigmaParams DefaultSigmaParams(secp_primitives::GroupElement().set_base_g(), 7, 4);

// SigmaParams Implementation.

SigmaParams::SigmaParams(const secp_primitives::GroupElement& g, unsigned m, unsigned n) :
    g(g),
    m(m),
    n(n)
{
    if (!g.isMember() || g.isInfinity() || m == 0 || n == 0) {
        throw std::invalid_argument("Invalid Sigma parameters");
    }

    std::array<unsigned char, 32> hash;

    g.sha256(hash.data());
    h.reserve(m * n);

    for (unsigned i = 0; i < m * n; i++) {
        h.emplace_back();
        h[i].generate(hash.data());
        h[i].sha256(hash.data());
    }

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    if (!ctx)
        throw ("Failed to create secp256k1's context.");

    try {
        secp256k1::initialize(ctx, [] (unsigned char *buf, size_t size) {
            while (!RAND_bytes(buf, size));
        });
    } catch (std::exception& e) {
        secp256k1_context_destroy(ctx);
        throw ("Failed to initialize secp256k1's context.");
    }
}

SigmaParams::~SigmaParams()
{
    secp256k1::terminate();
    secp256k1_context_destroy(ctx);
}

// SigmaPrivateKey Implementation.

SigmaPrivateKey::SigmaPrivateKey()
{
}

SigmaPrivateKey::SigmaPrivateKey(
    secp_primitives::Scalar const &serial,
    secp_primitives::Scalar const &randomness)
    : serial(serial), randomness(randomness)
{
}

bool SigmaPrivateKey::operator==(const SigmaPrivateKey& other) const
{
    return serial == other.serial && randomness == other.randomness;
}

bool SigmaPrivateKey::operator!=(const SigmaPrivateKey& other) const
{
    return !(*this == other);
}

bool SigmaPrivateKey::IsMember() const
{
    return serial.isMember() && randomness.isMember();
}

bool SigmaPrivateKey::IsValid() const
{
    return IsMember() && !serial.isZero() && !randomness.isZero();
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

SigmaPublicKey::SigmaPublicKey(const SigmaPrivateKey& key, const SigmaParams& params)
{
    Generate(key, params);
}

bool SigmaPublicKey::operator==(const SigmaPublicKey& other) const
{
    return commitment == other.commitment;
}

bool SigmaPublicKey::operator!=(const SigmaPublicKey& other) const
{
    return !(*this == other);
}

bool SigmaPublicKey::IsMember() const
{
    return commitment.isMember();
}

bool SigmaPublicKey::IsValid() const
{
    return IsMember() && !commitment.isInfinity();
}

void SigmaPublicKey::Generate(const SigmaPrivateKey& key, const SigmaParams& params)
{
    if (!key.IsMember()) {
        throw std::invalid_argument("The private key is not valid");
    }

    commitment = sigma::SigmaPrimitives<secp_primitives::Scalar, secp_primitives::GroupElement>::commit(
        params.g,
        key.serial,
        params.h[0],
        key.randomness
    );
}

// SigmaProof Implementation.

SigmaProof::SigmaProof(const SigmaParams& params) :
    params(params),
    proof(params.n, params.m)
{
}

bool SigmaProof::operator==(const SigmaProof& other) const
{
    return proof == other.proof;
}

bool SigmaProof::operator!=(const SigmaProof& other) const
{
    return !(*this == other);
}

} // namespace elysium
