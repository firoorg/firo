#ifndef ZCOIN_EXODUS_SIGMAPRIMITIVES_H
#define ZCOIN_EXODUS_SIGMAPRIMITIVES_H

#include "../clientversion.h"
#include "../streams.h"
#include "../uint256.h"
#include "../utilstrencodings.h"

#include "../sigma/sigmaplus_proof.h"
#include "../sigma/sigmaplus_prover.h"
#include "../sigma/sigmaplus_verifier.h"

#include "../secp256k1/include/secp256k1_group.hpp"
#include "../secp256k1/include/secp256k1_scalar.hpp"

#include <boost/optional.hpp>

#include <functional>
#include <iterator>
#include <ostream>
#include <stdexcept>
#include <vector>

#include <assert.h>
#include <inttypes.h>
#include <stddef.h>

namespace exodus {

uint160 GetSerialId(const secp_primitives::Scalar &serial);

class SigmaParams
{
public:
    secp_primitives::GroupElement g;
    unsigned m, n;
    std::vector<secp_primitives::GroupElement> h;
    secp256k1_context *ctx;

public:
    SigmaParams(const secp_primitives::GroupElement& g, unsigned m, unsigned n);
    ~SigmaParams();
};

class SigmaPrivateKey
{
public:
    secp_primitives::Scalar serial;
    secp_primitives::Scalar randomness;

public:
    SigmaPrivateKey();
    SigmaPrivateKey(
        secp_primitives::Scalar const &serial,
        secp_primitives::Scalar const &randomness);

public:
    bool operator==(const SigmaPrivateKey& other) const;
    bool operator!=(const SigmaPrivateKey& other) const;

public:
    bool IsValid() const;

public:
    void Generate();

public:
    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(serial);
        READWRITE(randomness);
    }
};

class SigmaPublicKey
{
public:
    secp_primitives::GroupElement commitment;

public:
    SigmaPublicKey();
    SigmaPublicKey(const SigmaPrivateKey& key, const SigmaParams& params);

public:
    bool operator==(const SigmaPublicKey& other) const;
    bool operator!=(const SigmaPublicKey& other) const;

public:
    bool IsValid() const;

public:
    void Generate(const SigmaPrivateKey& key, const SigmaParams& params);

public:
    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(commitment);
    }
};

class SigmaProof
{
public:
    const SigmaParams& params;
    secp_primitives::Scalar serial;
    sigma::SigmaPlusProof<secp_primitives::Scalar, secp_primitives::GroupElement> proof;

public:
    explicit SigmaProof(const SigmaParams& params);

    template<typename PublicKey>
    SigmaProof(const SigmaParams& params, const SigmaPrivateKey& key, PublicKey first, PublicKey last, bool fPadding) :
        SigmaProof(params)
    {
        Generate(key, first, last, fPadding);
    }

public:
    bool operator==(const SigmaProof& other) const;
    bool operator!=(const SigmaProof& other) const;

public:
    template<typename PublicKey>
    bool Verify(PublicKey first, PublicKey last, bool fPadding) const
    {
        // Create commitment set.
        auto gs = (params.g * serial).inverse();
        std::vector<secp_primitives::GroupElement> commits;

        commits.reserve(std::distance(first, last));

        for (auto it = first; it != last; it++) {
            commits.emplace_back(it->commitment + gs);
        }

        // Verify proof.
        sigma::SigmaPlusVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> verifier(
            params.g,
            params.h,
            params.n,
            params.m
        );

        return verifier.verify(commits, proof, fPadding);
    }

public:
    template<typename PublicKey>
    void Generate(const SigmaPrivateKey& priv, PublicKey first, PublicKey last, bool fPadding)
    {
        if (!priv.IsValid()) {
            throw std::invalid_argument("Private key is not valid");
        }

        // Create commitment set.
        auto gs = (params.g * priv.serial).inverse();
        SigmaPublicKey pub(priv, params);
        std::vector<secp_primitives::GroupElement> commits;
        boost::optional<size_t> index;

        commits.reserve(std::distance(first, last));

        for (auto it = first; it != last; it++) {
            auto& commit = it->commitment;

            if (commit == pub.commitment) {
                index = std::distance(first, it);
            }

            commits.emplace_back(commit + gs);
        }

        if (!index) {
            throw std::invalid_argument("No commitment for private key in the set");
        }

        // Generate proof.
        sigma::SigmaPlusProver<secp_primitives::Scalar, secp_primitives::GroupElement> prover(
            params.g,
            params.h,
            params.n,
            params.m
        );

        prover.proof(commits, *index, priv.randomness, fPadding, proof);
        serial = priv.serial;
    }

public:
    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(serial);
        READWRITE(proof);
    }
};

typedef uint8_t SigmaDenomination;
typedef uint32_t SigmaMintGroup;
typedef uint16_t SigmaMintIndex;

extern const SigmaParams DefaultSigmaParams;

} // namespace exodus

namespace std {

using namespace exodus;

// std::hash specialization.

template<>
struct hash<SigmaPrivateKey>
{
    size_t operator()(const SigmaPrivateKey& k) const
    {
        size_t h = 0;

        h ^= hash<secp_primitives::Scalar>()(k.serial);
        h ^= hash<secp_primitives::Scalar>()(k.randomness);

        return h;
    }
};

template<>
struct hash<SigmaPublicKey>
{
    size_t operator()(const SigmaPublicKey& k) const
    {
        return k.commitment.hash();
    }
};

// basic_ostream supports.

template<typename Char, typename Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const SigmaPrivateKey& k)
{
    return os << "{serial: " << k.serial.GetHex() << ", randomness: " << k.randomness.GetHex() << '}';
}

template<typename Char, typename Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const SigmaPublicKey& k)
{
    return os << "{commitment: " << k.commitment.tostring() << '}';
}

template<typename Char, typename Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const SigmaProof& p)
{
    CDataStream buffer(SER_DISK, CLIENT_VERSION);

    buffer << p.proof;

    return os << "{serial: " << p.serial.GetHex() << ", proof: " << HexStr(buffer.vch) << '}';
}

} // namespace std

#endif // ZCOIN_EXODUS_SIGMAPRIMITIVES_H
