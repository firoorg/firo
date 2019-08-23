#ifndef ZCOIN_EXODUS_SIGMA_H
#define ZCOIN_EXODUS_SIGMA_H

#include "../sigma/params.h"
#include "../sigma/sigmaplus_proof.h"
#include "../sigma/sigmaplus_prover.h"
#include "../sigma/sigmaplus_verifier.h"

#include <GroupElement.h>
#include <Scalar.h>

#include <boost/optional.hpp>

#include <cinttypes>
#include <iterator>
#include <stdexcept>
#include <vector>

#include <assert.h>
#include <stddef.h>

namespace exodus {

// Sigma Cryptographic Primitives.
class SigmaPrivateKey
{
public:
    explicit SigmaPrivateKey(const sigma::Params *params = sigma::Params::get_default());

    const sigma::Params * GetParams() const { return params; };
    const secp_primitives::Scalar& GetSerial() const { return serial; }
    const secp_primitives::Scalar& GetRandomness() const { return randomness; }

    bool operator==(const SigmaPrivateKey& other) const;
    bool operator!=(const SigmaPrivateKey& other) const;

    bool IsValid() const;

    void SetSerial(const secp_primitives::Scalar& v);
    void SetRandomness(const secp_primitives::Scalar& v);
    void Set(const secp_primitives::Scalar& serial, const secp_primitives::Scalar& randomness);
    void Generate();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(serial);
        READWRITE(randomness);
    }

private:
    const sigma::Params *params;
    secp_primitives::Scalar serial;
    secp_primitives::Scalar randomness;
};

class SigmaPublicKey
{
public:
    SigmaPublicKey();
    explicit SigmaPublicKey(const SigmaPrivateKey& pkey);

    bool operator==(const SigmaPublicKey& other) const;

    const secp_primitives::GroupElement& GetCommitment() const { return commitment; }

    bool IsValid() const;

    void SetCommitment(const secp_primitives::GroupElement& v);
    void Generate(const SigmaPrivateKey& pkey);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(commitment);
    }

private:
    secp_primitives::GroupElement commitment;
};

class SigmaProof
{
public:
    SigmaProof();

    const secp_primitives::Scalar& GetSerial() const { return serial; }
    const sigma::SigmaPlusProof<secp_primitives::Scalar, secp_primitives::GroupElement>& GetProof() const { return proof; }

    template<typename Iterator>
    bool Verify(sigma::Params *params, Iterator begin, Iterator end)
    {
        proof.params = params;

        // Create commitment set.
        auto gs = (proof.params->get_g() * serial).inverse();
        std::vector<secp_primitives::GroupElement> commits;

        commits.reserve(std::distance(begin, end));

        for (auto it = begin; it != end; it++) {
            commits.emplace_back(it->GetCommitment() + gs);
        }

        // Verify proof.
        sigma::SigmaPlusVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> verifier(
            proof.params->get_g(),
            proof.params->get_h(),
            proof.params->get_n(),
            proof.params->get_m()
        );

        return verifier.verify(commits, proof);
    }

    void SetSerial(const secp_primitives::Scalar& v);
    void SetProof(const sigma::SigmaPlusProof<secp_primitives::Scalar, secp_primitives::GroupElement>& v);

    template<typename Iterator>
    void Generate(const SigmaPrivateKey& priv, Iterator begin, Iterator end)
    {
        if (!priv.IsValid()) {
            throw std::invalid_argument("Private key is not valid");
        }

        proof.params = priv.GetParams();
        serial = priv.GetSerial();

        // Create commitment set.
        auto gs = (proof.params->get_g() * serial).inverse();
        auto pub = SigmaPublicKey(priv).GetCommitment();
        std::vector<secp_primitives::GroupElement> commits;
        boost::optional<size_t> index;

        commits.reserve(std::distance(begin, end));

        for (auto it = begin; it != end; it++) {
            auto& commit = it->GetCommitment();

            if (commit == pub) {
                index = std::distance(begin, it);
            }

            commits.emplace_back(commit + gs);
        }

        if (!index) {
            throw std::invalid_argument("No commitment for private key in the set");
        }

        // Generate proof.
        sigma::SigmaPlusProver<secp_primitives::Scalar, secp_primitives::GroupElement> prover(
            proof.params->get_g(),
            proof.params->get_h(),
            proof.params->get_n(),
            proof.params->get_m()
        );

        prover.proof(commits, *index, priv.GetRandomness(), proof);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(serial);
        READWRITE(proof);
    }

private:
    secp_primitives::Scalar serial;
    sigma::SigmaPlusProof<secp_primitives::Scalar, secp_primitives::GroupElement> proof;
};

// Exodus Specific.
typedef std::uint8_t DenominationId;

std::pair<SigmaProof, uint16_t> CreateSigmaSpend(
    SigmaPrivateKey const &priv, uint32_t propertyId, uint8_t denomination, uint32_t group);
bool VerifySigmaSpend(uint32_t propertyId, uint8_t denomination, uint32_t group,
    uint16_t groupSize, SigmaProof &proof);

} // namespace exodus

#endif // ZCOIN_EXODUS_SIGMA_H
