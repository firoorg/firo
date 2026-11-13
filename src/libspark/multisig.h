#ifndef FIRO_LIBSPARK_MULTISIG_H
#define FIRO_LIBSPARK_MULTISIG_H

#include "aead.h"
#include "chaum.h"
#include "keys.h"

namespace spark {

using namespace secp_primitives;

// Threshold multisignature for Spark spends, as described in doc/spark-multisig.md
// (section 5 of the Lelantus Spark paper).
//
// A group of n participants shares one Spark wallet. Each holds the group's full view
// key and a share of its spend key, and any `threshold` of them can authorize a spend.
// The proof they produce verifies like any other, so nothing on chain shows a group.
//
// Participants are named by secp256k1 public keys. Sorting the keys by their compressed
// encoding assigns the identifiers 1..n, so the order a caller lists them in never
// matters. The same keys protect the protocol messages: whatever is secret travels
// encrypted to its recipients, which leaves the authenticity of the participant keys
// as the one thing the participants have to establish among themselves.

const std::size_t MULTISIG_MAX_PARTICIPANTS = 16;

// What a participant keeps once key generation has completed
class MultisigKey {
public:
    // A participant key in its 33-byte compressed public key encoding
    static GroupElement parse_participant(const std::vector<unsigned char>& compressed);
    static std::vector<unsigned char> serialize_participant(const GroupElement& key);

    FullViewKey get_full_view_key(const Params* params) const;
    // Y_index: the public counterpart of the spend key share of participant `index`
    GroupElement get_verification_share(std::size_t index) const;
    // This participant's spend key share. `secret` is the secret of its participant key.
    Scalar get_share(const Params* params, const Scalar& secret) const;

    // Encrypt a message for the group, and decrypt one. The key comes from the view
    // key, which is exactly what the participants share, so a sealed message can pass
    // through any relay without exposing the transaction or its signing transcript.
    std::vector<unsigned char> seal(const Params* params, CDataStream& data) const;
    CDataStream open(const Params* params, const std::vector<unsigned char>& sealed) const;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        uint8_t version = 1;
        READWRITE(version);
        if (version != 1) {
            throw std::invalid_argument("Unsupported multisig key version");
        }
        READWRITE(threshold);
        READWRITE(participants);
        READWRITE(index);
        READWRITE(s1);
        READWRITE(s2);
        READWRITE(commitments);
        READWRITE(share);
    }

    uint32_t threshold = 0;
    std::vector<GroupElement> participants; // participant keys, ordered by identifier
    uint32_t index = 0; // identifier of the participant holding this key
    Scalar s1, s2; // the group's view key
    std::vector<GroupElement> commitments; // to the coefficients of the group's polynomial; the first is D
    AEADEncryptedData share; // spend key share, encrypted to the participant's own key

private:
    friend class MultisigKeygen;
    GroupElement storage_key(const Params* params, const Scalar& secret) const;
    GroupElement seal_key(const Params* params, const Scalar& salt) const;
};

// A participant's key generation message. One message serves every recipient: it grows
// from round one (commitments) to round two (shares), and each share is encrypted to
// the participant it is meant for.
struct MultisigKeygenMessage {
    GroupElement key; // the sender's participant key
    std::vector<GroupElement> C; // commitments to the coefficients of the sender's polynomial
    GroupElement R; // proof of knowledge of the constant coefficient
    Scalar mu;
    std::vector<unsigned char> view_commitment; // binds the sender's view key contributions until round two reveals them
    std::vector<AEADEncryptedData> shares; // round two, by recipient identifier: polynomial share and view key contributions

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        uint8_t version = 1;
        READWRITE(version);
        if (version != 1) {
            throw std::invalid_argument("Unsupported multisig message version");
        }
        READWRITE(key);
        READWRITE(C);
        READWRITE(R);
        READWRITE(mu);
        READWRITE(view_commitment);
        READWRITE(shares);
    }
};

// Distributed key generation for one participant.
//
// Every value a participant contributes is derived from its secret key and the group
// parameters, so the rounds hold no state between calls and repeat identically. Shares
// only ever go to the participant keys those values were derived for, which keeps a
// replayed round from handing out further points of the polynomial.
class MultisigKeygen {
public:
    // `participants` lists every participant key, in any order. `secret` must be the
    // secret of one of them.
    MultisigKeygen(
        const Params* params,
        std::size_t threshold,
        const std::vector<GroupElement>& participants,
        const Scalar& secret);

    const std::vector<GroupElement>& get_participants() const { return participants; }
    std::size_t get_index() const { return index; }

    // Round one: commit to this participant's polynomial and view key contributions
    MultisigKeygenMessage round1() const;
    // Round two: given the round one message of every participant, add the shares
    MultisigKeygenMessage round2(const std::vector<MultisigKeygenMessage>& messages) const;
    // Given the round two message of every participant, verify all of it and derive the
    // key. Success means every participant whose share decrypted worked from the same
    // round one messages; the participants still confirm among themselves that each of
    // them completed and reached the same address before the wallet receives funds.
    MultisigKey finalize(const std::vector<MultisigKeygenMessage>& messages) const;

private:
    Scalar derive(const std::string& purpose, uint64_t i, const std::vector<unsigned char>& data = {}) const;
    Scalar pok_challenge(std::size_t sender, const MultisigKeygenMessage& message) const;
    std::vector<unsigned char> view_commitment(std::size_t sender, const Scalar& s1, const Scalar& s2) const;
    std::vector<MultisigKeygenMessage> check(const std::vector<MultisigKeygenMessage>& messages) const;
    std::vector<unsigned char> round1_hash(const std::vector<MultisigKeygenMessage>& ordered) const;
    GroupElement share_key(const std::vector<unsigned char>& transcript, std::size_t sender, std::size_t recipient) const;
    Scalar aggregate(const std::string& label, const std::vector<Scalar>& contributions) const;

    const Params* params;
    std::size_t threshold;
    std::vector<GroupElement> participants; // ordered by identifier
    Scalar secret;
    std::size_t index; // this participant's identifier
    std::vector<unsigned char> context; // binds the threshold and the participant keys
};

// One signer's nonces for a spend, one pair per transaction input. A nonce authorizes
// a single transaction: it must never be stored where a restart or a restored backup
// could bring it back, and never be used again once a signature share has been made.
struct MultisigNonce {
    std::vector<Scalar> d, e;
};

// The public commitments to a signer's nonces
struct MultisigCommitment {
    uint32_t index = 0; // signer identifier
    std::vector<GroupElement> D, E;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(index);
        READWRITE(D);
        READWRITE(E);
    }
};

// A signer's response for each transaction input
struct MultisigShare {
    uint32_t index = 0; // signer identifier
    std::vector<Scalar> z;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(index);
        READWRITE(z);
    }
};

// Threshold production of the Chaum proof that authorizes a V2 spend.
//
// V2 proves each input on its own under one shared challenge, so the single-input
// signing of the paper is run once per input with its own nonce pair. A signer's
// binding factors commit to the whole session: every signer's commitments for every
// input, and everything else the challenge of the proof is computed from. If any of
// that could change while the binding factors stayed the same, a cosigner could steer
// the challenge after seeing the nonce commitments, and signatures from parallel
// sessions could be combined into one for a transaction nobody approved.
class MultisigSession {
public:
    // Everything the proof's challenge commits to apart from the proof's own
    // commitments. `mu`, `context`, `S` and `T` come from the spend transaction
    // (getBindingHash, getChaumContext, getS1, getUsedLTags).
    static Scalar statement_hash(
        const Params* params,
        const Scalar& mu,
        const ChaumV2Context& context,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T);

    // Sample this signer's nonces for a spend of `inputs` coins. The randomness is
    // mixed with `secret`, any secret of the signer, so that a weak random number
    // generator alone does not expose the nonces.
    static MultisigCommitment commit(const Params* params, std::size_t index, std::size_t inputs, const Scalar& secret, MultisigNonce& nonce);

    // `commitments` holds exactly `threshold` signers
    MultisigSession(
        const Params* params,
        const MultisigKey& key,
        const Scalar& mu,
        const ChaumV2Context& context,
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& T,
        const std::vector<MultisigCommitment>& commitments);

    // This signer's response. The caller discards `nonce` before releasing the result.
    MultisigShare sign(const Scalar& secret, const MultisigNonce& nonce) const;
    bool verify(const MultisigShare& share) const;
    // Verify every signer's response and assemble the proof. `serials` are the serial
    // numbers of the spent coins, which any holder of the full view key can recover.
    ChaumProofV2 combine(const std::vector<Scalar>& serials, const std::vector<MultisigShare>& shares) const;

private:
    std::size_t position(std::size_t index) const;

    const Params* params;
    MultisigKey key;
    Scalar mu;
    ChaumV2Context context;
    std::vector<GroupElement> S, T;
    std::vector<MultisigCommitment> commitments; // ordered by signer identifier
    std::vector<std::vector<Scalar>> rho; // binding factors, by signer and input
    std::vector<Scalar> lambda; // interpolation coefficient of each signer
    std::vector<Scalar> a, b; // per-input nonces for the serial number and its mask
    ChaumProofV2 proof; // the commitments A1 and A2
    Scalar c;
};

}

#endif
