#ifndef FIRO_LIBSPARK_SPATS_NFT_HOLDING_H
#define FIRO_LIBSPARK_SPATS_NFT_HOLDING_H

#include "../params.h"

namespace spark {

/**
 * Off-chain proof that the prover holds one NFT coin.
 * The statement is the coin serial commitment S, value commitment C, link tag T,
 * and the claimed asset type and identifier. The proof shows C opens to value 1
 * and that T is the tag of S. It is bound to a message.
 * A verifier must also check that S and C are on its ledger and that T is unspent.
 */
class NftHoldingProof {
public:
    GroupElement S;
    GroupElement C;
    GroupElement T;
    Scalar a;
    Scalar iota;
    GroupElement As;
    GroupElement At;
    GroupElement Am;
    Scalar ts;
    Scalar tr;
    Scalar tm;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(S);
        READWRITE(C);
        READWRITE(T);
        READWRITE(a);
        READWRITE(iota);
        READWRITE(As);
        READWRITE(At);
        READWRITE(Am);
        READWRITE(ts);
        READWRITE(tr);
        READWRITE(tm);
    }
};

/**
 * Prove knowledge of the serial scalar, spend-key scalar, and value mask for an NFT coin.
 * @throws std::invalid_argument when the witness does not open the coin.
 */
NftHoldingProof ProveNftHolding(
    const Params* params,
    const GroupElement& S,
    const GroupElement& C,
    const GroupElement& T,
    const Scalar& a,
    const Scalar& iota,
    const Scalar& serial,
    const Scalar& spend_r,
    const Scalar& value_mask,
    const std::vector<unsigned char>& message);

/** Check the proof against its statement and message. Does not consult the ledger. */
bool VerifyNftHolding(const Params* params, const NftHoldingProof& proof, const std::vector<unsigned char>& message);

}

#endif
