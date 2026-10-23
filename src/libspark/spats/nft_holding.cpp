#include "nft_holding.h"

#include "../transcript.h"
#include "../util.h"

namespace spark {

namespace {

Scalar Challenge(
    const Params* params,
    const NftHoldingProof& proof,
    const std::vector<unsigned char>& message)
{
    Transcript transcript(LABEL_TRANSCRIPT_NFT_HOLDING);
    transcript.add("E", params->get_E());
    transcript.add("F", params->get_F());
    transcript.add("G", params->get_G());
    transcript.add("H", params->get_H());
    transcript.add("U", params->get_U());
    transcript.add("S", proof.S);
    transcript.add("C", proof.C);
    transcript.add("T", proof.T);
    transcript.add("a", proof.a);
    transcript.add("iota", proof.iota);
    transcript.add("message", message);
    transcript.add("As", proof.As);
    transcript.add("At", proof.At);
    transcript.add("Am", proof.Am);
    return transcript.challenge("c");
}

bool OpensCoin(
    const Params* params,
    const GroupElement& S,
    const GroupElement& C,
    const GroupElement& T,
    const Scalar& a,
    const Scalar& iota,
    const Scalar& serial,
    const Scalar& spend_r,
    const Scalar& value_mask)
{
    const GroupElement serial_commitment = params->get_F() * serial + params->get_G() * spend_r;
    const GroupElement tag_commitment = T * serial + params->get_G() * spend_r;
    const GroupElement value_commitment =
        params->get_E() * a +
        params->get_F() * iota +
        params->get_G() * Scalar(uint64_t(1)) +
        params->get_H() * value_mask;
    return serial_commitment == S && tag_commitment == params->get_U() && value_commitment == C;
}

}

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
    const std::vector<unsigned char>& message)
{
    if (!params)
        throw std::invalid_argument("Missing Spark parameters");
    if (!OpensCoin(params, S, C, T, a, iota, serial, spend_r, value_mask))
        throw std::invalid_argument("NFT holding witness does not open the coin");

    NftHoldingProof proof;
    proof.S = S;
    proof.C = C;
    proof.T = T;
    proof.a = a;
    proof.iota = iota;

    Scalar rs, rr, rm, challenge;
    do {
        rs.randomize();
        rr.randomize();
        rm.randomize();
        proof.As = params->get_F() * rs + params->get_G() * rr;
        proof.At = T * rs + params->get_G() * rr;
        proof.Am = params->get_H() * rm;
        challenge = Challenge(params, proof, message);
    } while (challenge.isZero());

    proof.ts = rs + challenge * serial;
    proof.tr = rr + challenge * spend_r;
    proof.tm = rm + challenge * value_mask;
    return proof;
}

bool VerifyNftHolding(const Params* params, const NftHoldingProof& proof, const std::vector<unsigned char>& message)
{
    if (!params || proof.T.isInfinity() || proof.As.isInfinity() || proof.At.isInfinity() || proof.Am.isInfinity())
        return false;

    const Scalar challenge = Challenge(params, proof, message);
    if (challenge.isZero())
        return false;

    const GroupElement serial_right = proof.As + proof.S * challenge;
    const GroupElement serial_left = params->get_F() * proof.ts + params->get_G() * proof.tr;
    const GroupElement tag_right = proof.At + params->get_U() * challenge;
    const GroupElement tag_left = proof.T * proof.ts + params->get_G() * proof.tr;
    const GroupElement value_statement =
        proof.C +
        (params->get_E() * proof.a).inverse() +
        (params->get_F() * proof.iota).inverse() +
        (params->get_G() * Scalar(uint64_t(1))).inverse();
    const GroupElement value_right = proof.Am + value_statement * challenge;
    const GroupElement value_left = params->get_H() * proof.tm;
    return serial_left == serial_right && tag_left == tag_right && value_left == value_right;
}

}
