#include "balance.h"
#include "transcript.h"

namespace spats{

Balance::Balance(const GroupElement& E_, const GroupElement& F_, const GroupElement& H_):
    E(E_),F(F_),H(H_){
}

Scalar Balance::challenge(
        const GroupElement& C,
        const GroupElement& A) {
    Transcript transcript(LABEL_TRANSCRIPT_BALANCE);
    transcript.add("E", E);
    transcript.add("F", F);
    transcript.add("H", H);
    transcript.add("C", C);
    transcript.add("A", A);

    return transcript.challenge("c");
}

void Balance::prove(const GroupElement& C, const Scalar& w, const Scalar& x, const Scalar& z, BalanceProof& proof) {

    if (E*w+F*x+H*z != C){
        throw std::invalid_argument("Bad Balance statement!");
    }

    Scalar rw;
    Scalar rx;
    Scalar rz;
    rw.randomize();
    rx.randomize();
    rz.randomize();
    proof.A = E*rw + F*rx + H*rz;

    const Scalar c = challenge(C, proof.A);

    proof.tw = rw + c*w;
    proof.tx = rx + c*x;
    proof.tz = rz + c*z;

}

bool Balance::verify(const GroupElement& C, const BalanceProof& proof) {
    const GroupElement check1 = E*proof.tw + F*proof.tx + H*proof.tz;

    const Scalar c = challenge(C, proof.A);
    const GroupElement check2 = proof.A + C*c;

    return (check2+check1.inverse()).isInfinity();
}

}