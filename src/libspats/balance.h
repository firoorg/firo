#ifndef FIRO_LIBSPATS_BALANCE_H
#define FIRO_LIBSPATS_BALANCE_H

#include "balance_proof.h"

namespace spats {

class Balance {
public:
    Balance(const GroupElement& E, const GroupElement& F, const GroupElement& H);

    void prove(const GroupElement& C, const Scalar& w, const Scalar& x, const Scalar& z, BalanceProof& proof);
    bool verify(const GroupElement& C, const BalanceProof& proof);

private:
    Scalar challenge(const GroupElement& Y, const GroupElement& A);
    const GroupElement& E;
    const GroupElement& F;
    const GroupElement& H;
};

}

#endif
