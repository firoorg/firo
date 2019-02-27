#ifndef ZCOINSCHNOORPROOVER_H
#define ZCOINSCHNOORPROOVER_H

#include "LelantusPrimitives.h"

namespace lelantus {

template <class Exponent, class GroupElement>
class SchnorrProver {
public:
    SchnorrProver(const GroupElement& g, const GroupElement& h);

    void proof(const Exponent& P, const Exponent& T, SchnorrProof<Exponent, GroupElement>& proof_out);

private:
    const GroupElement& g_;
    const GroupElement& h_;
};

}//namespace lelantus

#include "SchnorrProver.hpp"

#endif //ZCOINSCHNOORPROOVER_H
