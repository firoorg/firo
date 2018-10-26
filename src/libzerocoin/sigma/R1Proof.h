#ifndef ZCOIN_R1PROOF_H
#define ZCOIN_R1PROOF_H

#include <vector>
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include "../common/GeneratorVector.h"

namespace sigma {

template <class Exponent, class GroupElement>
class R1Proof{

public:
    R1Proof() = default;
    void set_A(const GroupElement& A) { A_ = A;}
    void set_C(const GroupElement& C) { C_ = C;}
    void set_D(const GroupElement& D) { D_ = D;}
    void set_f(const std::vector<Exponent> f) { f_ = f;}
    void set_zA(const Exponent ZA) {ZA_ = ZA;}
    void set_zC(const Exponent ZC) {ZC_ = ZC;}

    GroupElement get_A() const {return A_;}
    GroupElement get_C() const {return C_;}
    GroupElement get_D() const {return D_;}
    const std::vector<Exponent>& get_f() const {return f_;}
    Exponent get_ZA() const {return  ZA_;}
    Exponent get_ZC() const {return ZC_;}

private:
    GroupElement A_;
    GroupElement C_;
    GroupElement D_;
    std::vector<Exponent> f_;
    Exponent ZA_;
    Exponent ZC_;
};

}// namespace sigma
#endif //ZCOIN_R1PROOF_H
