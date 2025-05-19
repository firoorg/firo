#ifndef FIRO_LIBSPATS_TYPE_H
#define FIRO_LIBSPATS_TYPE_H

#include "type_proof.h"
#include <secp256k1/include/MultiExponent.h>

namespace spats
{

class TypeEquality
{
public:
    TypeEquality(const GroupElement& E, const GroupElement& F, const GroupElement& G, const GroupElement& H);

    void prove(const GroupElement& C, const Scalar& w, const Scalar& x, const Scalar& y, const Scalar& z, TypeProof& proof);
    void prove(const std::vector<GroupElement>& C, const Scalar& w, const Scalar& x, const std::vector<Scalar>& y, const std::vector<Scalar>& z, TypeProof& proof);
    bool verify(const GroupElement& C, const TypeProof& proof);
    bool verify(const std::vector<GroupElement>& C, const TypeProof& proof);

private:
    Scalar challenge(const std::vector<GroupElement>& C, const GroupElement& A, const GroupElement& B);
    const GroupElement& E;
    const GroupElement& F;
    const GroupElement& G;
    const GroupElement& H;
};

} // namespace spats

#endif