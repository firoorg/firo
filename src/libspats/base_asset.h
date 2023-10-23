#ifndef FIRO_LIBSPATS_BASE_H
#define FIRO_LIBSPATS_BASE_H

#include "base_asset_proof.h"
#include <secp256k1/include/MultiExponent.h>

namespace spats {

class BaseAsset {
public:
    BaseAsset(const GroupElement& G,const GroupElement& H);

    void prove(const Scalar& y,const Scalar& z, const GroupElement& C, BaseAssetProof& proof);
    void prove(const std::vector<Scalar>& y,const std::vector<Scalar>& z, const std::vector<GroupElement>& C, BaseAssetProof& proof);
    bool verify(const GroupElement& C, const BaseAssetProof& proof);
    bool verify(const std::vector<GroupElement>& C, const BaseAssetProof& proof);

private:
    Scalar challenge(const std::vector<GroupElement>& C, const GroupElement& A);
    const GroupElement& G;
    const GroupElement& H;
};

}

#endif
