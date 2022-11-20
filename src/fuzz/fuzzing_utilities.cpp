#include "fuzzing_utilities.h"

FuzzedSecp256k1Object::FuzzedSecp256k1Object(FuzzedDataProvider *fdp) {
    this->fdp = fdp;
}

secp_primitives::GroupElement FuzzedSecp256k1Object::GetGroupElement() {
    char* x = (char *)this->fdp->ConsumeBytes<uint8_t>(256).data();
    char* y = (char *)this->fdp->ConsumeBytes<uint8_t>(256).data();
    secp_primitives::GroupElement ge = secp_primitives::GroupElement(x, y);

    return ge;
}

secp_primitives::Scalar FuzzedSecp256k1Object::GetScalar() {
    uint64_t value = this->fdp->ConsumeIntegral<uint64_t>();
    secp_primitives::Scalar s = secp_primitives::Scalar(value);

    return s;

}