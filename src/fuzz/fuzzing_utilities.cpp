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

secp_primitives::GroupElement FuzzedSecp256k1Object::GetMemberGroupElement() {
    secp_primitives::GroupElement ge;
    ge.randomize();
    return ge;
}

std::vector<secp_primitives::GroupElement> FuzzedSecp256k1Object::GetMemberGroupElements(size_t len) {
    std::vector<secp_primitives::GroupElement> ge_vec;
    ge_vec.resize(len);
    for (size_t i = 0; i < len; i++) {
        ge_vec[i] = (GetMemberGroupElement());
    }
    return ge_vec;
}

std::vector<secp_primitives::GroupElement> FuzzedSecp256k1Object::GetRandomGroupVector(size_t len) {
    std::vector<secp_primitives::GroupElement> result;
    result.resize(len);
    for (size_t i = 0; i < len; i++) {
        result[i].randomize();
    }
    return result;
}

std::vector<secp_primitives::GroupElement> FuzzedSecp256k1Object::GetGroupElements(int len) {
    std::vector<secp_primitives::GroupElement> ge_vec;
    ge_vec.reserve(len);
    for (int i = 0; i < len; i++) {
        ge_vec.push_back(GetGroupElement());
    }

    return ge_vec;
}

std::vector<secp_primitives::Scalar> FuzzedSecp256k1Object::GetScalars(size_t len) {
    std::vector<secp_primitives::Scalar> scalar_vec;
    scalar_vec.reserve(len);
    for (int i = 0; i < len; i++) {
        scalar_vec.push_back(GetScalar());
    }

    return scalar_vec;
}

std::vector<secp_primitives::Scalar> FuzzedSecp256k1Object::GetScalarsVector(size_t len) {
    std::vector<secp_primitives::Scalar> scalar_vec;
    scalar_vec.reserve(len);
    for (int i = 0; i < len; i++) {
        scalar_vec.push_back(GetScalar());
    }

    return scalar_vec;
}

secp_primitives::Scalar FuzzedSecp256k1Object::GetScalar_modified() {
    secp_primitives::Scalar s = secp_primitives::Scalar(this->fdp->ConsumeBytes<uint8_t>(256).data());
    return s;
}

std::vector<secp_primitives::Scalar> FuzzedSecp256k1Object::GetScalars_modified(int len) {
    std::vector<secp_primitives::Scalar> scalar_vec;
    scalar_vec.reserve(len);
    for (int i = 0; i < len; i++) {
        scalar_vec.push_back(GetScalar_modified());
    }

    return scalar_vec;
}