#include "ecdsasignature.h"

#include <stdexcept>

namespace elysium {

ECDSASignature::ECDSASignature() : valid(false)
{
}

ECDSASignature::ECDSASignature(unsigned char const *signature, size_t len) : valid(false)
{
    if (len >= 70 && len <= 72) {
        if (1 == secp256k1_ecdsa_signature_parse_der(
            Context(),
            &(this->signature), 
            signature,
            len))
        {
            valid = true;
        }
    } else {
        throw std::invalid_argument("Signature encoding type is not supported");
    }
}

bool ECDSASignature::Valid() const
{  
    return valid;
}

std::vector<unsigned char> ECDSASignature::Data() const
{
    std::vector<unsigned char> result;
    result.resize(SIGNATURE_DER_SERIALIZED_SIZE);

    size_t outLen = SIGNATURE_DER_SERIALIZED_SIZE;
    if (1 != secp256k1_ecdsa_signature_serialize_der(
        Context(),
        result.data(),
        &outLen,
        &signature)) {
        throw std::runtime_error("Serialized size is in valid");
    }

    return result;
}

} // namespace elysium