#include "FuzzedDataProvider.h"
#include "../secp256k1/include/Scalar.h"
#include "../secp256k1/include/GroupElement.h"

class FuzzedSecp256k1Object {
    public: 
        FuzzedSecp256k1Object(FuzzedDataProvider *fdp);
        ~FuzzedSecp256k1Object();

        FuzzedDataProvider *fdp;

        secp_primitives::GroupElement GetGroupElement();
        secp_primitives::Scalar GetScalar();

        std::vector<secp_primitives::GroupElement> GetGroupElements(int len);
        std::vector<secp_primitives::Scalar> GetScalars(int len);
};