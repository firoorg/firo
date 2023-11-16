#include "FuzzedDataProvider.h"
#include "../secp256k1/include/Scalar.h"
#include "../secp256k1/include/GroupElement.h"

class FuzzedSecp256k1Object {
    public: 
        FuzzedSecp256k1Object(FuzzedDataProvider *fdp);

        FuzzedDataProvider *fdp;

        secp_primitives::GroupElement GetGroupElement();
        secp_primitives::Scalar GetScalar();
        secp_primitives::GroupElement GetMemberGroupElement();
        secp_primitives::Scalar GetScalar_modified();

        std::vector<secp_primitives::GroupElement> GetGroupElements(int len);
        std::vector<secp_primitives::Scalar> GetScalars(size_t len);
        std::vector<secp_primitives::GroupElement> GetMemberGroupElements(size_t len);
        std::vector<secp_primitives::GroupElement> GetRandomGroupVector(size_t len);
        std::vector<secp_primitives::Scalar> GetScalars_modified(int len);
        std::vector<secp_primitives::Scalar> GetScalarsVector(size_t len);

};