#ifndef ZCOIN_SIGMA_PARAMS_H
#define ZCOIN_SIGMA_PARAMS_H
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include <serialize.h>

using namespace secp_primitives;

namespace sigma {

class ParamsV3{
public:
    static ParamsV3* get_default();
    const GroupElement& get_g() const;
    const GroupElement& get_h0() const;
    const std::vector<GroupElement>& get_h() const;

private:
   ParamsV3(const GroupElement& g, const GroupElement& h, int n, int m);
    ~ParamsV3();

private:
    static ParamsV3* instance;
    GroupElement g_;
    std::vector<GroupElement> h_;
    int m_;
    int n_;
};

}//namespace sigma

#endif //ZCOIN_SIGMA_PARAMS_H
