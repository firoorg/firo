#ifndef ZCOIN_SIGMA_PARAMS_H
#define ZCOIN_SIGMA_PARAMS_H
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include <serialize.h>

using namespace secp_primitives;

namespace sigma {

class V3Params{
public:
    static V3Params* get_default();
    const GroupElement& get_g() const;
    const GroupElement& get_h0() const;
    const std::vector<GroupElement>& get_h() const;

private:
    V3Params(const GroupElement& g, const GroupElement& h, int n, int m);
    ~V3Params();

private:
    static V3Params* instance;
    GroupElement g_;
    std::vector<GroupElement> h_;
    int m_;
    int n_;
};

}//namespace sigma

#endif //ZCOIN_SIGMA_PARAMS_H
