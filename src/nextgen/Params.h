#ifndef ZCOIN_NEXTGEN_PARAMS_H
#define ZCOIN_NEXTGEN_PARAMS_H
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include <serialize.h>

using namespace secp_primitives;

namespace nextgen {

class Params{
public:
    static Params* get_default();
    const GroupElement& get_g() const;
    const GroupElement& get_h0() const;
    const GroupElement& get_h1() const;
    const std::vector<GroupElement>& get_h() const;
    int get_n() const;
    int get_m() const;
    ~Params();
private:
    Params(const GroupElement& g, const GroupElement& h, int n, int m);


private:
    static  std::unique_ptr<Params> instance;
    GroupElement g_;
    std::vector<GroupElement> h_;
    int m_;
    int n_;
};

}//namespace nextgen

#endif //ZCOIN_NEXTGEN_PARAMS_H
