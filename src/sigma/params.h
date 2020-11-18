#ifndef FIRO_SIGMA_PARAMS_H
#define FIRO_SIGMA_PARAMS_H
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include <serialize.h>

using namespace secp_primitives;

namespace sigma {

class Params {
public:
    static Params* get_default();
    const GroupElement& get_g() const;
    const GroupElement& get_h0() const;
    const std::vector<GroupElement>& get_h() const;
    uint64_t get_n() const;
    uint64_t get_m() const;

private:
   Params(const GroupElement& g, int n, int m);
    ~Params();

private:
    static Params* instance;
    GroupElement g_;
    std::vector<GroupElement> h_;
    int m_;
    int n_;
};

}//namespace sigma

#endif //FIRO_SIGMA_PARAMS_H
