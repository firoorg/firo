#ifndef ZCOIN_SIGMA_PARAMS_H
#define ZCOIN_SIGMA_PARAMS_H
#include <secp256k1/include/secp256k1_scalar.hpp>
#include <secp256k1/include/secp256k1_group.hpp>
#include <secp256k1/include/secp256k1.hpp>
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

    secp256k1_context *ctx;
};

}//namespace sigma

#endif //ZCOIN_SIGMA_PARAMS_H
