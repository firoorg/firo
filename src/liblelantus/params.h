#ifndef ZCOIN_LELANTUS_PARAMS_H
#define ZCOIN_LELANTUS_PARAMS_H
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include <serialize.h>

using namespace secp_primitives;

namespace lelantus {

class Params{
public:
    static Params* get_default();
    const GroupElement& get_g() const;
    const GroupElement& get_h0() const;
    const GroupElement& get_h1() const;
    const std::vector<GroupElement>& get_h() const;
    const std::vector<GroupElement>& get_bulletproofs_g() const;
    const std::vector<GroupElement>& get_bulletproofs_h() const;
    int get_n() const;
    int get_m() const;
    int get_bulletproofs_n() const;
    ~Params();
private:
    Params(const GroupElement& g, int n, int m, int _n, int max_m);


private:
    static  std::unique_ptr<Params> instance;
    //sigma params
    GroupElement g_;
    std::vector<GroupElement> h_;
    int m_;
    int n_;
    //bulletproof params
    int _n;
    int max_m;
    std::vector<GroupElement> g_rangeProof;
    std::vector<GroupElement> h_rangeProof;
};

}//namespace lelantus

#endif //ZCOIN_LELANTUS_PARAMS_H
