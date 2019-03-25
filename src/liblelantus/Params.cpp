#include "Params.h"

namespace lelantus {

    std::unique_ptr<Params> Params::instance;
Params* Params::get_default() {
    if(instance != nullptr)
        return instance.get();
    else {
        //fixing generator G and H;
       GroupElement g("9216064434961179932092223867844635691966339998754536116709681652691785432045",
                      "33986433546870000256104618635743654523665060392313886665479090285075695067131");
       //fixing n and m; N = n^m = 16,384
       int n = 4;
       int m = 7;
       //fixing bulletproof params
       int _n = 64;
       int max_m = 16;

       instance.reset(new Params(g, n, m, _n, max_m));
        return instance.get();
    }
}

Params::Params(const GroupElement& g, int n, int m, int _n, int max_m):
    n_(n), m_(m), g_(g), _n(_n), max_m(max_m){
    //creating generator for sigma
    this->h_.resize(n*m);
    unsigned char buff0[32] = {0};
    g.sha256(buff0);
    h_[0].generate(buff0);
    for (int i = 1; i < n * m; ++i)
    {
        unsigned char buff[32] = {0};
        h_[i - 1].sha256(buff);
        h_[i].generate(buff);
    }
    //creating generator for bulletproofs
    g_rangeProof.resize(_n * max_m);
    h_rangeProof.resize(_n * max_m);
    g_rangeProof[0].generate(buff0);
    unsigned char buff1[32] = {0};
    g_rangeProof[0].sha256(buff1);
    h_rangeProof[0].generate(buff1);
    for (int i = 1; i < _n * max_m; ++i)
    {
        unsigned char buff[32] = {0};
        h_rangeProof[i-1].sha256(buff);
        g_rangeProof[i].generate(buff);
        unsigned char buff2[32] = {0};
        g_rangeProof[i].sha256(buff2);
        h_rangeProof[i].generate(buff2);
    }
}

Params::~Params(){
}

const GroupElement& Params::get_g() const{
    return g_;
}

const GroupElement& Params::get_h0() const{
    return h_[0];
}

const GroupElement& Params::get_h1() const{
    return h_[1];
}

const std::vector<GroupElement>& Params::get_h() const{
    return h_;
}

const std::vector<GroupElement>& Params::get_bulletproofs_g() const{
    return g_rangeProof;
}
const std::vector<GroupElement>& Params::get_bulletproofs_h() const{
    return h_rangeProof;
}

int Params::get_n() const{
    return n_;
}

int Params::get_m() const{
    return m_;
}

int Params::get_bulletproofs_n() const{
    return _n;
}

} //namespace lelantus
