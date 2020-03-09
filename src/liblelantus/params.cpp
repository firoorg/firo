#include "params.h"
#include <iostream>
namespace lelantus {

    std::unique_ptr<Params> Params::instance;
Params const* Params::get_default() {
    if(instance != nullptr)
        return instance.get();
    else {
       //fixing generator G;
       GroupElement g;
       unsigned char buff[32] = {0};
       GroupElement base;
       base.set_base_g();
       base.sha256(buff);
       g.generate(buff);
       //fixing n and m; N = n^m = 65,536
       int n = 16;
       int m = 4;
       //fixing bulletproof params
       int n_rangeProof = 64;
       int max_m_rangeProof = 16;

       instance.reset(new Params(g, n, m, n_rangeProof, max_m_rangeProof));
        return instance.get();
    }
}

Params::Params(const GroupElement& g_, int n_sigma_, int m_sigma_, int n_rangeProof_, int max_m_rangeProof_):
    g(g_),
    n_sigma(n_sigma_),
    m_sigma(m_sigma_),
    n_rangeProof(n_rangeProof_),
    max_m_rangeProof(max_m_rangeProof_)
{
    //creating generators for sigma
    this->h_sigma.resize(n_sigma * m_sigma);
    unsigned char buff0[32] = {0};
    g.sha256(buff0);
    h_sigma[0].generate(buff0);
    for (int i = 1; i < n_sigma * m_sigma; ++i)
    {
        unsigned char buff[32] = {0};
        h_sigma[i - 1].sha256(buff);
        h_sigma[i].generate(buff);
    }

    //creating generators for bulletproofs
    g_rangeProof.resize(n_rangeProof * max_m_rangeProof);
    h_rangeProof.resize(n_rangeProof * max_m_rangeProof);
    g_rangeProof[0].generate(buff0);
    unsigned char buff1[32] = {0};
    g_rangeProof[0].sha256(buff1);
    h_rangeProof[0].generate(buff1);
    for (int i = 1; i < n_rangeProof * max_m_rangeProof; ++i)
    {
        unsigned char buff[32] = {0};
        h_rangeProof[i-1].sha256(buff);
        g_rangeProof[i].generate(buff);
        unsigned char buff2[32] = {0};
        g_rangeProof[i].sha256(buff2);
        h_rangeProof[i].generate(buff2);
    }
}

const GroupElement& Params::get_g() const{
    return g;
}

const GroupElement& Params::get_h0() const{
    return h_sigma[0];
}

const GroupElement& Params::get_h1() const{
    return h_sigma[1];
}

const std::vector<GroupElement>& Params::get_sigma_h() const{
    return h_sigma;
}

const std::vector<GroupElement>& Params::get_bulletproofs_g() const{
    return g_rangeProof;
}
const std::vector<GroupElement>& Params::get_bulletproofs_h() const{
    return h_rangeProof;
}

int Params::get_sigma_n() const{
    return n_sigma;
}

int Params::get_sigma_m() const{
    return m_sigma;
}

int Params::get_bulletproofs_n() const{
    return n_rangeProof;
}

} //namespace lelantus
