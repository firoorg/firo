#include "params.h"

namespace sigma {

ParamsV3* ParamsV3::instance;
ParamsV3* ParamsV3::get_default() {
    if(instance != nullptr)
        return instance;
    else {
        //fixing generator G;
        GroupElement g("9216064434961179932092223867844635691966339998754536116709681652691785432045",
                       "33986433546870000256104618635743654523665060392313886665479090285075695067131");
        //fixing n and m; N = n^m = 16,384
        int n = 4;
        int m = 7;
        instance = new ParamsV3(g, n, m);
        return instance;
    }
}

ParamsV3::ParamsV3(const GroupElement& g, int n, int m) :
    g_(g),
    m_(m),
    n_(n)
{
    unsigned char buff0[32] = {0};
    g.sha256(buff0);
    GroupElement h0;
    h0.generate(buff0);
    h_.reserve(28);
    h_.emplace_back(h0);
    for(int i = 1; i < n*m; ++i) {
        h_.push_back(GroupElement());
        unsigned char buff[32] = {0};
        h_[i - 1].sha256(buff);
        h_[i].generate(buff);
    }
}

ParamsV3::~ParamsV3(){
    delete instance;
}

const GroupElement& ParamsV3::get_g() const{
    return g_;
}
const GroupElement& ParamsV3::get_h0() const{
    return h_[0];
}

const std::vector<GroupElement>& ParamsV3::get_h() const{
    return h_;
}

uint64_t ParamsV3::get_n() const{
    return n_;
}
uint64_t ParamsV3::get_m() const{
    return m_;
}

} //namespace sigma
