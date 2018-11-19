#include "Params.h"

namespace sigma {
    V3Params* V3Params::instance;
V3Params* V3Params::get_default() {
    if(instance != nullptr)
        return instance;
    else {
        //fixing generator G and H;
       GroupElement g("9216064434961179932092223867844635691966339998754536116709681652691785432045",
                      "33986433546870000256104618635743654523665060392313886665479090285075695067131");
       GroupElement h("50204771751011461524623624559944050110546921468100198079190811223951215371253",
                      "71960464583475414858258501028406090652116947054627619400863446545880957517934");
       //fixing n and m; N = n^m = 16,384
       int n = 4;
       int m = 7;
       instance = new V3Params(g, h, n, m);
        return instance;
    }
}

V3Params::V3Params(const GroupElement& g, const GroupElement& h, int n, int m):
    n_(n), m_(m), g_(g){
    h_.reserve(28);
    h_.emplace_back(h);
    for(int i = 1; i < n*m; ++i) {
        h_.push_back(GroupElement());
        unsigned char buff[32] = {0};
        h_[i - 1].sha256(buff);
        h_[i].generate(buff);
    }
}

V3Params::~V3Params(){
    delete instance;
}

const GroupElement& V3Params::get_g() const{
    return g_;
}
const GroupElement& V3Params::get_h0() const{
    return h_[0];
}

const std::vector<GroupElement>& V3Params::get_h() const{
    return h_;
}

} //namespace sigma
