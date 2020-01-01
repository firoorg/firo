#include "chainparams.h"
#include "params.h"
#include <openssl/rand.h>

namespace sigma {

Params* Params::instance;
Params* Params::get_default() {
    if(instance != nullptr)
        return instance;
    else {
        //fixing generator G;
        GroupElement g;

        if(!(::Params().GetConsensus().IsTestnet())) {
            unsigned char buff[32] = {0};
            GroupElement base;
            base.set_base_g();
            base.sha256(buff);
            g.generate(buff);
        }
        else
            g = GroupElement("9216064434961179932092223867844635691966339998754536116709681652691785432045",
                             "33986433546870000256104618635743654523665060392313886665479090285075695067131");

        //fixing n and m; N = n^m = 16,384
        int n = 4;
        int m = 7;
        instance = new Params(g, n, m);
        return instance;
    }
}

Params::Params(const GroupElement& g, int n, int m) :
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

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    if (!ctx)
        throw ("Failed to create secp256k1's context.");

    try {
        secp256k1::initialize(ctx, [] (unsigned char *buf, size_t size) {
            while (!RAND_bytes(buf, size));
        });
    } catch (std::exception& e) {
        secp256k1_context_destroy(ctx);
        throw ("Failed to initialize secp256k1's context.");
    }
}

Params::~Params(){
    secp256k1::terminate();
    secp256k1_context_destroy(ctx);
    delete instance;
}

const GroupElement& Params::get_g() const{
    return g_;
}
const GroupElement& Params::get_h0() const{
    return h_[0];
}

const std::vector<GroupElement>& Params::get_h() const{
    return h_;
}

uint64_t Params::get_n() const{
    return n_;
}
uint64_t Params::get_m() const{
    return m_;
}

} //namespace sigma
