#include "../fuzzing_utilities.h"
#include "../FuzzedDataProvider.h"
#include "../../libspark/bpplus.h"
#include "../../libspark/bpplus_proof.h"
#include <cassert>


extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    FuzzedDataProvider fdp(buf, len);
    FuzzedSecp256k1Object fsp(&fdp);

    /** Single Proof **/
    size_t N0 = fdp.ConsumeIntegralInRange<size_t>(0,64);
    size_t M0 = fdp.ConsumeIntegral<size_t>();

    N0 = 64;
    M0 = 4;
    // Generators
    GroupElement G0, H0;
    G0.randomize();
    H0.randomize();

    std::vector<GroupElement> Gi0, Hi0;
    size_t generators_needed = N0*M0;
    if (!spark::is_nonzero_power_of_2(generators_needed)) {
        generators_needed = 1 << (spark::log2(N0*M0) + 1);
    }

    Gi0.resize(generators_needed);
    Hi0.resize(generators_needed);
    for (size_t i=0; i < generators_needed; i++) {
        Gi0[i].randomize();
        Hi0[i].randomize();
    }

    // Commitments
    std::vector<Scalar> v, r;
    v.resize(M0);
    r.resize(M0);
    // v = fsp.GetScalars(M0);
    // r = fsp.GetScalars(M0);
    for(int i = 0; i < M0; i++){
        v[i] = Scalar((uint64_t) rand());
        r[i].randomize();
    }

    std::vector<GroupElement> C0;
    C0.resize(M0);
    for (size_t i=0; i < M0; i++) {
        C0[i] = G0*v[i] + H0*r[i];
    }

    spark::BPPlus bpplus0(G0, H0, Gi0, Hi0, N0);
    spark::BPPlusProof proof0;
    bpplus0.prove(v, r, C0, proof0);
    assert(bpplus0.verify(C0, proof0));
    /** End of Single proof fuzz test**/

    /** Batch Proof **/

    size_t N1 = fdp.ConsumeIntegralInRange<size_t>(1,64);
    size_t B = fdp.ConsumeIntegral<size_t>();
    N1 = 64;
    B = 5;

    std::vector<std::size_t> sizes;
    sizes.resize(B);
    for(int i = 0; i < B; i++){
        sizes[i] = (fdp.ConsumeIntegral<std::size_t>() % 8) + 1 ; // otherwise it's "Bad BPPlus statement!4" line 102 bpplus.cpp since B = 5.(checked)
    }
    // sizes = fdp.ConsumeRemainingBytes<std::size_t>();

    // Generators
    GroupElement G1, H1;
    G1.randomize();
    H1.randomize();

    // std::size_t next_power = 1 << (uint(log2(B)) + 1);
    std::vector<GroupElement> Gi1, Hi1;
    Gi1.resize(8*N1);
    Hi1.resize(8*N1);
    for (size_t i=0; i < 8*N1; i++) {
        Hi1[i].randomize();
        Gi1[i].randomize();
    }

    spark::BPPlus bpplus1(G1, H1, Gi1, Hi1, N1);
    std::vector<spark::BPPlusProof> proofs;
    proofs.resize(B);
    std::vector<std::vector<GroupElement>> C1;

    for (size_t i=0; i < B; i++) {
        std::size_t M = sizes[i];
        std::vector<Scalar> v, r;
        v.resize(M);
        r.resize(M);
        std::vector<GroupElement> C_;
        C_.resize(M);
        for (size_t j=0; j < M; j++) {
            v[j] = Scalar(uint64_t(j));
            r[j].randomize();
            C_[j] = G1*v[j] + H1*r[j];
        }
        C1.emplace_back(C_);
        bpplus1.prove(v, r, C_, proofs[i]);
    }
    assert(bpplus1.verify(C1, proofs));

    /** End of Batch proof fuzz test **/

    return 0;
}
