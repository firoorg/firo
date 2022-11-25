#include "../fuzzing_utilities.h"
#include "../FuzzedDataProvider.h"
#include "../../libspark/bpplus.h"
#include "../../libspark/bpplus_proof.h"
#include <cassert>


extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    FuzzedDataProvider fdp(buf, len);
    FuzzedSecp256k1Object fsp(&fdp);

    /** Single Proof **/
    size_t N0 = fdp.ConsumeIntegral<size_t>();
    size_t M0 = fdp.ConsumeIntegral<size_t>();

    // Generators
    GroupElement G0, H0;
    G0.randomize();
    H0.randomize();

    std::vector<GroupElement> Gi0, Hi0;
    size_t generators_needed = N0*M0;
    if (!spark::is_nonzero_power_of_2(generators_needed)) {
        generators_needed = 1 << (log2(N*M) + 1);
    }

    Gi0.resize(generators_needed);
    Hi0.resize(generators_needed);
    for (size_t i=0; i < generators_needed; i++) {
        Gi0[i].randomize();
        Hi0[i].randomize();
    }

    // Commitments
    std::vector<Scalar> v, r;
    v = fsp.GetScalars(M0);
    r = fsp.GetScalars(M0);

    std::vector<GroupElement> C0;
    for (size_t i=0; i < M0; i++) {
        C[i] = G0*v[i] + H0*r[i];
    }

    spark::BPPlus bpplus(G0, H0, Gi0, Hi0, N0);
    spark::BPPlusProof proof;
    bpplus.prove(v, r, C0, proof);
    assert(bpplus.verify(C0, proof));
    /** End of Single proof fuzz test**/

    /** Batch Proof **/

    size_t N1 = fdp.ConsumeIntegral<size_t>();
    size_t B = fdp.ConsumeIntegral<size_t>();
    vector<size_t> sizes = fdp.ConsumeRemainingBytes<size_t>();

    // Generators
    GroupElement G1, H1;
    G1.randomize();
    H1.randomize();

    std::vector<GroupElement> Gi1, Hi1;
    Gi1.resize(8*N1);
    Hi1.resize(8*N1);
    for (size_t i=0; i < 8*N1; i++) {
        Hi1[i].randomize();
        Gi1[i].randomize();
    }

    BBPlus bpplus(G1, H1, Gi1, Hi1, N1);
    std::vector<BPPlusProof> proofs;
    proofs.resize(B);
    std::vector<std::vector<GroupElement>> C1;

    for (size_t i=0; i < B; i++) {
        size_t M = sizes[i];
        std::vector<Scalar> v, r;
        v.resize(M);
        r.resize(M);
        std::vector<GroupElement> C_;
        C_.resize(M);
        for (size_t j=0; j < M; j++) {
            v[j] = Scalar(uint64_t(j));
            r[j].randomize();
            C_[j] = G1*v[j] + H1*r[j]
        }
        C1.emplace_back(C_);
        bpplus.prove(v, r, C_, proofs[i]);
    }
    assert(bpplus.verify(C, proofs));

    /** End of Batch proof fuzz test **/

    return 0;
}
