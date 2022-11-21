#include "../fuzzing_utilities.h"
#include "../FuzzedDataProvider.h"
#include "../../libspark/bpplus.h"
#include "../../libspark/bpplus_proof.h"
#include <cassert>


extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    FuzzedDataProvider fdp(buf, len);
    FuzzedSecp256k1Object fsp(&fdp);

    size_t N = fdp.ConsumeIntegral<size_t>();
    size_t M = fdp.ConsumeIntegral<size_t>();

    /** Single Proof **/
    // Generators
    GroupElement G0, H0;
    G0.randomize();
    H0.randomize();

    std::vector<GroupElement> Gi0, Hi0;
    size_t generators_needed = N*M;
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
    v = fsp.GetScalars(M);
    r = fsp.GetScalars(M);

    std::vector<GroupElement> C;
    for (size_t i=0; i < M; i++) {
        C[i] = G0*v[i] + H0*r[i];
    }

    spark::BPPlus bpplus(G0, H0, Gi0, Hi0, N);
    spark::BPPlusProof proof;
    bpplus.prove(v, r, C, proof);
    assert(bpplus.verify(C, proof));
    /** End of Single proof fuzz test**/

    /** Batch Proof **/

    /** End of Batch proof fuzz test **/

    return 0;
}