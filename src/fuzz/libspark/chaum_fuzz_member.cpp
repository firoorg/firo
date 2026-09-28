#include "../fuzzing_utilities.h"
#include "../FuzzedDataProvider.h"
#include "../../libspark/chaum_proof.h"
#include "../../libspark/chaum.h"
#include "chaum_fuzz_helpers.h"
#include <cassert>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    FuzzedDataProvider fdp(buf, len);
    FuzzedSecp256k1Object fsp(&fdp);

    /** Serialization tests **/
    GroupElement F0, G0, H0, U0;
    F0.randomize();
    G0.randomize();
    H0.randomize();
    U0.randomize();

    const std::size_t n = fdp.ConsumeIntegralInRange<std::size_t>(
        1, spark::MAX_CHAUM_V2_INPUTS);

    Scalar mu0;
    mu0.randomize();
    std::vector<Scalar> x0, y0, z0;
    x0.resize(n);
    y0.resize(n);
    z0.resize(n);
    std::vector<GroupElement> S0, T0;
    S0.resize(n);
    T0.resize(n);
    for (size_t i=0; i < n; i++) {
        x0[i].randomize();
        y0[i].randomize();
        z0[i].randomize();

        S0[i] = F0*x0[i] + G0*y0[i] + H0*z0[i];
        T0[i] = (U0 + G0*y0[i].negate())*x0[i].inverse();
    }

    spark::ChaumProofV1 proof0;

    spark::Chaum chaum0(F0, G0, H0, U0);
    chaum0.prove_v1(mu0, x0, y0, z0, S0, T0, proof0);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof0;

    spark::ChaumProofV1 deserialized_proof0;
    serialized >> deserialized_proof0;

    assert(proof0.A1 == deserialized_proof0.A1);
    assert(proof0.t2 == deserialized_proof0.t2);
    assert(proof0.t3 == deserialized_proof0.t3);
    for (size_t i = 0 ; i < n; i++) {
        assert(proof0.A2[i] == deserialized_proof0.A2[i]);
        assert(proof0.t1[i] == deserialized_proof0.t1[i]);
    }

    // fuzz completeness
    GroupElement F1, G1, H1, U1;
    F1.randomize();
    G1.randomize();
    H1.randomize();
    U1.randomize();

    const std::size_t n1 = fdp.ConsumeIntegralInRange<std::size_t>(
        1, spark::MAX_CHAUM_V2_INPUTS);

    Scalar mu1;
    mu1.randomize();
    std::vector<Scalar> x1, y1, z1;
    x1.resize(n1);
    y1.resize(n1);
    z1.resize(n1);
    std::vector<GroupElement> S1, T1;
    S1.resize(n1);
    T1.resize(n1);
    for (std::size_t i = 0; i < n1; i++) {
        x1[i].randomize();
        y1[i].randomize();
        z1[i].randomize();

        S1[i] = F1*x1[i] + G1*y1[i] + H1*z1[i];
        T1[i] = (U1 + G1*y1[i].negate())*x1[i].inverse();
    }

    spark::ChaumProofV1 proof1;
    spark::Chaum chaum1(F1, G1, H1, U1);
    chaum1.prove_v1(mu1, x1, y1, z1, S1, T1, proof1);

    assert(chaum1.verify_v1(mu1, S1, T1, proof1));
    /** End of completeness tests**/

    /* Fuzzing for bad proofs*/
    assert_v1_rejects_mutations(chaum1, mu1, S1, T1, proof1);

    return 0;

}
