#include "../fuzzing_utilities.h"
#include "../FuzzedDataProvider.h"
#include "../../libspark/chaum_proof.h"
#include "../../libspark/chaum.h"
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

    const std::size_t n = fdp.ConsumeIntegralInRange(1, INT_MAX);

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

    spark::ChaumProof proof0;

    spark::Chaum chaum0(F0, G0, H0, U0);
    chaum0.prove(mu0, x0, y0, z0, S0, T0, proof0);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof0;

    spark::ChaumProof deserialized_proof0;
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

    const std::size_t n1 = fdp.ConsumeIntegralInRange(1, INT_MAX);

    Scalar mu1;
    mu1.randomize();
    std::vector<Scalar> x1, y1, z1;
    x1.resize(n1);
    y1.resize(n1);
    z1.resize(n1);
    std::vector<GroupElement> S1, T1;
    S1.resize(n1);
    T1.resize(n1);
    for (std::size_t i = 0; i < n; i++) {
        x1[i].randomize();
        y1[i].randomize();
        z1[i].randomize();

        S1[i] = F1*x1[i] + G1*y1[i] + H1*z1[i];
        T1[i] = (U1 + G1*y1[i].negate())*x1[i].inverse();
    }

    spark::ChaumProof proof1;
    spark::Chaum chaum1(F1, G1, H1, U1);
    chaum1.prove(mu1, x1, y1, z1, S1, T1, proof1);

    assert(chaum1.verify(mu1, S1, T1, proof1));
    /** End of completeness tests**/

    /* Fuzzing for bad proofs*/

    // Bad mu
    Scalar evil_mu;
    evil_mu.randomize();
    assert(!(chaum1.verify(evil_mu, S1, T1, proof1)));

    // Bad S
    for (std::size_t i = 0; i < n1; i++) {
        std::vector<GroupElement> evil_S(S1);
        evil_S[i].randomize();
        assert(!(chaum1.verify(m1, evil_S, T1, proof1)));
    }

    // Bad T
    for (std::size_t i = 0; i < n1; i++) {
        std::vector<GroupElement> evil_T(T1);
        evil_T[i].randomize();
        assert(!(chaum1.verify(mu1, S1, evil_T, proof1)));
    }

    // Bad A1
    spark::ChaumProof evil_proof = proof1;
    evil_proof.A1.randomize();
    assert(!(chaum1.verify(mu1, S1, T1, evil_proof)));

    // Bad A2
    for (std::size_t i = 0; i < n1; i++) {
        evil_proof = proof1;
        evil_proof.A2[i].randomize();
        assert(!(chaum1.verify(mu1, S1, T1, evil_proof)));
    }

    // Bad t1
    for (std::size_t i = 0; i < n1; i++) {
        evil_proof = proof1;
        evil_proof.t1[i].randomize();
        assert(!(chaum3.verify(mu3, S3, T3, evil_proof)));
    }

    // Bad t2
    evil_proof = proof3;
    evil_proof.t2.randomize();
    assert(!(chaum3.verify(mu3, S3, T3, evil_proof)));

    // Bad t3
    evil_proof = proof3;
    evil_proof.t3.randomize();
    assert(!(chaum3.verify(mu3, S3, T3, evil_proof)));
    
    return 0;

}