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

    const std::size_t n = fdp.ConsumeIntegral<size_t>();

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

    /** Now fuzz all the things **/

    GroupElement F1, G1, H1, U1;
    F1 = fsp.GetMemberGroupElement();
    G1 = fsp.GetMemberGroupElement();
    H1 = fsp.GetMemberGroupElement();
    U1 = fsp.GetMemberGroupElement();
    //F1.randomize();
    //G1.randomize();
    //H1.randomize();
    //U1.randomize();

    Scalar mu1;
    mu1 = fsp.GetScalar();
    std::vector<Scalar> x1, y1, z1;
    x1.resize(n);
    x1 = fsp.GetScalars(n);
    y1.resize(n);
    y1 = fsp.GetScalars(n);
    z1.resize(n);
    z1 = fsp.GetScalars(n);

    std::vector<GroupElement> S1, T1;
    S1.resize(n);
    T1.resize(n);
    for (size_t i=0; i < n; i++) {
        S1[i] = F1*x1[i] + G1*y1[i] + H1*z1[i];
        T1[i] = (U1 + G1*y1[i].negate())*x1[i].inverse();
    }

    spark::ChaumProof proof1;

    spark::Chaum chaum1(F1, G1, H1, U1);
    chaum1.prove(mu1, x1, y1, z1, S1, T1, proof1);

    serialized << proof1;

    spark::ChaumProof deserialized_proof1;
    serialized >> deserialized_proof1;

    assert(proof1.A1 == deserialized_proof1.A1);
    assert(proof1.t2 == deserialized_proof1.t2);
    assert(proof1.t3 == deserialized_proof1.t3);
    for (size_t i = 0 ; i < n; i++) {
        assert(proof1.A2[i] == deserialized_proof1.A2[i]);
        assert(proof1.t1[i] == deserialized_proof1.t1[i]);
    }
    /**End of serialization tests**/

    /** Completeness tests **/

    GroupElement F2, G2, H2, U2;
    F2.randomize();
    G2.randomize();
    H2.randomize();
    U2.randomize();

    Scalar mu2;
    mu2.randomize();
    std::vector<Scalar> x2, y2, z2;
    x2.resize(n);
    y2.resize(n);
    z2.resize(n);
    std::vector<GroupElement> S2, T2;
    S2.resize(n);
    T2.resize(n);
    for (size_t i=0; i < n; i++) {
        x2[i].randomize();
        y2[i].randomize();
        z2[i].randomize();

        S2[i] = F2*x2[i] + G2*y2[i] + H2*z2[i];
        T2[i] = (U2 + G2*y2[i].negate())*x2[i].inverse();
    }

    spark::ChaumProof proof2;

    spark::Chaum chaum2(F2, G2, H2, U2);
    chaum2.prove(mu2, x2, y2, z2, S2, T2, proof2);
    assert(chaum2.verify(mu2, S2, T2, proof2));

    /** Full all the things again**/

    GroupElement F3, G3, H3, U3;
    F3 = fsp.GetMemberGroupElement();
    G3 = fsp.GetMemberGroupElement();
    H3 = fsp.GetMemberGroupElement();
    U3 = fsp.GetMemberGroupElement();
    //F3.randomize();
    //G3.randomize();
    //H3.randomize();
    //U3.randomize();
    

    Scalar mu3;
    mu3 = fsp.GetScalar();
    std::vector<Scalar> x3, y3, z3;
    x3.resize(n);
    x3 = fsp.GetScalars(n);
    y3.resize(n);
    y3 = fsp.GetScalars(n);
    z3.resize(n);
    z3 = fsp.GetScalars(n);

    std::vector<GroupElement> S3, T3;
    S3.resize(n);
    T3.resize(n);
    for (size_t i=0; i < n; i++) {
        S3[i] = F3*x3[i] + G3*y3[i] + H3*z3[i];
        T3[i] = (U3 + G3*y3[i].negate())*x3[i].inverse();
    }

    spark::ChaumProof proof3;

    spark::Chaum chaum3(F3, G3, H3, U3);
    chaum3.prove(mu3, x3, y3, z3, S3, T3, proof3);
    assert(chaum3.verify(mu3, S3, T3, proof3));

    /** End of completeness tests**/

    /* Fuzzing for bad proofs*/

    // Bad mu
    Scalar evil_mu;
    evil_mu.randomize();
    assert(!(chaum3.verify(evil_mu, S3, T3, proof3)));

    // Bad S
    for (std::size_t i = 0; i < n; i++) {
        std::vector<GroupElement> evil_S(S3);
        evil_S[i].randomize();
        assert(!(chaum3.verify(mu3, evil_S, T3, proof3)));
    }

    // Bad T
    for (std::size_t i = 0; i < n; i++) {
        std::vector<GroupElement> evil_T(T3);
        evil_T[i].randomize();
        assert(!(chaum3.verify(mu3, S3, evil_T, proof3)));
    }

    // Bad A1
    spark::ChaumProof evil_proof = proof3;
    evil_proof.A1.randomize();
    assert(!(chaum3.verify(mu3, S3, T3, evil_proof)));

    // Bad A2
    for (std::size_t i = 0; i < n; i++) {
        evil_proof = proof3;
        evil_proof.A2[i].randomize();
        assert(!(chaum3.verify(mu3, S3, T3, evil_proof)));
    }

    // Bad t1
    for (std::size_t i = 0; i < n; i++) {
        evil_proof = proof3;
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