#include "../fuzzing_utilities.h"
#include "../FuzzedDataProvider.h"
#include "../../libspark/chaum_proof.h"
#include "../../libspark/chaum.h"
#include <cassert>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {

    if (len == 0) {
        return 0;
    }

    FuzzedDataProvider fdp(buf, len);
    FuzzedSecp256k1Object fsp(&fdp);

    GroupElement F1, G1, H1, U1;
    std::vector<GroupElement> ge = fsp.GetGroupElements(4);

    F1 = ge[0];
    G1 = ge[1];
    H1 = ge[2];
    U1 = ge[3];

    const std::size_t n = fdp.ConsumeIntegral<size_t>();

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

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
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

    GroupElement F3, G3, H3, U3;
    F3 = fsp.GetGroupElement();
    G3 = fsp.GetGroupElement();
    H3 = fsp.GetGroupElement();
    U3 = fsp.GetGroupElement();

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