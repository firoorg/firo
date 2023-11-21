#include "../fuzzing_utilities.h"
#include "../FuzzedDataProvider.h"
#include "../../libspark/schnorr_proof.h"
#include "../../libspark/schnorr.h"
#include <cassert>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    FuzzedDataProvider fdp(buf, len);
    FuzzedSecp256k1Object fsp(&fdp);

    /** Serialization and Completeness tests **/
    GroupElement G0;
    // G0 = fsp.GetGroupElement();

    // NOTE: all GetGroupElement() is replaced by GetMemberGroupElement()

    // ensure that G0 is valid group element 
    // thus the crash of valid fieldElement and groupElement will not occur
    G0.generate(buf);

    Scalar y0;
    y0 = fsp.GetScalar();
    GroupElement Y0 = G0*y0;

    spark::SchnorrProof proof0;

    spark::Schnorr schnorr0(G0);
    schnorr0.prove(y0, Y0, proof0);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof0;

    spark::SchnorrProof deserialized_proof0;
    serialized >> deserialized_proof0;

    assert(proof0.A == deserialized_proof0.A);
    assert(proof0.t == deserialized_proof0.t);
    assert(schnorr0.verify(Y0, proof0));

    /** End of serialization and completeness tests **/

    /** Aggregation test **/

    size_t n = fdp.ConsumeIntegral<size_t>();

    GroupElement G1;
    G1 = fsp.GetMemberGroupElement();
    std::vector<Scalar> y1;
    std::vector<GroupElement> Y1;

    for(size_t i=0; i < n; i++) {
        y1.emplace_back();
        y1.back() = fsp.GetScalar();

        Y1.emplace_back(G1 * y1.back());
    }

    spark::SchnorrProof proof1;
    spark::Schnorr schnorr1(G1);
    schnorr1.prove(y1, Y1, proof1);
    assert(schnorr1.verify(Y1, proof1));

    /** End of aggregation test **/

    /*
        fuzzing bad proofs
    */

   // Bad Y
    GroupElement evil_Y;
    evil_Y.randomize();
    assert(!(schnorr1.verify(evil_Y, proof1)));

    // Bad A
    spark::SchnorrProof evil_proof = proof1;
    evil_proof.A.randomize();
    assert(!(schnorr1.verify(Y1, evil_proof)));

    // Bad t
    evil_proof = proof1;
    evil_proof.t.randomize();
    assert(!(schnorr1.verify(Y1, evil_proof)));

    // //checking empty proof
    // std::vector<Scalar> y3;
    // std::vector<GroupElement> Y3;
    // y3.resize(0);
    // Y3.resize(0);
    // spark::SchnorrProof proof3;

    // spark::Schnorr schnorr3(G1);
    // schnorr3.prove(y3, Y3, proof3);
    // assert(schnorr1.verify(Y3, proof3));

}