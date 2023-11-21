#include "../fuzzing_utilities.h"
#include "../FuzzedDataProvider.h"
#include "../../libspark/aead.h"
#include <cassert>


extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    FuzzedDataProvider fdp(buf, len);
    FuzzedSecp256k1Object fsp(&fdp);

    secp_primitives::GroupElement ge = fsp.GetGroupElement();
    std::string additional_data = fdp.ConsumeBytesAsString(len);
    int fuzzed_message = fdp.ConsumeIntegral<int>();
    CDataStream ser(SER_NETWORK, PROTOCOL_VERSION);
    ser << fuzzed_message;

    spark::AEADEncryptedData aed = spark::AEAD::encrypt(ge, additional_data, ser);
    ser = spark::AEAD::decrypt_and_verify(ge, additional_data, aed);
    int received_fuzzed_message;
    ser >> received_fuzzed_message;
    assert(fuzzed_message == received_fuzzed_message);

    return 0;
}