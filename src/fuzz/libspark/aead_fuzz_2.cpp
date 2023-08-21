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
    spark::AEADEncryptedData result;

    try{

        result = spark::AEAD::encrypt(ge, additional_data, ser);
        assert(!result.ciphertext.empty());
        assert(!result.tag.empty());
        
    } catch (const std::exception& e) {
        std::cerr << "Input that caused the exception: " << additional_data << std::endl;
    }

    try{
        
        ser = spark::AEAD::decrypt_and_verify(ge, additional_data, result);
        assert(!ser.empty());

    } catch (const std::exception& e) {
        
        std::cerr << "Input that caused the exception in decrypt: " << additional_data << std::endl;

    }

    int received_fuzzed_message;
    ser >> received_fuzzed_message;
    
    assert(fuzzed_message == received_fuzzed_message);

    return 0;
}