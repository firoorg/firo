var data = {lines:[
{"lineNum":"    1","line":"#include \"../fuzzing_utilities.h\""},
{"lineNum":"    2","line":"#include \"../FuzzedDataProvider.h\""},
{"lineNum":"    3","line":"#include \"../../libspark/aead.h\""},
{"lineNum":"    4","line":"#include <cassert>"},
{"lineNum":"    5","line":""},
{"lineNum":"    6","line":""},
{"lineNum":"    7","line":"extern \"C\" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {","class":"lineCov","hits":"1","order":"26",},
{"lineNum":"    8","line":"    FuzzedDataProvider fdp(buf, len);","class":"lineCov","hits":"1","order":"27",},
{"lineNum":"    9","line":"    FuzzedSecp256k1Object fsp(&fdp);","class":"lineCov","hits":"1","order":"29",},
{"lineNum":"   10","line":""},
{"lineNum":"   11","line":"    secp_primitives::GroupElement ge = fsp.GetGroupElement();","class":"lineCov","hits":"1","order":"33",},
{"lineNum":"   12","line":"    std::string additional_data = fdp.ConsumeBytesAsString(len);","class":"lineCov","hits":"1","order":"118",},
{"lineNum":"   13","line":"    int fuzzed_message = fdp.ConsumeIntegral<int>();","class":"lineCov","hits":"1","order":"126",},
{"lineNum":"   14","line":"    CDataStream ser(SER_NETWORK, PROTOCOL_VERSION);","class":"lineCov","hits":"1","order":"140",},
{"lineNum":"   15","line":"    ser << fuzzed_message;","class":"lineCov","hits":"1","order":"151",},
{"lineNum":"   16","line":""},
{"lineNum":"   17","line":"    spark::AEADEncryptedData aed = spark::AEAD::encrypt(ge, additional_data, ser);","class":"lineCov","hits":"1","order":"163",},
{"lineNum":"   18","line":"    ser = spark::AEAD::decrypt_and_verify(ge, additional_data, aed);","class":"lineCov","hits":"1","order":"385",},
{"lineNum":"   19","line":"    int received_fuzzed_message;"},
{"lineNum":"   20","line":"    ser >> received_fuzzed_message;","class":"lineCov","hits":"1","order":"408",},
{"lineNum":"   21","line":"    assert(fuzzed_message == received_fuzzed_message);","class":"lineCov","hits":"1","order":"426",},
{"lineNum":"   22","line":""},
{"lineNum":"   23","line":"    return 0;"},
{"lineNum":"   24","line":"}","class":"lineCov","hits":"1","order":"427",},
]};
var percent_low = 25;var percent_high = 75;
var header = { "command" : "aead_fuzz_debug", "date" : "2023-08-09 11:47:13", "instrumented" : 13, "covered" : 13,};
var merged_data = [];
