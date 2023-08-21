CXX := hfuzz-clang++
CXXFLAGS := -DHAVE_CONFIG_H -iquote src/secp256k1/include/
LIBS := -lcrypto -lstdc++ -lboost_thread -lboost_filesystem -lboost_program_options -lboost_chrono
BPPLUS_SRCS := libspark/bpplus_fuzz.cpp ../libspark/bpplus.cpp ../libspark/util.cpp fuzzing_utilities.cpp ../libspark/hash.cpp ../libspark/kdf.cpp ../libspark/transcript.cpp ../crypto/aes.cpp ../crypto/chacha20.cpp ../crypto/sha512.cpp ../secp256k1/src/cpp/Scalar.cpp ../secp256k1/src/cpp/GroupElement.cpp ../secp256k1/src/cpp/MultiExponent.cpp ../support/cleanse.cpp ../util.cpp ../utiltime.cpp ../utilstrencodings.cpp ../random.cpp ../chainparamsbase.cpp
BPPLUS_OUTPUT := libspark/bpplus_hfuzz
BPPLUS_OUTPUT_DEBUG := libspark/bpplus_debug
DEBUG_FLAGS := -g -O0 -ggdb 

bpplus: $(BPPLUS_OUTPUT)

$(BPPLUS_OUTPUT): $(BPPLUS_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

bpplus_debug: $(BPPLUS_OUTPUT_DEBUG)

$(BPPLUS_OUTPUT_DEBUG): $(BPPLUS_SRCS)
	$(CXX) $(DEBUG_FLAGS) $(CXXFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f $(BPPLUS_OUTPUT) $(BPPLUS_OUTPUT_DEBUG) *.o
