CXX := hfuzz-clang++

CXXFLAGS := -DHAVE_CONFIG_H -I../../src/  -iquote ../../src/config/  -iquote ../secp256k1/  -iquote ../secp256k1/src/  -iquote ../secp256k1/include/
CXXFLAGS2 := -DHAVE_CONFIG_H

LIBS := -lcrypto -lstdc++ -lboost_thread -lboost_filesystem -lboost_program_options -lboost_chrono
LIBS2 := -lstdc++ -lcrypto

INCLUDE_HEADER := -include ../streams.h -include ../version.h

BPPLUS_SRCS := libspark/bpplus_fuzz.cpp ../libspark/bpplus.cpp ../libspark/util.cpp fuzzing_utilities.cpp ../libspark/hash.cpp ../libspark/kdf.cpp ../libspark/transcript.cpp ../crypto/aes.cpp ../crypto/chacha20.cpp ../crypto/sha512.cpp ../secp256k1/src/cpp/Scalar.cpp ../secp256k1/src/cpp/GroupElement.cpp ../secp256k1/src/cpp/MultiExponent.cpp ../support/cleanse.cpp ../util.cpp ../utiltime.cpp ../utilstrencodings.cpp ../random.cpp ../chainparamsbase.cpp
BPPLUS_OUTPUT := libspark/bpplus_hfuzz
BPPLUS_OUTPUT_DEBUG := libspark/bpplus_debug

BECH32_SRCS := libspark/bech32_fuzz_2.cpp ../libspark/bech32.cpp
BECH32_OUTPUT := libspark/bech32_hfuzz
BECH32_OUTPUT_DEBUG := libspark/bech32_debug

AEAD_SRCS := libspark/aead_fuzz.cpp ../libspark/aead.cpp ../libspark/util.cpp ../libspark/kdf.cpp ../libspark/hash.cpp ../fuzz/fuzzing_utilities.cpp ../crypto/aes.cpp ../support/lockedpool.cpp ../support/cleanse.cpp ../secp256k1/src/cpp/Scalar.cpp ../secp256k1/src/cpp/GroupElement.cpp
AEAD_OUTPUT := libspark/aead_hfuzz
AEAD_OUTPUT_DEBUG := libspark/aead_debug

GROOTLE_SRCS := libspark/grootle_fuzz.cpp ../libspark/grootle.cpp ../libspark/util.cpp fuzzing_utilities.cpp ../libspark/hash.cpp ../libspark/kdf.cpp ../libspark/transcript.cpp ../crypto/aes.cpp ../crypto/chacha20.cpp ../crypto/sha512.cpp ../secp256k1/src/cpp/Scalar.cpp ../secp256k1/src/cpp/GroupElement.cpp ../secp256k1/src/cpp/MultiExponent.cpp ../support/cleanse.cpp  ../util.cpp ../utiltime.cpp ../utilstrencodings.cpp ../random.cpp ../chainparamsbase.cpp
GROOTLE_OUTPUT := libspark/grootle_hfuzz
GROOTLE_OUTPUT_DEBUG := libspark/grootle_debug

CHAUM_SRCS := libspark/chaum_fuzz.cpp ../libspark/chaum.cpp ../libspark/transcript.cpp fuzzing_utilities.cpp ../secp256k1/src/cpp/Scalar.cpp ../secp256k1/src/cpp/GroupElement.cpp  ../secp256k1/src/cpp/MultiExponent.cpp  ../support/cleanse.cpp
CHAUM_OUTPUT := libspark/chaum_hfuzz
CHAUM_OUTPUT_DEBUG := libspark/chaum_debug

SCHNORR_SRCS := libspark/schnorr_fuzz.cpp ../libspark/schnorr.cpp  ../fuzz/fuzzing_utilities.cpp ../secp256k1/src/cpp/Scalar.cpp ../secp256k1/src/cpp/GroupElement.cpp ../secp256k1/src/cpp/MultiExponent.cpp ../libspark/transcript.cpp  ../support/cleanse.cpp
SCHNORR_OUTPUT := libspark/schnorr_hfuzz
SCHNORR_OUTPUT_DEBUG := libspark/schnorr_debug

COIN_SRCS := libspark/coin_fuzz.cpp ../libspark/coin.cpp ../libspark/params.cpp ../crypto/aes.cpp ../crypto/ripemd160.cpp ../crypto/sha256.cpp ../secp256k1/src/cpp/Scalar.cpp ../secp256k1/src/cpp/GroupElement.cpp ../secp256k1/src/cpp/MultiExponent.cpp  ../support/*.cpp ../uint256.cpp ../utilstrencodings.cpp fuzzing_utilities.cpp ../libspark/aead.cpp ../libspark/util.cpp ../libspark/keys.cpp  ../libspark/f4grumble.cpp ../libspark/hash.cpp  ../libspark/bech32.cpp ../libspark/kdf.cpp
COIN_OUTPUT := libspark/coin_hfuzz
COIN_OUTPUT_DEBUG := libspark/coin_debug

MINT_TRANSACTION_SRCS := libspark/mint_transaction_fuzz.cpp ../libspark/mint_transaction.cpp ../libspark/coin.cpp ../libspark/keys.cpp ../libspark/schnorr.cpp ../fuzz/fuzzing_utilities.cpp ../libspark/util.cpp ../libspark/hash.cpp ../libspark/kdf.cpp ../libspark/transcript.cpp ../libspark/f4grumble.cpp ../libspark/params.cpp ../libspark/bech32.cpp ../libspark/aead.cpp ../crypto/aes.cpp ../crypto/ripemd160.cpp ../crypto/sha256.cpp ../secp256k1/src/cpp/Scalar.cpp ../secp256k1/src/cpp/GroupElement.cpp ../secp256k1/src/cpp/MultiExponent.cpp ../support/cleanse.cpp ../uint256.cpp ../utilstrencodings.cpp
MINT_TRANSACTION_OUTPUT := libspark/mint_transaction_hfuzz
MINT_TRANSACTION_OUTPUT_DEBUG := libspark/mint_transaction_debug

SPEND_TRANSACTION_SRCS := libspark/spend_transaction_fuzz.cpp ../libspark/spend_transaction.cpp ../libspark/coin.cpp ../libspark/keys.cpp ../libspark/schnorr.cpp ../fuzz/fuzzing_utilities.cpp ../libspark/util.cpp ../libspark/hash.cpp ../libspark/kdf.cpp ../libspark/transcript.cpp ../libspark/f4grumble.cpp ../libspark/params.cpp ../libspark/bech32.cpp ../libspark/aead.cpp ../libspark/chaum.cpp ../libspark/bpplus.cpp ../libspark/grootle.cpp ../crypto/aes.cpp ../crypto/ripemd160.cpp ../crypto/sha256.cpp ../crypto/chacha20.cpp ../crypto/sha512.cpp ../secp256k1/src/cpp/Scalar.cpp ../secp256k1/src/cpp/GroupElement.cpp ../secp256k1/src/cpp/MultiExponent.cpp ../support/cleanse.cpp ../uint256.cpp ../utilstrencodings.cpp ../util.cpp ../utiltime.cpp ../chainparamsbase.cpp ../random.cpp
SPEND_TRANSACTION_OUTPUT := libspark/spend_transaction_hfuzz
SPEND_TRANSACTION_OUTPUT_DEBUG := libspark/spend_transaction_debug

F4GRUMBLE_SRCS := libspark/f4grumble_fuzz.cpp ../libspark/f4grumble.cpp  ../libspark/util.cpp ../libspark/kdf.cpp ../libspark/hash.cpp ../crypto/aes.cpp ../support/lockedpool.cpp ../support/cleanse.cpp ../secp256k1/src/cpp/Scalar.cpp ../secp256k1/src/cpp/GroupElement.cpp
F4GRUMBLE_OUTPUT := libspark/f4grumble_hfuzz
F4GRUMBLE_OUTPUT_DEBUG := libspark/f4grumble_debug

DEBUG_FLAGS := -g -O0 -ggdb 

bpplus: $(BPPLUS_OUTPUT)
$(BPPLUS_OUTPUT): $(BPPLUS_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

bpplus_debug: $(BPPLUS_OUTPUT_DEBUG)
$(BPPLUS_OUTPUT_DEBUG): $(BPPLUS_SRCS)
	$(CXX) $(DEBUG_FLAGS) $(CXXFLAGS) $^ -o $@ $(LIBS)

bech32: $(BECH32_OUTPUT)
$(BECH32_OUTPUT): $(BECH32_SRCS)
	$(CXX) $(CXXFLAGS2) $^ -o $@ $(LIBS2)

bech32_debug: $(BECH32_OUTPUT_DEBUG)
$(BECH32_OUTPUT_DEBUG): $(BECH32_SRCS)
	$(CXX) $(DEBUG_FLAGS) $(CXXFLAGS2) $^ -o $@ $(LIBS2)

aead: $(AEAD_OUTPUT)
$(AEAD_OUTPUT): $(AEAD_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS2)

aead_debug: $(AEAD_OUTPUT_DEBUG)
$(AEAD_OUTPUT_DEBUG): $(AEAD_SRCS)
	$(CXX) $(DEBUG_FLAGS) $(CXXFLAGS) $^ -o $@ $(LIBS2)

grootle: $(GROOTLE_OUTPUT)
$(GROOTLE_OUTPUT): $(GROOTLE_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

grootle_debug: $(GROOTLE_OUTPUT_DEBUG)
$(GROOTLE_OUTPUT_DEBUG): $(GROOTLE_SRCS)
	$(CXX) $(DEBUG_FLAGS) $(CXXFLAGS) $^ -o $@ $(LIBS)

chaum: $(CHAUM_OUTPUT)
$(CHAUM_OUTPUT): $(CHAUM_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(INCLUDE_HEADER) $(LIBS)

chaum_debug: $(CHAUM_OUTPUT_DEBUG)
$(CHAUM_OUTPUT_DEBUG): $(CHAUM_SRCS)
	$(CXX) $(DEBUG_FLAGS) $(CXXFLAGS2) $^ -o $@ $(INCLUDE_HEADER) $(LIBS)

schnorr: $(SCHNORR_OUTPUT)
$(SCHNORR_OUTPUT): $(SCHNORR_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(INCLUDE_HEADER) $(LIBS)

schnorr_debug: $(SCHNORR_OUTPUT_DEBUG)
$(SCHNORR_OUTPUT_DEBUG): $(SCHNORR_SRCS)
	$(CXX) $(DEBUG_FLAGS) $(CXXFLAGS) $^ -o $@ $(INCLUDE_HEADER) $(LIBS)

coin: $(COIN_OUTPUT)
$(COIN_OUTPUT): $(COIN_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

coin_debug: $(COIN_OUTPUT_DEBUG)
$(COIN_OUTPUT_DEBUG): $(COIN_SRCS)
	$(CXX) $(DEBUG_FLAGS) $(CXXFLAGS) $^ -o $@ $(LIBS)

mint_transaction: $(MINT_TRANSACTION_OUTPUT)
$(MINT_TRANSACTION_OUTPUT): $(MINT_TRANSACTION_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS2)

mint_transaction_debug: $(MINT_TRANSACTION_OUTPUT_DEBUG)
$(MINT_TRANSACTION_OUTPUT_DEBUG): $(MINT_TRANSACTION_SRCS)
	$(CXX) $(DEBUG_FLAGS) $(CXXFLAGS2) $^ -o $@ $(LIBS2)

spend_transaction: $(SPEND_TRANSACTION_OUTPUT)
$(SPEND_TRANSACTION_OUTPUT): $(SPEND_TRANSACTION_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

spend_transaction_debug: $(SPEND_TRANSACTION_OUTPUT_DEBUG)
$(SPEND_TRANSACTION_OUTPUT_DEBUG): $(SPEND_TRANSACTION_SRCS)
	$(CXX) $(DEBUG_FLAGS) $(CXXFLAGS) $^ -o $@ $(LIBS)

f4grumble: $(F4GRUMBLE_OUTPUT)
$(F4GRUMBLE_OUTPUT): $(F4GRUMBLE_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

f4grumble_debug: $(F4GRUMBLE_OUTPUT_DEBUG)
$(F4GRUMBLE_OUTPUT_DEBUG): $(F4GRUMBLE_SRCS)
	$(CXX) $(DEBUG_FLAGS) $(CXXFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f $(BPPLUS_OUTPUT) $(BPPLUS_OUTPUT_DEBUG) $(BECH32_OUTPUT) $(BECH32_OUTPUT_DEBUG) $(AEAD_OUTPUT) $(AEAD_OUTPUT_DEBUG) $(GROOTLE_OUTPUT) $(GROOTLE_OUTPUT_DEBUG) $(CHAUM_OUTPUT) $(CHAUM_OUTPUT_DEBUG) $(SCHNORR_OUTPUT) $(SCHNORR_OUTPUT_DEBUG) $(COIN_OUTPUT) $(COIN_OUTPUT_DEBUG) $(MINT_TRANSACTION_OUTPUT) $(MINT_TRANSACTION_OUTPUT_DEBUG) $(SPEND_TRANSACTION_OUTPUT) $(SPEND_TRANSACTION_OUTPUT_DEBUG) *.o
