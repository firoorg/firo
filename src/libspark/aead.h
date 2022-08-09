#ifndef FIRO_SPARK_AEAD_H
#define FIRO_SPARK_AEAD_H
#include <openssl/evp.h>
#include "util.h"

namespace spark {

struct AEADEncryptedData {
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> tag;
	std::vector<unsigned char> key_commitment;

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(ciphertext);
		READWRITE(tag);
		READWRITE(key_commitment);
    }
};

class AEAD {
public:
	static AEADEncryptedData encrypt(const GroupElement& prekey, const std::string additional_data, CDataStream& data);
	static CDataStream decrypt_and_verify(const GroupElement& prekey, const std::string associated_data, AEADEncryptedData& data);
};

}

#endif
