#ifndef FIRO_SPARK_AEAD_H
#define FIRO_SPARK_AEAD_H
#include <openssl/evp.h>
#include "util.h"

namespace spark {

struct AEADEncryptedData {
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> tag;

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(ciphertext);
		READWRITE(tag);
    }
};

class AEAD {
public:
	static AEADEncryptedData encrypt(const std::vector<unsigned char>& key, const std::string additional_data, CDataStream& data);
	static CDataStream decrypt_and_verify(const std::vector<unsigned char>& key, const std::string associated_data, AEADEncryptedData& data);
};

}

#endif
