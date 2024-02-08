#ifndef FIRO_SPARK_KDF_H
#define FIRO_SPARK_KDF_H
#include <openssl/evp.h>
#include "util.h"

namespace spark {

class KDF {
public:
	KDF(const std::string label, std::size_t derived_key_size);
	~KDF();
	void include(CDataStream& data);
	std::vector<unsigned char> finalize();

private:
	void include_size(std::size_t size);
	EVP_MD_CTX* ctx;
	std::size_t derived_key_size;
};

}

#endif
