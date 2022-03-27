#ifndef FIRO_SPARK_KDF_H
#define FIRO_SPARK_KDF_H
#include <openssl/evp.h>
#include "util.h"

namespace spark {

class KDF {
public:
	KDF(const std::string label);
	~KDF();
	void include(CDataStream& data);
	std::vector<unsigned char> finalize(std::size_t size);

private:
	void include_size(std::size_t size);
	EVP_MD_CTX* ctx;
};

}

#endif
