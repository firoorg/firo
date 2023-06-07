#ifndef FIRO_SPARK_F4GRUMBLE_H
#define FIRO_SPARK_F4GRUMBLE_H
#include <openssl/evp.h>
#include "util.h"

namespace spark {

using namespace secp_primitives;

class F4Grumble {
public:
	F4Grumble(const unsigned char network, const int l_M);

	std::vector<unsigned char> encode(const std::vector<unsigned char>& input);
	std::vector<unsigned char> decode(const std::vector<unsigned char>& input);

	static std::size_t get_max_size();

private:
	static std::vector<unsigned char> vec_xor(const std::vector<unsigned char>& x, const std::vector<unsigned char>& y);

	// The internal Feistel round functions
	std::vector<unsigned char> G(const unsigned char i, const std::vector<unsigned char>& u);
	std::vector<unsigned char> H(const unsigned char i, const std::vector<unsigned char>& u);

	unsigned char network;
	int l_M, l_L, l_R;
};

}

#endif
