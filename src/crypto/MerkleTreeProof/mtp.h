#ifndef MTP_H_
#define MTP_H_

extern "C" {
#include <inttypes.h>
}
#include "uint256.h"
#include <deque>
#include <vector>

void mtp_hash(const char* input, uint32_t target,
		uint8_t hashRootMTP[16], unsigned int * nNonce,
		uint64_t (&nBlockMTP)[72*2][128], std::deque<std::vector<uint8_t>> * nProofMTP, uint256 powLimit,
		uint256 * output);

bool mtp_verify(const char* input, const uint32_t target,
		const uint8_t hashRootMTP[16], const unsigned int * nNonce,
		const uint64_t (&nBlockMTP)[72*2][128], const std::deque<std::vector<uint8_t>> * nProofMTP, uint256 powLimit,
		uint256 * output);

#endif
