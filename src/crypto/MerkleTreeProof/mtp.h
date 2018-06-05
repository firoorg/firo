#ifndef MTP_H_
#define MTP_H_
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <iomanip>
#include "merkle-tree.hpp"
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include "uint256.h"
#include "arith_uint256.h"

extern "C" {
	#include "blake2/blake2.h"
	#include "blake2/blake2-impl.h"
	#include "blake2/blamka-round-ref.h"
	#include "core.h"
	#include "ref.h"
	#include <inttypes.h>
}

void mtp_hash(const char* input, uint32_t target,
		uint8_t hashRootMTP[16], unsigned int * nNonce,
		uint64_t (&nBlockMTP)[72*2][128], std::deque<std::vector<uint8_t>> * nProofMTP, uint256 powLimit,
		uint256 * output);

bool mtp_verify(const char* input, const uint32_t target,
		const uint8_t hashRootMTP[16], const unsigned int * nNonce,
		const uint64_t (&nBlockMTP)[72*2][128], const std::deque<std::vector<uint8_t>> * nProofMTP, uint256 powLimit,
		uint256 * output);


#endif
