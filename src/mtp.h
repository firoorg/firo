//
// Created by aizen on 4/09/17.
//

#ifndef ZCOIN_MTP_H
#define ZCOIN_MTP_H

#endif //ZCOIN_MTP_H

#include "main.h"
#include "argon2/core.h"
#include "argon2/argon2.h"
#include "argon2/thread.h"
#include "argon2/blake2/blake2.h"
#include "argon2/blake2/blake2-impl.h"
#include "argon2/blake2/blamka-round-opt.h"
#include "merkletree/sha.h"

void mtp_hash(char* output, const char* input, unsigned int d, CBlock *pblock);

bool mtp_verifier(unsigned int d, CBlock *pblock);