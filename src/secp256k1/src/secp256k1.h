#ifndef SECP256K1_SECP256K1_H
#define SECP256K1_SECP256K1_H

#ifdef HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include "ecmult.h"
#include "ecmult_gen.h"
#include "util.h"

struct secp256k1_context_struct {
    secp256k1_ecmult_context ecmult_ctx;
    secp256k1_ecmult_gen_context ecmult_gen_ctx;
    secp256k1_callback illegal_callback;
    secp256k1_callback error_callback;
};

#endif /* SECP256K1_SECP256K1_H */
