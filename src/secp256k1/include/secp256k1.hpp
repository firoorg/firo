#ifndef SECP256K1_HPP
#define SECP256K1_HPP

#include "secp256k1.h"

#include <stddef.h>

namespace secp256k1 {

        typedef void (*random_bytes_t) (unsigned char *buffer, size_t size);

        void initialize(secp256k1_context *ctx, random_bytes_t random);
        void terminate();

} // namespace secp256k1

#endif // SECP256K1_HPP