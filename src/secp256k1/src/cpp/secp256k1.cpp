#include "secp256k1.hpp"

namespace secp256k1 {

secp256k1_context *default_context;
random_bytes_t random_bytes;

void initialize(secp256k1_context *ctx, random_bytes_t random) {
    default_context = ctx;
    random_bytes = random;
}

void terminate() {
    // for future use due to we already introduced initialize
    // it will need to modify the caller site again if we introduce the terminate later
}

} // namespace secp256k1
