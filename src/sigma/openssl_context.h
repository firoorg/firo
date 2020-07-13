#ifndef _OPENSSL_CONTEXT_H__
#define _OPENSSL_CONTEXT_H__

#include <openssl/rand.h>
#include <secp256k1.h>
#include <stdexcept>

// This class is created for creation of a global openSSL context.
class OpenSSLContext {
public:
    static secp256k1_context* get_context() {
        return get_instance().ctx;
    }
    static const OpenSSLContext& get_instance() {
        static OpenSSLContext instance;
        return instance;
    }

    OpenSSLContext() {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        unsigned char seed[32];
        if (RAND_bytes(seed, sizeof(seed)) != 1) {
            throw std::runtime_error("Unable to generate randomness for context");
        }
        if (secp256k1_context_randomize(ctx, seed) != 1) {
            throw std::runtime_error("Unable to randomize context");
        };
    }

private:
    secp256k1_context* ctx;

};
#endif // _OPENSSL_CONTEXT_H__
