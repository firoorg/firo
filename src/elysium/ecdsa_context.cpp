// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ecdsa_context.h"

#include "../random.h"

namespace elysium {

ECDSAContext::ECDSAContext(unsigned int flags)
    : context(secp256k1_context_create(flags))
{
    std::array<uint8_t, 32> seed;
    GetRandBytes(seed.data(), seed.size());
    if (!secp256k1_context_randomize(context, seed.data())) {
        throw std::runtime_error("Fail to randomize context");
    }
}

ECDSAContext::ECDSAContext(ECDSAContext const &context)
    : context(secp256k1_context_clone(context.Context()))
{
}

ECDSAContext::ECDSAContext(ECDSAContext &&context)
{
    std::swap(this->context, context.context);
}

ECDSAContext::~ECDSAContext()
{
    if (context != NULL) {
        secp256k1_context_destroy(context);
        context = NULL;
    }
}

ECDSAContext& ECDSAContext::operator=(ECDSAContext const &context)
{
    return *this = ECDSAContext(context);
}

ECDSAContext& ECDSAContext::operator=(ECDSAContext &&context)
{
    std::swap(this->context, context.context);
    return *this;
}

secp256k1_context const *ECDSAContext::Context() const
{
    return context;
}

ECDSAContext ECDSAContext::CreateSignContext()
{
    return ECDSAContext(SECP256K1_CONTEXT_SIGN);
}

ECDSAContext ECDSAContext::CreateVerifyContext()
{
    return ECDSAContext(SECP256K1_CONTEXT_VERIFY);
}

} // elysium