// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ecdsa_context.h"

#include "../random.h"

namespace elysium {

ECDSAContext::ECDSAContext(unsigned int flags)
    : context(secp256k1_context_create(flags))
{
}

ECDSAContext::ECDSAContext(ECDSAContext const &context)
    : context(secp256k1_context_clone(context.Get()))
{
}

ECDSAContext::ECDSAContext(ECDSAContext &&context)
{
    std::swap(this->context, context.context);
}

ECDSAContext::~ECDSAContext()
{
    secp256k1_context_destroy(context);
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

secp256k1_context const *ECDSAContext::Get() const
{
    return context;
}

ECDSAContext ECDSAContext::CreateSignContext()
{
    ECDSAContext context(SECP256K1_CONTEXT_SIGN);
    context.Randomize();

    return context;
}

ECDSAContext ECDSAContext::CreateVerifyContext()
{
    return ECDSAContext(SECP256K1_CONTEXT_VERIFY);
}

void ECDSAContext::Randomize()
{
    std::array<uint8_t, 32> seed;
    GetRandBytes(seed.data(), seed.size());
    if (!secp256k1_context_randomize(context, seed.data())) {
        secp256k1_context_destroy(context);
        throw std::runtime_error("Fail to randomize context");
    }
}

} // elysium