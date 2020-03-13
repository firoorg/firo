// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_ELYSIUM_ECDSA_CONTEXT_H
#define ZCOIN_ELYSIUM_ECDSA_CONTEXT_H

#include <secp256k1.h>

namespace elysium {

class ECDSAContext
{
public:
    ECDSAContext(unsigned int flags);
    ECDSAContext(ECDSAContext const &context);
    ECDSAContext(ECDSAContext &&context);
    ~ECDSAContext();

public:
    ECDSAContext& operator=(ECDSAContext const &context);
    ECDSAContext& operator=(ECDSAContext &&context);

    secp256k1_context const *Get() const;

    static ECDSAContext CreateSignContext();
    static ECDSAContext CreateVerifyContext();

private:
    void Randomize();

private:
    secp256k1_context* context;
};

} // elysium

#endif // ZCOIN_ELYSIUM_ECDSA_CONTEXT_H