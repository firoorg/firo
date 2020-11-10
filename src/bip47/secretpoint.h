#ifndef ZCOIN_BIP47SECRETPOINT_H
#define ZCOIN_BIP47SECRETPOINT_H
#include "key.h"
#include "pubkey.h"
#include "../secp256k1/include/Scalar.h"

namespace bip47 {

class CSecretPoint {
public:
    CSecretPoint() = delete;
    CSecretPoint(std::vector<unsigned char> const & dataPrv, std::vector<unsigned char> const & dataPub);

    std::vector<unsigned char> getEcdhSecret() const;

    bool isShared(CSecretPoint const & secret) const;

private:
    bool equals(CSecretPoint const & v_secret) const;

    secp_primitives::Scalar a;
    CPubKey pubKey;
};

}

#endif // ZCOIN_BIP47SECRETPOINT_H
