#include "sigma/coin.h"
#include "bip47/secretpoint.h"
#include "sigma/openssl_context.h"
#include "bip47/utils.h"
#include "utilstrencodings.h"


namespace bip47 {

CSecretPoint::CSecretPoint(CKey const & privkey, CPubKey const & pubkey)
:a(privkey.begin()), pubkey(pubkey)
{}

std::vector<unsigned char> CSecretPoint::getEcdhSecret() const {
    if(ecdhSecret.empty()) {
        secp_primitives::GroupElement B = utils::GeFromPubkey(pubkey);
        ecdhSecret = (B * a).getvch();
        ecdhSecret.erase(ecdhSecret.end() - 2, ecdhSecret.end());
    }
    return ecdhSecret;
}

bool CSecretPoint::isShared(CSecretPoint const & other) const
{
    return getEcdhSecret() == other.getEcdhSecret();
}

}
