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
    secp_primitives::GroupElement B = utils::GeFromPubkey(pubkey);
    std::vector<unsigned char> result = (B * a).getvch();
    result.erase(result.end() - 2, result.end());
    return result;
}

bool CSecretPoint::operator==(CSecretPoint const & other) const
{
    return getEcdhSecret() == other.getEcdhSecret();
}

}
