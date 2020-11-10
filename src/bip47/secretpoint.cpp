#include "sigma/coin.h"
#include "bip47/secretpoint.h"
#include "sigma/openssl_context.h"
#include "bip47/utils.h"
#include "utilstrencodings.h"


namespace bip47 {

CSecretPoint::CSecretPoint(std::vector<unsigned char> const & dataPrv, std::vector<unsigned char> const & dataPub)
:a(dataPrv.data())
{
    pubKey.Set(dataPub.begin(), dataPub.end());
}

bool CSecretPoint::isShared(CSecretPoint const & secret) const
{
    return equals(secret);
}

std::vector<unsigned char> CSecretPoint::getEcdhSecret() const {
    secp_primitives::GroupElement B = utils::GeFromPubkey(pubKey);
    std::vector<unsigned char> result = (B * a).getvch();
    result.erase(result.end() - 2, result.end());
    return result;
}

bool CSecretPoint::equals(CSecretPoint const & v_secret) const
{
    std::vector<unsigned char> const v1 = getEcdhSecret()
        , v2 = v_secret.getEcdhSecret();
    return v1 == v2;
}

}
