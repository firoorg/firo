#include "bip47/channeladdress.h"
#include "bip47/utils.h"
#include "chainparamsbase.h"


namespace bip47 {

CChannelAddress::CChannelAddress(CExtPubKey const & cKey, int child)
{
    childNum = child;
    CExtPubKey dk;
    if (!cKey.Derive(dk, childNum)) {
        throw std::runtime_error("CChannelAddress::CChannelAddress(CBaseChainParams *v_params, CExtPubKey &cKey, int child) creation failed.\n");
    }
    ecKey = dk;
    pubKey = std::vector<unsigned char>(ecKey.pubkey.begin(), ecKey.pubkey.end());
}

std::vector<unsigned char>& CChannelAddress::getPubKey()
{
    return pubKey;
}

std::string CChannelAddress::getPath()
{
    return strPath;
}

}
