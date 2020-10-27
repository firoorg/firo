#include "bip47/channeladdress.h"

CBIP47ChannelAddress::CBIP47ChannelAddress(CExtPubKey const & cKey, int child)
{
    childNum = child;
    CExtPubKey dk;
    if (!cKey.Derive(dk, childNum)) {
        throw std::runtime_error("CBIP47ChannelAddress::CBIP47ChannelAddress(CBaseChainParams *v_params, CExtPubKey &cKey, int child) creation failed.\n");
    }
    ecKey = dk;
    pubKey = std::vector<unsigned char>(ecKey.pubkey.begin(), ecKey.pubkey.end());
}

std::vector<unsigned char>& CBIP47ChannelAddress::getPubKey()
{
    return pubKey;
}

std::string CBIP47ChannelAddress::getPath()
{
    return strPath;
}
