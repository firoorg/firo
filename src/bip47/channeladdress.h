
#ifndef BIP47CHANNELADDRESS_H
#define BIP47CHANNELADDRESS_H
#include "bip47/utils.h"
#include "chainparamsbase.h"
#include "key.h"

class CBIP47ChannelAddress
{
public:
    CBIP47ChannelAddress() {}
    CBIP47ChannelAddress(CExtPubKey& cKey, int child);

    std::vector<unsigned char>& getPubKey();
    std::string getPath();

private:
    int childNum;
    std::string strPath;
    CExtPubKey ecKey;
    std::vector<unsigned char> pubKey;
};
#endif
