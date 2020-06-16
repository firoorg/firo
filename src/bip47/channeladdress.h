#ifndef BIP47CHANNELADDRESS_H
#define BIP47CHANNELADDRESS_H
#include "bip47/common.h"
#include "chainparamsbase.h"
#include "key.h"
class Bip47ChannelAddress {
private:
    int childNum;
    std::string strPath;
    
    CExtPubKey ecKey;
    
    std::vector<unsigned char> pubKey;
    
public:
    Bip47ChannelAddress();
    
    Bip47ChannelAddress(CExtPubKey &cKey, int child);
    
    std::vector<unsigned char>& getPubKey();

    std::string getPath();
};
#endif
