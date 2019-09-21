#ifndef BIP47CHANNELADDRESS_H
#define BIP47CHANNELADDRESS_H
#include "bip47_common.h"
#include "chainparamsbase.h"
#include "key.h"
class Bip47ChannelAddress {
private:
    int childNum;
    String strPath ;
    
    CExtPubKey ecKey ;
    // CExtKey ecKey ;
    
    std::vector<unsigned char> pubKey ;
    std::vector<unsigned char> pubKeyHash ;
    CBaseChainParams *params ;
public:
    Bip47ChannelAddress() ;
    Bip47ChannelAddress(CBaseChainParams *v_params, CExtPubKey &cKey, int child) ;
    std::vector<unsigned char>& getPubKey() ;

    std::vector<unsigned char>& getPubKeyHash() ;

    String getAddressString() ;

    String getPrivateKeyString() ;

    // Address getAddress() {
    //     return ecKey.toAddress(params);
    // }

    String getPath() ;
};
#endif