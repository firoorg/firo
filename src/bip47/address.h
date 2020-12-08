#ifndef BIP47ADDRESS_H
#define BIP47ADDRESS_H

#include "base58.h"

namespace bip47 {

class CAddress
{
public:
    CAddress() = default;
    CAddress(CBitcoinAddress const & address, bool isUsed = false);
    
    void isUsed(bool);
    bool isUsed() const;
    
    CBitcoinAddress address;
private:
    bool isUsed_;
};

}

#endif
