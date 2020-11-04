
#include "bip47/address.h"

namespace bip47 {

std::string CAddress::getAddress() 
{
    return address;
}

int CAddress::getIndex() const 
{
    return index;
}

bool CAddress::isSeen() 
{
    return seen;
}

void CAddress::setSeen(bool v_seen) 
{
    seen = v_seen;
}

std::string CAddress::toString() 
{
    return address;
}

}
