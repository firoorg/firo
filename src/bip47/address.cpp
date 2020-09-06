
#include "bip47/address.h"

std::string CBIP47Address::getAddress() 
{
    return address;
}

int CBIP47Address::getIndex() const 
{
    return index;
}

bool CBIP47Address::isSeen() 
{
    return seen;
}

void CBIP47Address::setSeen(bool v_seen) 
{
    seen = v_seen;
}

std::string CBIP47Address::toString() 
{
    return address;
}
