#include "bip47/address.h"
#include "bip47/utils.h"

namespace bip47 {

CAddress::CAddress(CBitcoinAddress const & address, bool isUsed)
:address(address), isUsed_(isUsed)
{}

void CAddress::isUsed(bool isUsed) {
    isUsed_ = isUsed;
}

bool CAddress::isUsed() const {
    return isUsed_;
}

}
