
#include "bip47/address.h"

CBIP47Address::CBIP47Address(){}
CBIP47Address::CBIP47Address(std::string v_address, int v_index){
    address = v_address;
    index = v_index;
}
CBIP47Address::CBIP47Address(std::string v_address, int v_index, bool v_seen) {
    address = v_address;
    index = v_index;
    seen = v_seen;
}

std::string CBIP47Address::getAddress() {
    return address;
}

int CBIP47Address::getIndex() {
    return index;
}

bool CBIP47Address::isSeen() {
    return seen;
}

void CBIP47Address::setSeen(bool v_seen) {
    seen = v_seen;
}

std::string CBIP47Address::toString() {
    return address;
}
