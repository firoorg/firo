
#include "bip47/address.h"

Bip47Address::Bip47Address(){}
Bip47Address::Bip47Address(std::string v_address, int v_index){
    address = v_address;
    index = v_index;
}
Bip47Address::Bip47Address(std::string v_address, int v_index, bool v_seen) {
    address = v_address;
    index = v_index;
    seen = v_seen;
}

std::string Bip47Address::getAddress() {
    return address;
}

int Bip47Address::getIndex() {
    return index;
}

bool Bip47Address::isSeen() {
    return seen;
}

void Bip47Address::setSeen(bool v_seen) {
    seen = v_seen;
}

std::string Bip47Address::toString() {
    return address;
}
