#include "Bip47Address.h"
Bip47Address::Bip47Address(){}
Bip47Address::Bip47Address(String v_address, int v_index){
    address = v_address;
    index = v_index;
}
Bip47Address::Bip47Address(String v_address, int v_index, bool v_seen) {
    address = v_address;
    index = v_index;
    seen = v_seen;
}

String Bip47Address::getAddress() {
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

String Bip47Address::toString() {
    return address;
}
