#ifndef ELYSIUM_CPP_BIGINT_H
#define ELYSIUM_CPP_BIGINT_H

#include "univalue.h"

// The client will parse objects created by this function as JS bigints.
UniValue BigInt(std::string s) {
    UniValue r = UniValue::VOBJ;
    r.pushKV("bigint", s);
    return r;
}

UniValue BigInt(uint64_t n) {
    std::ostringstream s;
    s << n;

    return BigInt(s.str());
}

#endif //ELYSIUM_CPP_BIGINT_H
