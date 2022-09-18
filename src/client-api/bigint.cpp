#include "univalue.h"
#include "bigint.h"
#include <boost/lexical_cast.hpp>

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

int64_t get_bigint(const UniValue& u) {
    return boost::lexical_cast<int64_t>(u.get_str());
}