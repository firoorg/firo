#ifndef BIP47_DEFS_H
#define BIP47_DEFS_H

#include <vector>

#include "base58.h"

#include "../util.h"

#define LogBip47(...) do { \
    LogPrintStr("bip47: " + tfm::format(__VA_ARGS__)); \
} while(0)

namespace bip47
{
    static constexpr size_t AddressLookaheadNumber = 10;

    static constexpr CAmount NotificationTxValue = 0.0001 * COIN;

    typedef std::vector<std::pair<CBitcoinAddress, CKey>> MyAddrContT;
    typedef std::vector<CBitcoinAddress> TheirAddrContT;
    typedef std::vector<unsigned char> Bytes;

    struct FindByAddress {
        FindByAddress(CBitcoinAddress const & address): address(address) {}
        bool operator()(MyAddrContT::value_type const & pair) const {return pair.first == address;}
        CBitcoinAddress const & address;
    };

}

#endif /* BIP47_DEFS_H */
