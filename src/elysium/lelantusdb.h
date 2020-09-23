// Copyright (c) 2020 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_ELYSIUM_LELANTUSDB_H
#define ZCOIN_ELYSIUM_LELANTUSDB_H

#include "../dbwrapper.h"
#include "../sync.h"
#include "../liblelantus/coin.h"

#include "property.h"

namespace elysium {

class LelantusDb
{
protected:
    CCriticalSection cs;
    CDBWrapper db;

    static const size_t DEFAULT_GROUPSIZE = 65000;
    static const size_t DEFAULT_STARTCOINS = 16000;

public:
    LelantusDb(size_t nCacheSize, bool fMemory = false, bool fWipe = false, size_t groupSize = DEFAULT_GROUPSIZE, size_t startCoins = DEFAULT_STARTCOINS);

public:
    bool HasSerial(PropertyId id, Scalar const &serial, uint256 &spendTx);
    bool RemoveSerials(int block);
    bool WriteSerial(
        PropertyId id,
        secp_primitives::Scalar serial,
        int block,
        uint256 const &spendTx);

    std::vector<lelantus::PublicCoin> GetAnonimityGroup(
        PropertyId id,
        uint32_t groupId,
        size_t count);

    bool RemoveMints(int block);
    bool WriteMint(
        PropertyId propertyId,
        lelantus::PublicCoin const &pubKey,
        int block);

protected:

    template<typename ...T>
    uint64_t GetNextSequence(T ...t) {
        auto key = std::make_tuple(t..., UINT64_MAX);
        auto it = NewIterator();

        it->Seek(key);

        if (!it->Valid()) {
            return 0;
        }

        it->Prev();
        if (!it->Valid()) {
            return 0;
        }

        auto key2 = key;
        if (!it->GetKey(key2)) {
            return 0;
        }

        std::get<sizeof...(t)>(key) = std::get<sizeof...(t)>(key2);

        if (key != key2) {
            return 0;
        }

        auto v = std::get<sizeof...(t)>(key);
        swapByteOrder(v);

        return v + 1;
    }

    bool WriteGroupSize(size_t groupSize, size_t mintAmount);
    std::pair<size_t, size_t> ReadGroupSize();

    std::unique_ptr<CDBIterator> NewIterator();
};

} // namespace elysium

#endif // ZCOIN_ELYSIUM_LELANTUSDB_H