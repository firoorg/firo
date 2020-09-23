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
private:
    CCriticalSection cs;
    CDBWrapper db;

public:
    LelantusDb(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

public:
    bool HasSerial(PropertyId id, Scalar const &serial);
    bool RemoveSerials(int block);
    bool WriteSerials(
        int block,
        std::vector<std::pair<PropertyId, std::vector<Scalar>>> const &serials);

protected:
    bool WriteNextSerialSequence(uint64_t);
    uint64_t ReadNextSerialSequence();
};

} // namespace elysium

#endif // ZCOIN_ELYSIUM_LELANTUSDB_H