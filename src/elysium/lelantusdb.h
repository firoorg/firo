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

    std::vector<lelantus::PublicCoin> GetMints(PropertyId id, int block);
    bool RemoveMints(int block);
    bool WriteMints(
        int block,
        std::vector<std::pair<PropertyId, std::vector<lelantus::PublicCoin>>> const &mints
        );

protected:
    bool WriteNextSerialSequence(uint64_t);
    uint64_t ReadNextSerialSequence();

    bool WriteGroupSize(size_t groupSize, size_t mintAmount);
    std::pair<size_t, size_t> ReadGroupSize();
};

} // namespace elysium

#endif // ZCOIN_ELYSIUM_LELANTUSDB_H