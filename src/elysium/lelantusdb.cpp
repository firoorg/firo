// Copyright (c) 2020 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "convert.h"
#include "lelantusdb.h"

namespace elysium {

static const char DB_SERIAL             = 0x00;
static const char DB_SERIAL_SEQUENCE    = 0x01;
static const char DB_SERIAL_NEXT        = 0x02;

// DB
LelantusDb::LelantusDb(size_t nCacheSize, bool fMemory, bool fWipe) :
    db(fMemory ? "" : GetDataDir() / "elysium_lelantusdb", nCacheSize, fMemory, fWipe)
{
}

bool LelantusDb::HasSerial(PropertyId id, Scalar const &serial)
{
    return db.Exists(std::make_tuple(DB_SERIAL, id, serial));
}

bool LelantusDb::RemoveSerials(int block)
{
    auto sequence = ReadNextSerialSequence();
    if (sequence <= 0) {
        return false;
    }

    auto it = std::unique_ptr<CDBIterator>(db.NewIterator());
    auto _sequence = sequence - 1;
    swapByteOrder(_sequence);

    it->Seek(std::make_tuple(DB_SERIAL_SEQUENCE, _sequence));

    std::tuple<PropertyId, secp_primitives::Scalar, int> val;

    std::vector<std::tuple<char, uint64_t>> toBeRemoveSerialOrders;
    std::vector<std::tuple<char, PropertyId, secp_primitives::Scalar>> toBeRemoveSerials;

    CDataStream keyStream(SER_DISK, CLIENT_VERSION);
    for (; it->Valid()
        && (keyStream = it->GetKey()).size() > 0
        && keyStream[0] == DB_SERIAL_SEQUENCE;
        it->Prev()) {

        if (!it->GetValue(val)) {
            throw std::runtime_error("Fail to get value");
        }

        if (std::get<2>(val) < block) {
            break;
        }

        toBeRemoveSerialOrders.emplace_back();
        if (!it->GetKey(toBeRemoveSerialOrders.back())) {
            throw std::runtime_error("Fail to get sequence key");
        }

        toBeRemoveSerials.emplace_back(DB_SERIAL, std::get<0>(val), std::get<1>(val));

        sequence--;
    }

    for (auto const &removeKey : toBeRemoveSerialOrders) {
        if (!db.Erase(removeKey)) {
            throw std::runtime_error("Fail to erase key");
        }
    }

    for (auto const &removeKey : toBeRemoveSerials) {
        if (!db.Erase(removeKey)) {
            throw std::runtime_error("Fail to erase key");
        }
    }

    WriteNextSerialSequence(sequence);

    return true;
}

bool LelantusDb::WriteSerials(
    int block,
    std::vector<std::pair<PropertyId, std::vector<Scalar>>> const &serials)
{
    auto sequence = ReadNextSerialSequence();

    for (auto const &propertySerials : serials) {
        for (auto const &serial : propertySerials.second) {
            auto _sequence = sequence++;
            swapByteOrder(_sequence);

            db.Write(std::make_tuple(DB_SERIAL_SEQUENCE, _sequence),
                std::make_tuple(propertySerials.first, serial, block));

            db.Write(std::make_tuple(DB_SERIAL, propertySerials.first, serial), 0);
        }
    }

    WriteNextSerialSequence(sequence);

    return true;
}

bool LelantusDb::WriteNextSerialSequence(uint64_t sequence)
{
    return db.Write(DB_SERIAL_NEXT, sequence);
}

uint64_t LelantusDb::ReadNextSerialSequence()
{
    uint64_t sequence;
    if (!db.Read(DB_SERIAL_NEXT, sequence)) {
        return 0;
    }

    return sequence;
}

} // namespace elysium