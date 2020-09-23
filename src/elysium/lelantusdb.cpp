// Copyright (c) 2020 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "convert.h"
#include "lelantusdb.h"

namespace elysium {

static const char DB_SERIAL             = 0x00;
static const char DB_SERIAL_SEQUENCE    = 0x01;

static const char DB_COIN = 0x02;
static const char DB_COIN_SEQUENCE = 0x03;
static const char DB_COIN_GROUP = 0x04;
static const char DB_COIN_GLOBAL_SEQUENCE = 0x05;

static const char DB_GROUPSIZE = 0x10;

// DB
LelantusDb::LelantusDb(size_t nCacheSize, bool fMemory, bool fWipe, size_t groupSize, size_t startCoins) :
    db(fMemory ? "" : GetDataDir() / "elysium_lelantusdb", nCacheSize, fMemory, fWipe)
{
    WriteGroupSize(groupSize, startCoins);
}

bool LelantusDb::HasSerial(PropertyId id, Scalar const &serial, uint256 &spendTx)
{
    return db.Read(std::make_tuple(DB_SERIAL, id, serial), spendTx);
}

bool LelantusDb::RemoveSerials(int block)
{
    auto sequence = GetNextSequence(DB_SERIAL_SEQUENCE);
    if (sequence <= 0) {
        return false;
    }

    auto it = NewIterator();
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

    return true;
}

bool LelantusDb::WriteSerial(
    PropertyId id,
    secp_primitives::Scalar serial,
    int block,
    uint256 const &spendTx)
{
    if (db.Exists(std::make_tuple(DB_SERIAL, id, serial))) {
        return false;
    }

    auto sequence = GetNextSequence(DB_SERIAL_SEQUENCE);
    auto _sequence = sequence++;

    swapByteOrder(_sequence);

    db.Write(std::make_tuple(DB_SERIAL_SEQUENCE, _sequence),
        std::make_tuple(id, serial, block));

    db.Write(std::make_tuple(DB_SERIAL, id, serial), spendTx);

    return true;
}

std::vector<lelantus::PublicCoin> LelantusDb::GetAnonimityGroup(
    PropertyId id,
    uint32_t groupId,
    size_t count)
{
}

bool LelantusDb::RemoveMints(int block)
{
}

bool LelantusDb::WriteMint(
    PropertyId propertyId,
    lelantus::PublicCoin const &pubKey,
    int block)
{
}

bool LelantusDb::WriteGroupSize(size_t groupSize, size_t mintAmount)
{
    if (db.Exists(DB_GROUPSIZE)) {
        return false;
    }

    return db.Write(DB_GROUPSIZE, std::make_pair(groupSize, mintAmount));
}

std::pair<size_t, size_t> LelantusDb::ReadGroupSize()
{
    std::pair<size_t, size_t> groupSizes;
    if (!db.Read(DB_GROUPSIZE, groupSizes)) {
        throw std::runtime_error("Fail to read group size");
    }

    return groupSizes;
}

std::unique_ptr<CDBIterator> LelantusDb::NewIterator()
{
    return std::unique_ptr<CDBIterator>(db.NewIterator());
}

} // namespace elysium