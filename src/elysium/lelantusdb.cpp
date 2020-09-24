// Copyright (c) 2020 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "convert.h"
#include "lelantusdb.h"

template<typename T>
T swapByteOrder(T t) {
    elysium::swapByteOrder(t);
    return t;
}

namespace elysium {

static const char DB_SERIAL             = 0x00;
static const char DB_SERIAL_SEQUENCE    = 0x01;

static const char DB_COIN = 0x02;
static const char DB_COIN_SEQUENCE = 0x03;
static const char DB_COIN_GROUP = 0x04;
static const char DB_COIN_GLOBAL_SEQUENCE = 0x05;

static const char DB_GROUPSIZE = 0x10;

namespace {

struct GroupData {
    uint64_t startSequence = 0;
    uint64_t extendedSequence = 0;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(startSequence);
        READWRITE(extendedSequence);
    }
};

} // unnamed namespace

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
    int groupId,
    size_t count)
{
    GroupData groupData;
    if (!db.Read(std::make_tuple(DB_COIN_GROUP, id, groupId), groupData)) {
        throw std::runtime_error("Fail to read first sequence in group");
    }
    auto first = groupData.extendedSequence;

    auto it = NewIterator();
    it->Seek(std::make_tuple(DB_COIN_SEQUENCE, id, ::swapByteOrder(first)));

    std::vector<lelantus::PublicCoin> coins;
    coins.reserve(count);

    std::pair<lelantus::PublicCoin, int> pubAndBlock;
    for (size_t i = 0; it->Valid() && i != count; it->Next(), i++) {
        std::tuple<char, PropertyId, uint64_t> key;
        if (!it->GetKey(key)) {
            break;
        }

        if (key != std::make_tuple(DB_COIN_SEQUENCE, id, ::swapByteOrder(first + i))) {
            break;
        }

        if (!it->GetValue(pubAndBlock)) {
            throw std::runtime_error("Fail to parse public coin and block");
        }

        coins.push_back(pubAndBlock.first);
    }

    return coins;
}

bool LelantusDb::RemoveMints(int block)
{
    auto nextGlobalSequence = GetNextSequence(DB_COIN_GLOBAL_SEQUENCE);
    if (nextGlobalSequence <= 0) {
        return false;
    }

    std::pair<PropertyId, uint64_t> idAndSequence;
    std::pair<lelantus::PublicCoin, int> coinAndBlock;

    std::unordered_map<PropertyId, uint64_t> lastLocalSequences;

    std::vector<std::tuple<char, uint64_t>> toBeRemoveSequences;
    std::vector<std::tuple<char, PropertyId, uint64_t>> toBeRemoveLocalSequences;

    do {

        auto sequenceKey = std::make_tuple(DB_COIN_GLOBAL_SEQUENCE, ::swapByteOrder(--nextGlobalSequence));
        if (!db.Read(sequenceKey, idAndSequence)) {
            throw std::runtime_error("Fail to get global sequence");
        }

        auto localSequenceKey = std::make_tuple(DB_COIN_SEQUENCE, idAndSequence.first, ::swapByteOrder(idAndSequence.second));
        if (!db.Read(localSequenceKey, coinAndBlock)) {
            throw std::runtime_error("Fail to get local sequence");
        }

        if (coinAndBlock.second >= block) {
            toBeRemoveSequences.push_back(sequenceKey);
            toBeRemoveLocalSequences.push_back(localSequenceKey);

            // record last local sequence
            lastLocalSequences[idAndSequence.first] = idAndSequence.second;
        }

    } while(nextGlobalSequence > 0 && coinAndBlock.second >= block);

    // remove sequence
    for (auto const &key : toBeRemoveSequences) {
        if (!db.Erase(key)) {
            throw std::runtime_error("Fail to remove sequence");
        }
    }

    for (auto const &key : toBeRemoveLocalSequences) {
        if (!db.Erase(key)) {
            throw std::runtime_error("Fail to remove global sequence");
        }
    }

    // prune groups
    for (auto const &idAndSequence : lastLocalSequences) {
        bool remove = true;
        while (remove) {
            remove = false;
            size_t coins;
            auto lastGroup = GetLastGroup(idAndSequence.first, coins);

            GroupData groupData;
            auto groupKey = std::make_tuple(DB_COIN_GROUP, idAndSequence.first, lastGroup);
            if (!db.Read(groupKey, groupData)) {
                throw std::runtime_error("Fail to get first sequence");
            }

            if (groupData.startSequence >= idAndSequence.second) {
                if (!db.Erase(groupKey)) {
                    throw std::runtime_error("Fail to erase group");
                }
                remove = true;
            }
        }
    }

    return !lastLocalSequences.empty();
}

bool LelantusDb::WriteMint(
    PropertyId propertyId,
    lelantus::PublicCoin const &pubKey,
    int block)
{
    auto coinKey = std::make_tuple(DB_COIN, propertyId, pubKey);
    if (db.Exists(coinKey)) {
        return false;
    }

    if (!db.Write(coinKey, 0)) {
        throw std::runtime_error("Fail to write coin");
    }

    // Write sequence in property
    auto nextSequence = GetNextSequence(DB_COIN_SEQUENCE, propertyId);

    if (!db.Write(std::make_tuple(DB_COIN_SEQUENCE, propertyId, ::swapByteOrder(nextSequence)), std::make_tuple(pubKey, block))) {
        throw std::runtime_error("Fail to write coin sequence");
    }

    // Write global sequence
    auto nextGlobalSequence = GetNextSequence(DB_COIN_GLOBAL_SEQUENCE);

    if (!db.Write(std::make_tuple(DB_COIN_GLOBAL_SEQUENCE, ::swapByteOrder(nextGlobalSequence)), std::make_tuple(propertyId, nextSequence))) {
        throw std::runtime_error("Fail to write coin global sequence");
    }

    // add new group if last group is full
    auto groupSizes = ReadGroupSize();

    size_t coins;
    auto lastGroup = GetLastGroup(propertyId, coins);

    if (coins > groupSizes.first) {
        StartNewGroup(propertyId, groupSizes.second);
    }

    return true;
}

bool LelantusDb::WriteGroupSize(size_t groupSize, size_t mintAmount)
{
    assert(groupSize > mintAmount);
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
    assert(groupSizes.first > groupSizes.second);

    return groupSizes;
}

int LelantusDb::GetLastGroup(PropertyId id, size_t &coins)
{
    auto nextSeq = GetNextSequence(DB_COIN_SEQUENCE, id);
    coins = nextSeq;

    GroupData groupData;
    int group = 0;
    if (!db.Exists(std::make_tuple(DB_COIN_GROUP, id, group))) {
        if (!db.Write(std::make_tuple(DB_COIN_GROUP, id, group), groupData)) {
            throw std::runtime_error("Fail to record group id 0");
        }
    }

    while (db.Read(std::make_tuple(DB_COIN_GROUP, id, group + 1), groupData)) {
        coins = nextSeq - groupData.extendedSequence;
        group++;
    }

    return group;
}

int LelantusDb::StartNewGroup(PropertyId id, size_t startCoins)
{
    auto nextSequence = GetNextSequence(DB_COIN_SEQUENCE, id);
    GroupData groupData;
    if (nextSequence == 0) {
        if (!db.Write(std::make_tuple(DB_COIN_GROUP, id, 0), groupData)) {
            throw std::runtime_error("Fail to record group id 0");
        }
        return 0;
    }

    // estimate condidate
    auto firstSeqCandidate = nextSequence - startCoins;

    auto it = NewIterator();
    it->Seek(std::make_tuple(DB_COIN_SEQUENCE, id, ::swapByteOrder(firstSeqCandidate)));

    if (!it->Valid()) {
        throw std::runtime_error("Fail to seek candidate");
    }

    std::pair<lelantus::PublicCoin, int> coin;
    if (!it->GetValue(coin)) {
        throw std::runtime_error("Fail to get value");
    }

    // find the first coin which is in the same block with first candidate
    int block = coin.second;
    uint64_t firstSeq = firstSeqCandidate;

    std::tuple<char, PropertyId, uint64_t> key;
    while (it->Valid() && firstSeq > 0) {
        if (!it->GetValue(coin)) {
            throw std::runtime_error("Fail to get value");
        }

        if (coin.second != block) {
            break;
        }

        if (!it->GetKey(key)) {
            throw std::runtime_error("Fail to get key");
        }

        if (std::get<1>(key) != id) {
            throw std::runtime_error("Lelantus database is inconsistent");
        }

        // record prior sequence which is in the same block
        firstSeq = ::swapByteOrder(std::get<2>(key));

        it->Prev();
    }

    size_t coins;
    auto nextGroup = GetLastGroup(id, coins) + 1;

    groupData.startSequence = nextSequence - 1;
    groupData.extendedSequence = firstSeq;

    if (!db.Write(std::make_tuple(DB_COIN_GROUP, id, nextGroup), groupData)) {
        throw std::runtime_error("Fail to record group id n");
    }

    return nextGroup;
}

std::unique_ptr<CDBIterator> LelantusDb::NewIterator()
{
    return std::unique_ptr<CDBIterator>(db.NewIterator());
}

} // namespace elysium