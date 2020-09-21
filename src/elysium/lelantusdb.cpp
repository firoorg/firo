// Copyright (c) 2020 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "convert.h"
#include "lelantusdb.h"

namespace elysium {

enum class KeyType : uint8_t
{
    // mint
    Coin = 0, // 0<id><order> = <public coin>
    CoinIndex = 1, // 1<id><block> = <order_i><order_j>
    BlockStoringIndex = 2, // 2<order> = 1<id><block>
    GroupIndex = 3, // 3<id><group_id> = <block_i><block_j>

    // serials
    Serial = 4, // 4<id><serial> = <block>
    SerialStoringOrder = 5, // 5<order> = <id><serial>
    SerialLastOrder = 6,
};

void SafeSeekToPreviousKey(leveldb::Iterator *it, const leveldb::Slice& key)
{
    it->Seek(key);
    if (it->Valid()) {
        it->Prev();
    } else {
        it->SeekToLast();
    }
}

// DB
LelantusDB::LelantusDB(size_t nCacheSize, bool fMemory, bool fWipe) :
    db(fMemory ? "" : GetDataDir() / "elysium_lelantusdb", nCacheSize, fMemory, fWipe)
{
}

bool LelantusDB::HasSerial(Scalar const &serial)
{
}

bool LelantusDB::RemoveSerials(int block)
{
}

bool LelantusDB::WriteSerials(
    int block,
    std::vector<std::pair<PropertyId, std::vector<Scalar>>> const &serials)
{
    auto order = ReadSerialOrder();

    for (auto const &propertySerials : serials) {
        // db.Write(std::make_tuple(), );
    }
}

bool LelantusDB::WriteSerialOrder(uint64_t order)
{
    return db.Write(KeyType::SerialLastOrder, order);
}

uint64_t LelantusDB::ReadSerialOrder()
{
    uint64_t order;
    if (!db.Read(KeyType::SerialLastOrder, order)) {
        return 0;
    }

    return order;
}

} // namespace elysium