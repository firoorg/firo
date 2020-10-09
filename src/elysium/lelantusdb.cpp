// Copyright (c) 2020 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "convert.h"
#include "lelantusdb.h"

#include "ui_interface.h"

template<typename T>
T swapByteOrder(T t) {
    elysium::swapByteOrder(t);
    return t;
}

namespace elysium {

static const char DB_SERIAL             = 's';
static const char DB_PENDING_COIN       = 'p';
static const char DB_COIN               = 'c';
static const char DB_COIN_SEQUENCE      = 'C';
static const char DB_COIN_GROUP         = 'g';
static const char DB_COIN_ID            = 'i';
static const char DB_UNDO               = 'u';
static const char DB_GROUPSIZE          = 'x';

static const char UNDO_REMOVE_SERIAL    = 's';
static const char UNDO_REMOVE_COIN      = 'c';
static const char UNDO_REMOVE_COIN_SEQ  = 'S';
static const char UNDO_REMOVE_COIN_ID   = 'I';
static const char UNDO_REMOVE_GROUP     = 'g';

namespace {

struct UndoEntry
{
    char undoType;
    int block;
    std::string data;

    UndoEntry() : undoType(0), block(0)
    {
    }

    UndoEntry(char undoType, int block, leveldb::Slice const &r) : undoType(undoType), block(block), data(r.data(), r.data() + r.size())
    {
    }

    UndoEntry(char undoType, int block, std::string const &r) : undoType(undoType), block(block), data(r)
    {
    }

    template <typename T>
    UndoEntry(char undoType, int block, T t) : undoType(undoType), block(block) {
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << t;
        data = ss.str();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(undoType);
        READWRITE(block);
        READWRITE(data);
    }
};

template <typename ...T>
std::string MakeRaw(T ...t)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << std::make_tuple(t...);

    return ss.str();
}

template <typename T>
bool ParseRaw(leveldb::Slice const &raw, T &t)
{
    CDataStream ss(raw.data(), raw.data() + raw.size(), SER_DISK, CLIENT_VERSION);
    ss >> t;

    return ss.eof();
}

template <typename T>
bool ParseRaw(std::string const &raw, T &t)
{
    CDataStream ss(raw.data(), raw.data() + raw.size(), SER_DISK, CLIENT_VERSION);
    ss >> t;

    return ss.eof();
}

// Utility struct to store undo entries
struct UndoRecorder
{
private:
    leveldb::WriteBatch &batch;
    uint64_t undoSequence;

public:
    UndoRecorder(leveldb::WriteBatch &batch, uint64_t nextUndoSequence)
        : batch(batch), undoSequence(nextUndoSequence)
    {
    }

    template <typename T>
    uint64_t Record(char undoType, int block, T t) {

        UndoEntry entry(undoType, block, t);
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << entry;

        batch.Put(MakeRaw(DB_UNDO, ::swapByteOrder(undoSequence)), leveldb::Slice(ss.data(), ss.size()));
        return ++undoSequence;
    }
};

struct CoinSequenceData {
    lelantus::PublicCoin publicCoin;
    int block;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(publicCoin);
        READWRITE(block);
    }
};

} // unnamed namespace

// DB
LelantusDb::LelantusDb(const boost::filesystem::path& path, bool wipe, size_t groupSize, size_t startCoins)
    : groupSize(groupSize), startGroupSize(startCoins)
{
    auto status = Open(path, wipe);
    if (!status.ok()) {
        throw std::runtime_error("Failed to create " + path.string() + ": " + status.ToString());
    }

    auto size = ReadGroupSize();
    if (size != std::make_pair(groupSize, startCoins)) {
        if (!WriteGroupSize(groupSize, startCoins)) {
            throw std::runtime_error("Failed to write group size");
        }
    }

    // TODO: throw if found pending coins
}

bool LelantusDb::HasSerial(PropertyId id, Scalar const &serial, uint256 &spendTx)
{
    std::string data;
    auto status = pdb->Get(readoptions, MakeRaw(DB_SERIAL, id, serial), &data);
    if (!status.ok()) {
        return false;
    }
    ParseRaw(data, spendTx);

    return true;
}

bool LelantusDb::WriteSerial(
    PropertyId id,
    secp_primitives::Scalar serial,
    int block,
    uint256 const &spendTx)
{
    leveldb::WriteBatch batch;

    auto nextSequence = GetNextSequence(DB_UNDO);
    UndoRecorder undoRecorder(batch, nextSequence);

    uint256 tx;
    if (HasSerial(id, serial, tx)) {
        return false;
    }

    // write serial
    auto key = MakeRaw(DB_SERIAL, id, serial);
    batch.Put(key, MakeRaw(spendTx));

    // write undo
    undoRecorder.Record(UNDO_REMOVE_SERIAL, block, key);

    return pdb->Write(syncoptions, &batch).ok();
}

std::vector<lelantus::PublicCoin> LelantusDb::GetAnonimityGroup(
    PropertyId id,
    int groupId,
    size_t count)
{
    LOCK(cs);

    uint64_t startSeq = UINT64_MAX;
    std::string rawStartSeq;

    if (!pdb->Get(readoptions, MakeRaw(DB_COIN_GROUP, id, groupId), &rawStartSeq).ok() || !ParseRaw(rawStartSeq, startSeq)) {
        throw std::runtime_error("Fail to read first sequence in group");
    }

    auto it = NewIterator();
    it->Seek(MakeRaw(DB_COIN_SEQUENCE, id, ::swapByteOrder(startSeq)));

    std::vector<lelantus::PublicCoin> coins;
    CoinSequenceData coinSeqData;
    for (size_t i = 0;
        i != count
        && it->Valid()
        && it->key() == MakeRaw(DB_COIN_SEQUENCE, id, ::swapByteOrder(startSeq + i)); it->Next(), i++) {

        ParseRaw(it->value(), coinSeqData);
        coins.push_back(coinSeqData.publicCoin);
    }

    return coins;
}

bool LelantusDb::HasMint(PropertyId propertyId, lelantus::PublicCoin const &pubKey)
{
    auto coinKey = MakeRaw(DB_COIN, propertyId, pubKey);
    std::string val;
    return pdb->Get(readoptions, coinKey, &val).ok();
}

bool LelantusDb::WriteMint(
    PropertyId propertyId,
    lelantus::PublicCoin const &pubKey,
    int block,
    MintEntryId const &id,
    std::vector<unsigned char> const &additional)
{
    leveldb::WriteBatch batch;

    auto nextUndoSeq = GetNextSequence(DB_UNDO);
    UndoRecorder undoRecorder(batch, nextUndoSeq);

    auto coinKey = MakeRaw(DB_COIN, propertyId, pubKey);
    std::string data;
    if (pdb->Get(readoptions, coinKey, &data).ok()) {
        return false;
    }

    // add coin index
    batch.Put(coinKey, MakeRaw(id, additional));
    undoRecorder.Record(UNDO_REMOVE_COIN, block, coinKey);

    // add tag index
    auto tagIndexKey = MakeRaw(DB_COIN_ID, propertyId, id);
    batch.Put(tagIndexKey, coinKey);
    undoRecorder.Record(UNDO_REMOVE_COIN_ID, block, tagIndexKey);

    // add pending
    auto nextPendingSeq = GetNextSequence(DB_PENDING_COIN);
    batch.Put(MakeRaw(DB_PENDING_COIN, ::swapByteOrder(nextPendingSeq++)), MakeRaw(propertyId, pubKey, block));

    return pdb->Write(syncoptions, &batch).ok();
}

bool LelantusDb::HasMint(PropertyId propertyId, MintEntryId const &id)
{
    auto tagKey = MakeRaw(DB_COIN_ID, propertyId, id);
    std::string val;
    return pdb->Get(readoptions, tagKey, &val).ok();
}

void LelantusDb::CommitCoins()
{
    LOCK(cs);

    leveldb::WriteBatch batch;

    auto nextUndoSeq = GetNextSequence(DB_UNDO);
    UndoRecorder undoRecorder(batch, nextUndoSeq);

    auto it = NewIterator();
    it->Seek(MakeRaw(DB_PENDING_COIN, uint64_t(0)));

    int block = -1;

    // get pendings
    std::map<PropertyId, std::vector<lelantus::PublicCoin>> entries;
    std::tuple<PropertyId, lelantus::PublicCoin, int> entry;
    leveldb::Slice key;
    for (; it->Valid() && (key = it->key()).size() > 0 && key[0] == DB_PENDING_COIN; it->Next()) {
        if (!ParseRaw(it->value(), entry)) {
            throw std::runtime_error("Fail to parse pending entry");
        }

        if (block == -1) {
            block = std::get<2>(entry);
        }

        if (block != std::get<2>(entry)) {
            throw std::runtime_error("Lelantus state is inconsistent");
        }

        entries[std::get<0>(entry)].push_back(std::get<1>(entry));

        batch.Delete(key);
    }

    // write all pendings
    for (auto const &idAndPubKeys : entries) {

        auto propertyId = idAndPubKeys.first;
        auto nextCoinSeq = GetNextSequence(DB_COIN_SEQUENCE, propertyId);

        // record sequence
        for (auto const &pubKey : idAndPubKeys.second) {
            auto coinSequenceKey = MakeRaw(DB_COIN_SEQUENCE, propertyId, ::swapByteOrder(nextCoinSeq++));
            batch.Put(coinSequenceKey, MakeRaw(CoinSequenceData{ .publicCoin = pubKey, .block = block }));
            undoRecorder.Record(UNDO_REMOVE_COIN_SEQ, block, coinSequenceKey);
        }

        size_t newCoins = idAndPubKeys.second.size();
        size_t coins = 0;
        auto lastGroup = GetLastGroup(propertyId, coins);

        if (coins + newCoins > groupSize) {
            // create new group
            auto required = newCoins > startGroupSize ? 0 : (startGroupSize - newCoins);

            // find best candidate
            auto nextCoinSeq = GetNextSequence(DB_COIN_SEQUENCE, propertyId);
            auto includedSeq = nextCoinSeq - required;

            // find first sequence in block
            auto it = NewIterator();
            it->Seek(MakeRaw(DB_COIN_SEQUENCE, propertyId, ::swapByteOrder(includedSeq)));

            int includedBlock = -1;
            auto firstSeq = includedSeq;
            CoinSequenceData data;
            for (; it->Valid() && it->key() == MakeRaw(DB_COIN_SEQUENCE, propertyId, ::swapByteOrder(includedSeq)); it->Prev(), includedSeq--) {
                if (!ParseRaw(it->value(), data)) {
                    throw std::runtime_error("Fail to parse sequence data");
                }

                includedBlock = includedBlock == -1 ? data.block : includedBlock;
                if (includedBlock != data.block) {
                    break;
                }

                firstSeq = includedSeq;
            }

            // write group
            auto groupKey = MakeRaw(DB_COIN_GROUP, propertyId, lastGroup + 1);
            batch.Put(groupKey, MakeRaw(firstSeq));
            undoRecorder.Record(UNDO_REMOVE_GROUP, block, groupKey);
        }
    }

    pdb->Write(syncoptions, &batch);
}

void LelantusDb::DeleteAll(int startBlock)
{
    LOCK(cs);
    auto next = GetNextSequence(DB_UNDO);
    if (next == 0) {
        return;
    }

    auto it = NewIterator();
    it->Seek(MakeRaw(DB_UNDO, ::swapByteOrder(next - 1)));

    leveldb::WriteBatch batch;
    leveldb::Slice key;
    for (; it->Valid() && (key = it->key()).size() > 0 && key[0] == DB_UNDO; it->Prev()) {
        UndoEntry undoEntry;
        ParseRaw(it->value(), undoEntry);

        if (undoEntry.block < startBlock) {
            break;
        }

        switch (undoEntry.undoType) {
        case UNDO_REMOVE_SERIAL:
            batch.Delete(undoEntry.data);
            break;
        case UNDO_REMOVE_COIN:
            batch.Delete(undoEntry.data);
            break;
        case UNDO_REMOVE_COIN_SEQ:
            batch.Delete(undoEntry.data);
            break;
        case UNDO_REMOVE_GROUP:
            batch.Delete(undoEntry.data);
            break;
        case UNDO_REMOVE_COIN_ID:
            batch.Delete(undoEntry.data);
            break;
        default:
            throw std::runtime_error(strprintf("Unknown type : %d", undoEntry.undoType));
        }
    }

    auto status = pdb->Write(syncoptions, &batch);
    if (!status.ok()) {
        throw std::runtime_error("Failed to write database: " + status.ToString());
    }
}

bool LelantusDb::WriteGroupSize(size_t groupSize, size_t mintAmount)
{
    assert(groupSize > mintAmount);
    std::string data;
    if (pdb->Get(readoptions, MakeRaw(DB_GROUPSIZE), &data).ok()) {
        return false;
    }

    return pdb->Put(writeoptions, MakeRaw(DB_GROUPSIZE), MakeRaw(groupSize, mintAmount)).ok();
}

std::pair<size_t, size_t> LelantusDb::ReadGroupSize()
{
    std::string data;
    if (!pdb->Get(readoptions, MakeRaw(DB_GROUPSIZE), &data).ok()) {
        return {0, 0};
    }

    std::pair<size_t, size_t> groupSizes;
    ParseRaw(data, groupSizes);

    assert(groupSizes.first > groupSizes.second);

    return groupSizes;
}

int LelantusDb::GetLastGroup(PropertyId id, size_t &coins)
{
    auto nextSeq = GetNextSequence(DB_COIN_SEQUENCE, id);
    coins = nextSeq;

    int group = 0;

    std::string data;
    if (!pdb->Get(readoptions, MakeRaw(DB_COIN_GROUP, id, group), &data).ok()) {
        if (!pdb->Put(writeoptions, MakeRaw(DB_COIN_GROUP, id, group), MakeRaw(uint64_t(0))).ok()) {
            throw std::runtime_error("Fail to record group id 0");
        }
    }

    uint64_t startSequence;
    while (pdb->Get(readoptions, MakeRaw(DB_COIN_GROUP, id, group + 1), &data).ok() && ParseRaw(data, startSequence)) {
        coins = nextSeq - startSequence;
        group++;
    }

    return group;
}

std::unique_ptr<leveldb::Iterator> LelantusDb::NewIterator()
{
    return std::unique_ptr<leveldb::Iterator>(CDBBase::NewIterator());
}

LelantusDb *lelantusDb;

} // namespace elysium