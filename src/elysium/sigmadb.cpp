#include "exodus.h"
#include "errors.h"
#include "log.h"
#include "sigmadb.h"
#include "sp.h"
#include "tally.h"
#include "tx.h"

#include <GroupElement.h>
#include "../clientversion.h"
#include "../tinyformat.h"
#include "../streams.h"

#include <boost/filesystem.hpp>

#include <leveldb/db.h>
#include <leveldb/write_batch.h>

#include <string>
#include <vector>

namespace elysium {

enum class KeyType : uint8_t
{
    Mint = 0,
    Sequence = 1,
    GroupSize = 2,
    SpendSerial = 3
};

template<typename ... T>
struct SizeOf;

template<typename T>
struct SizeOf<T>
{
    static constexpr size_t Value = (sizeof(T));
};

template<typename T, typename ...R>
struct SizeOf<T, R ...>
{
    static constexpr size_t Value = (sizeof(T) + SizeOf<R...>::Value);
};

template<typename It>
It SerializeKey(It it)
{
    return it;
}

template<typename It, typename ArrT, size_t ArrS, typename ...R>
It SerializeKey(It it, std::array<ArrT, ArrS> t, R ...r)
{
    it = std::copy(t.begin(), t.end(), it);
    return SerializeKey(it, r...);
}

template<
    typename It, typename T, typename ...R,
    typename std::enable_if<std::is_arithmetic<T>::value>::type* = nullptr
> It SerializeKey(It it, T t, R ...r)
{
    if (sizeof(t) > 1) {
        elysium::swapByteOrder(t);
    }
    it = std::copy_n(reinterpret_cast<uint8_t*>(&t), sizeof(t), it);
    return SerializeKey(it, r...);
}

template<typename ...T, size_t S = SizeOf<KeyType, T...>::Value>
std::array<uint8_t, S> CreateKey(KeyType type, T ...args)
{
    std::array<uint8_t, S> key;
    auto it = key.begin();
    it = std::copy_n(reinterpret_cast<uint8_t*>(&type), sizeof(type), it);

    SerializeKey(it, args...);

    return key;
}

// array size represent size of key
// <1 byte of type><4 bytes of property Id><1 byte of denomination><4 bytes of group id><2 bytes of idx>
#define MINT_KEY_SIZE sizeof(KeyType) + sizeof(uint8_t) + sizeof(uint16_t) + 2 * sizeof(uint32_t)
std::array<uint8_t, MINT_KEY_SIZE> CreateMintKey(
    uint32_t propertyId,
    uint8_t denomination,
    uint32_t groupId,
    uint16_t idx)
{
    return CreateKey(KeyType::Mint, propertyId, denomination, groupId, idx);
}

// array size represent size of key
// <1 byte of type><8 bytes of sequence>
#define SEQUENCE_KEY_SIZE sizeof(KeyType) + sizeof(uint64_t)
std::array<uint8_t, SEQUENCE_KEY_SIZE> CreateSequenceKey(
    uint64_t sequence)
{
    return CreateKey(KeyType::Sequence, sequence);
}

// array size represent size of key
// <1 byte of type>
#define GROUPSIZE_KEY_SIZE sizeof(KeyType)
std::array<uint8_t, GROUPSIZE_KEY_SIZE> CreateGroupSizeKey()
{
    return CreateKey(KeyType::GroupSize);
}

typedef std::array<uint8_t, 32> SpendSerial;

// array size represent size of key
// <1 byte of type><4 bytes of property Id><1 byte of denomination><32 bytes of serials>
#define SPEND_KEY_SIZE sizeof(KeyType) + sizeof(uint32_t) + sizeof(uint8_t) + std::tuple_size<SpendSerial>::value
std::array<uint8_t, SPEND_KEY_SIZE> CreateSpendSerialKey(
    uint32_t propertyId,
    uint8_t denomination,
    SpendSerial const &serial)
{
    return CreateKey(KeyType::SpendSerial, propertyId, denomination, serial);
}

inline bool IsMintKey(leveldb::Slice const &key)
{
    return key.size() == MINT_KEY_SIZE && key[0] == static_cast<char>(KeyType::Mint);
}

inline bool IsMintEntry(leveldb::Iterator *it)
{
    return IsMintKey(it->key());
}

inline bool IsSequenceKey(leveldb::Slice const &key)
{
    return key.size() == SEQUENCE_KEY_SIZE && key[0] == static_cast<char>(KeyType::Sequence);
}

inline bool IsSequenceEntry(leveldb::Iterator *it)
{
    return IsSequenceKey(it->key());
}

inline bool IsSpendSerialKey(leveldb::Slice const &key)
{
    return key.size() == SPEND_KEY_SIZE && key[0] == static_cast<char>(KeyType::SpendSerial);
}

inline bool IsSpendSerialEntry(leveldb::Iterator *it)
{
    return IsSpendSerialKey(it->key());
}

template<size_t S>
leveldb::Slice GetSlice(const std::array<uint8_t, S>& v)
{
    return leveldb::Slice(reinterpret_cast<const char*>(v.data()), v.size());
}

template<typename T, typename Allocator>
leveldb::Slice GetSlice(const std::vector<T, Allocator>& v)
{
    return leveldb::Slice(reinterpret_cast<const char *>(v.data()), v.size() * sizeof(T));
}

SigmaPublicKey ParseMint(const std::string& val)
{
    if (val.size() != secp_primitives::GroupElement::serialize_size) {
        throw std::runtime_error("ParseMint() : invalid key size");
    }

    SigmaPublicKey key;
    key.commitment.deserialize(reinterpret_cast<const unsigned char*>(val.data()));

    return key;
}

bool ParseMintKey(
    const leveldb::Slice& key, uint32_t& propertyId, uint8_t& denomination, uint32_t& groupId, uint16_t& idx)
{
    if (key.size() > 0 && key.data()[0] == static_cast<char>(KeyType::Mint)) {
        if (key.size() != MINT_KEY_SIZE) {
           throw std::runtime_error("invalid key size");
        }

        auto it = key.data() + sizeof(KeyType);
        std::memcpy(&propertyId, it, sizeof(propertyId));
        std::memcpy(&denomination, it += sizeof(propertyId), sizeof(denomination));
        std::memcpy(&groupId, it += sizeof(denomination), sizeof(groupId));
        std::memcpy(&idx, it += sizeof(groupId), sizeof(idx));

        elysium::swapByteOrder(propertyId);
        elysium::swapByteOrder(groupId);
        elysium::swapByteOrder(idx);

        return true;
    }
    return false;
}

bool ParseSpendSerialKey(
    const leveldb::Slice& key, uint32_t& propertyId, uint8_t& denomination, SpendSerial& serial)
{
    if (key.size() > 0 && key.data()[0] == static_cast<char>(KeyType::SpendSerial)) {
        if (key.size() != SPEND_KEY_SIZE) {
           throw std::runtime_error("invalid key size");
        }

        auto it = key.data() + sizeof(KeyType);
        std::memcpy(&propertyId, it, sizeof(propertyId));
        std::memcpy(&denomination, it += sizeof(propertyId), sizeof(denomination));
        std::memcpy(serial.data(), it += sizeof(denomination), std::tuple_size<SpendSerial>::value);

        elysium::swapByteOrder(propertyId);

        return true;
    }
    return false;
}

SpendSerial SerializeSpendSerial(secp_primitives::Scalar const &serial)
{
    SpendSerial s;
    if (serial.memoryRequired() != std::tuple_size<SpendSerial>::value) {
        throw std::invalid_argument("serial size is invalid");
    }

    serial.serialize(s.data());
    return s;
}

void SafeSeekToPreviousKey(leveldb::Iterator *it, const leveldb::Slice& key)
{
    it->Seek(key);
    if (it->Valid()) {
        it->Prev();
    } else {
        it->SeekToLast();
    }
}

SigmaDatabase *sigmaDb;

constexpr uint16_t SigmaDatabase::MAX_GROUP_SIZE;

// Database structure
// Index height and commitment
// 0<prob_id><denom><group_id><idx>=<GroupElement><int>
// Sequence of mint sorted following blockchain
// 1<seq uint64>=key
SigmaDatabase::SigmaDatabase(const boost::filesystem::path& path, bool wipe, uint16_t groupSize)
{
    auto status = Open(path, wipe);
    if (!status.ok()) {
        throw std::runtime_error("Failed to create " + path.string() + ": " + status.ToString());
    }

    this->groupSize = InitGroupSize(groupSize);
}

SigmaDatabase::~SigmaDatabase()
{
}

std::pair<SigmaMintGroup, SigmaMintIndex> SigmaDatabase::RecordMint(
    PropertyId propertyId,
    SigmaDenomination denomination,
    const SigmaPublicKey& pubKey,
    int height)
{
    auto lastGroup = GetLastGroupId(propertyId, denomination);
    auto mints = GetMintCount(propertyId, denomination, lastGroup);

    if (mints > groupSize) {
        throw std::runtime_error("mints count is exceed group limit");
    }
    auto nextIdx = mints;

    if (mints == groupSize) {
        lastGroup++;
        nextIdx = 0;
    }

    // Add mint entry.
    auto keyData = CreateMintKey(propertyId, denomination, lastGroup, nextIdx);
    auto key = GetSlice(keyData);

    std::vector<uint8_t> buffer(pubKey.commitment.memoryRequired());
    pubKey.commitment.serialize(buffer.data());

    AddEntry(key, GetSlice(buffer), height);

    // Raise event.
    MintAdded(propertyId, denomination, lastGroup, nextIdx, pubKey, height);

    return std::make_pair(lastGroup, nextIdx);
}

void SigmaDatabase::RecordSpendSerial(
    uint32_t propertyId,
    uint8_t denomination,
    secp_primitives::Scalar const &serial,
    int height,
    uint256 const &spendTx)
{
    auto serialData = SerializeSpendSerial(serial);
    auto keyData = CreateSpendSerialKey(propertyId, denomination, serialData);

    AddEntry(GetSlice(keyData), leveldb::Slice(std::string(spendTx.begin(), spendTx.end())), height);

    SpendAdded(propertyId, denomination, serial, spendTx);
}

// operation code of histories
enum class OpCode : uint8_t
{
    StoreMint = 0,
    StoreSpendSerial = 1
};

class History
{
public:
    History()
    {
    }

    History(int32_t block, OpCode op, std::vector<uint8_t> const &data)
        : block(block), op(op), data(data.begin(), data.end())
    {
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        auto op = static_cast<uint8_t>(this->op);

        READWRITE(block);
        READWRITE(op);
        READWRITE(data);

        this->op = static_cast<OpCode>(op);
    }

    int32_t block;
    OpCode op;
    std::vector<uint8_t> data;
};

void SigmaDatabase::DeleteAll(int startBlock)
{
    auto nextSequence = GetNextSequence();
    if (nextSequence == 0) {
        // No mint to delete
        return;
    }

    // Seek to most recent history.
    auto lastSequence = nextSequence - 1;
    auto sequenceKey = CreateSequenceKey(lastSequence);

    auto it = NewIterator();
    it->Seek(GetSlice(sequenceKey));

    leveldb::WriteBatch batch;
    std::vector<std::function<void()>> defers; // functions to be called after delete whole keys
    for (; it->Valid() && IsSequenceEntry(it.get()); it->Prev()) {

        CDataStream deserialized(
            it->value().data(),
            it->value().data() + it->value().size(),
            SER_DISK, CLIENT_VERSION
        );

        // Check if it need to delete then push it to batch
        History entry;
        deserialized >> entry;

        if (entry.block < startBlock) {
            // We iterate in the latest to oldest that mean we can stop as soon as we found it block number is lower
            // than theshold.
            break;
        }

        // intentionally using if instead of switch to separate scope
        if (entry.op == OpCode::StoreMint) {
            auto key = GetSlice(entry.data);

            // retrieve meta data of mint
            uint32_t propertyId;
            uint8_t denomination;
            uint32_t groupId;
            uint16_t count;
            if (!ParseMintKey(key, propertyId, denomination, groupId, count)) {
                throw std::runtime_error("fail to parse mint key");
            }

            // get commitment
            std::string data;
            auto status = pdb->Get(readoptions, key, &data);
            if (!status.ok()) {
                throw std::runtime_error("fail to get mint");
            }
            CDataStream pubkeyDeserialized(data.data(), data.data() + data.size(), SER_DISK, CLIENT_VERSION);
            SigmaPublicKey pub;
            pubkeyDeserialized >> pub;

            // function to trigger event
            defers.push_back([this, propertyId, denomination, pub]() {
                MintRemoved(propertyId, denomination, pub);
            });

            batch.Delete(GetSlice(entry.data));
        } else if (entry.op == OpCode::StoreSpendSerial) {
            auto key = GetSlice(entry.data);

            // retrieve meta data of spend
            uint32_t propertyId;
            uint8_t denomination;
            SpendSerial serialData;
            ParseSpendSerialKey(key, propertyId, denomination, serialData);

            secp_primitives::Scalar serial;
            serial.deserialize(serialData.data());

            // function to trigger event
            defers.push_back([this, propertyId, denomination, serial]() {
                SpendRemoved(propertyId, denomination, serial);
            });

            batch.Delete(key);
        } else {
            throw std::runtime_error("opcode is invalid");
        }

        batch.Delete(it->key());
    }

    auto status = pdb->Write(syncoptions, &batch);
    if (!status.ok()) {
        throw std::runtime_error("Fail to update database");
    }

    for (auto &defer : defers) {
        defer();
    }
}

void SigmaDatabase::RecordGroupSize(uint16_t groupSize)
{
    auto key = CreateGroupSizeKey();

    auto status = pdb->Put(writeoptions, GetSlice(key),
        leveldb::Slice(reinterpret_cast<char*>(&groupSize), sizeof(groupSize)));

    if (!status.ok()) {
        throw std::runtime_error("store sigma mint group size fail");
    }
}

uint16_t SigmaDatabase::GetGroupSize()
{
    auto key = CreateGroupSizeKey();

    std::string result;
    auto status = pdb->Get(readoptions, GetSlice(key), &result);

    if (status.ok()) {
        uint16_t groupSize(0);

        if (result.size() == sizeof(groupSize)) {
            std::copy_n(result.data(), result.size(), reinterpret_cast<char*>(&groupSize));
            return groupSize;
        }

        throw std::runtime_error("size of group size value is invalid");
    }

    if (!status.IsNotFound()) {
        throw std::runtime_error("fail to read group size from database");
    }
    return 0;
}

uint16_t SigmaDatabase::InitGroupSize(uint16_t groupSize)
{
    if (groupSize > MAX_GROUP_SIZE) {
        throw std::invalid_argument("group size exceed limit");
    }

    uint16_t currentGroupSize = GetGroupSize();

    if (!groupSize) {
        if (currentGroupSize) {
            // if groupSize == 0 and have groupSize in db
            // mean user need to use current groupSize
            return currentGroupSize;
        } else {
            // groupSize in db isn't set
            groupSize = MAX_GROUP_SIZE;
        }
    } else if (currentGroupSize) {
        if (groupSize != currentGroupSize) {
            // have groupSize in db but isn't equal to input
            throw std::invalid_argument("group size input isn't equal to group size in database");
        }

        return currentGroupSize;
    }

    RecordGroupSize(groupSize);
    return groupSize;
}

size_t SigmaDatabase::GetAnonimityGroup(
    uint32_t propertyId, uint8_t denomination, uint32_t groupId, size_t count,
    std::function<void(elysium::SigmaPublicKey&)> insertF)
{
    auto firstKey = CreateMintKey(propertyId, denomination, groupId, 0);

    auto it = NewIterator();
    it->Seek(GetSlice(firstKey));

    uint32_t mintPropId, mintGroupId;
    uint16_t mintIdx;
    uint8_t mintDenom;

    size_t i = 0;
    for (; i < count && it->Valid(); i++, it->Next()) {
        if (!ParseMintKey(it->key(), mintPropId, mintDenom, mintGroupId, mintIdx) ||
            mintPropId != propertyId ||
            mintDenom != denomination ||
            mintGroupId != groupId) {
            break;
        }

        if (mintIdx != i) {
            throw std::runtime_error("GetAnonimityGroup() : coin index is out of order");
        }

        auto pub = ParseMint(it->value().ToString());

        if (!pub.commitment.isMember()) {
            throw std::runtime_error("GetAnonimityGroup() : coin is invalid");
        }
        insertF(pub);
    }

    return i;
}

uint32_t SigmaDatabase::GetLastGroupId(
    uint32_t propertyId,
    uint8_t denomination)
{
    auto key = CreateMintKey(propertyId, denomination, UINT32_MAX, UINT16_MAX);
    uint32_t groupId = 0;

    auto it = NewIterator();
    SafeSeekToPreviousKey(it.get(), GetSlice(key));

    if (it->Valid()) {
        auto key = it->key();

        uint32_t mintPropId, mintGroupId;
        uint16_t mintIdx;
        uint8_t mintDenom;
        if (ParseMintKey(key, mintPropId, mintDenom, mintGroupId, mintIdx)
            && propertyId == mintPropId
            && denomination == mintDenom) {
            groupId = mintGroupId;
        }
    }

    return groupId;
}

size_t SigmaDatabase::GetMintCount(
    uint32_t propertyId, uint8_t denomination, uint32_t groupId)
{
    auto key = CreateMintKey(propertyId, denomination, groupId, UINT16_MAX);
    size_t count = 0;

    auto it = NewIterator();
    SafeSeekToPreviousKey(it.get(), GetSlice(key));

    if (it->Valid()) {
        auto key = it->key();

        uint32_t mintPropId, mintGroupId;
        uint16_t mintIdx;
        uint8_t mintDenom;
        if (ParseMintKey(key, mintPropId, mintDenom, mintGroupId, mintIdx)
            && propertyId == mintPropId
            && denomination == mintDenom
            && groupId == mintGroupId) {
            count = mintIdx + 1;
        }
    }

    return count;
}

uint64_t SigmaDatabase::GetNextSequence()
{
    auto key = CreateSequenceKey(UINT64_MAX);
    auto it = NewIterator();

    uint64_t nextSequence = 0;
    SafeSeekToPreviousKey(it.get(), GetSlice(key));

    if (it->Valid() && it->key().size() > 0 && it->key().data()[0] == static_cast<char>(KeyType::Sequence)) {
        if (it->key().size() != SEQUENCE_KEY_SIZE) {
            throw std::runtime_error("key size is invalid");
        }
        auto lastKey = it->key();
        std::memcpy(&nextSequence, lastKey.data() + sizeof(KeyType), sizeof(nextSequence));
        elysium::swapByteOrder(nextSequence);
        nextSequence++;
    }

    return nextSequence;
}

elysium::SigmaPublicKey SigmaDatabase::GetMint(
    uint32_t propertyId, uint8_t denomination, uint32_t groupId, uint16_t index)
{
    auto key = CreateMintKey(propertyId, denomination, groupId, index);

    std::string val;
    auto status = pdb->Get(
        readoptions,
        GetSlice(key),
        &val
    );

    if (status.ok()) {
        return ParseMint(val);
    }

    throw std::runtime_error("not found sigma mint");
}

bool SigmaDatabase::HasSpendSerial(
    uint32_t propertyId, uint8_t denomination, secp_primitives::Scalar const &serial, uint256 &spendTx)
{
    auto serialData = SerializeSpendSerial(serial);
    auto keyData = CreateSpendSerialKey(propertyId, denomination, serialData);
    std::string data;
    auto status = pdb->Get(readoptions, GetSlice(keyData), &data);

    if (status.ok()) {
        spendTx = uint256(std::vector<unsigned char>(data.begin(), data.end()));
        return true;
    }

    if (status.IsNotFound()) {
        return false;
    }

    throw std::runtime_error("Error on serial checking");
}

void SigmaDatabase::AddEntry(const leveldb::Slice& key, const leveldb::Slice& value, int block)
{
    leveldb::WriteBatch batch;

    // Add entry writting to batch first.
    batch.Put(key, value);

    // Prepare history object.
    History history;

    if (IsMintKey(key)) {
        history.op = OpCode::StoreMint;
    } else if (IsSpendSerialKey(key)) {
        history.op = OpCode::StoreSpendSerial;
    } else {
        throw std::invalid_argument("The specified entry is not supported");
    }

    history.block = block;
    history.data.insert(history.data.end(), key.data(), key.data() + key.size());

    // Add history writing to batch.
    auto next = GetNextSequence();
    auto sequenceKey = CreateSequenceKey(next);

    CDataStream serialized(SER_DISK, CLIENT_VERSION);
    serialized << history;

    batch.Put(GetSlice(sequenceKey), GetSlice(serialized.vch));

    // Execute batch.
    auto status = pdb->Write(syncoptions, &batch);
    if (!status.ok()) {
        throw std::runtime_error("Failed to write database: " + status.ToString());
    }
}

std::unique_ptr<leveldb::Iterator> SigmaDatabase::NewIterator() const
{
    return std::unique_ptr<leveldb::Iterator>(CDBBase::NewIterator());
}

} // namespace elysium
