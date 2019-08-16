#include "exodus.h"
#include "encoding.h"
#include "errors.h"
#include "log.h"
#include "sigmadb.h"
#include "sp.h"
#include "tally.h"
#include "tx.h"

#include <GroupElement.h>
#include "../tinyformat.h"

#include <boost/filesystem.hpp>

#include <leveldb/db.h>

#include <string>
#include <vector>

enum class KeyType : uint8_t
{
    Mint = 0,
    Sequence = 1,
    GroupSize = 2,
    Spend = 3
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

template<typename It, typename T, typename ...R>
It SerializeKey(It it, T t, R ...r)
{
    if (std::is_arithmetic<T>::value && sizeof(t) > 1) {
        exodus::swapByteOrder(t);
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

#define SERIAL_SIZE 32
typedef std::array<uint8_t, SERIAL_SIZE> SERIAL;

// array size represent size of key
// <1 byte of type><4 bytes of property Id><1 byte of denomination><32 bytes of serials>
#define SPEND_KEY_SIZE sizeof(KeyType) + sizeof(uint32_t) + sizeof(uint8_t) + SERIAL_SIZE
std::array<uint8_t, SPEND_KEY_SIZE> CreateSpendKey(
    uint32_t propertyId,
    uint8_t denomination,
    SERIAL const &serial)
{
    return CreateKey(KeyType::Spend, propertyId, denomination, serial);
}

template<size_t S>
leveldb::Slice GetSlice(const std::array<uint8_t, S>& v)
{
    return leveldb::Slice(reinterpret_cast<const char*>(v.data()), v.size());
}

template<typename T>
leveldb::Slice GetSlice(const std::vector<T>& v)
{
    return leveldb::Slice(reinterpret_cast<const char*>(v.data()), v.size() * sizeof(T));
}

std::pair<exodus::SigmaPublicKey, int32_t> ParseMint(const std::string& val)
{
    if (val.size() !=
        secp_primitives::GroupElement::serialize_size + sizeof(int32_t)) {
            throw std::runtime_error("ParseMint() : invalid key size");
    }

    auto ptr = reinterpret_cast<const unsigned char*>(val.data());

    secp_primitives::GroupElement commitment;
    ptr = commitment.deserialize(ptr);

    int32_t height(0);

    std::memcpy(&height, ptr, sizeof(height));

    exodus::SigmaPublicKey pubKey;
    pubKey.SetCommitment(commitment);

    return {pubKey, height};
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

        exodus::swapByteOrder(propertyId);
        exodus::swapByteOrder(groupId);
        exodus::swapByteOrder(idx);

        return true;
    }
    return false;
}

SERIAL GetSerial(exodus::SigmaProof const &proof)
{
    SERIAL s;
    if (proof.GetSerial().memoryRequired() != SERIAL_SIZE) {
        throw std::invalid_argument("serial size is invalid");
    }

    proof.GetSerial().serialize(s.data());
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

namespace exodus {

// Database structure
// Index height and commitment
// 0<prob_id><denom><group_id><idx>=<GroupElement><int>
// Sequence of mint sorted following blockchain
// 1<seq uint64>=key
CMPMintList::CMPMintList(const boost::filesystem::path& path, bool fWipe, uint16_t groupSize)
{
    leveldb::Status status = Open(path, fWipe);
    PrintToLog("Loading mint meta-info database: %s\n", status.ToString());

    this->groupSize = InitGroupSize(groupSize);
}

CMPMintList::~CMPMintList()
{
    if (exodus_debug_persistence) PrintToLog("CMPMintList closed\n");
}

std::pair<uint32_t, uint16_t> CMPMintList::RecordMint(
    uint32_t propertyId,
    uint8_t denomination,
    const exodus::SigmaPublicKey& pubKey,
    int32_t height)
{
    // Logic:
    // Get next group id and index for new pubkey by get last group id and amount of coin in group
    // If the count is equal to limit then move to new group
    // Record mint by key `0<prob_id><denom><group_id><idx>` with value `<GroupElement><int32_t>`
    // Record the key `0<prob_id><denom><group_id><idx>` as value of `1<sequence>`
    // Record Last group Id
    // Record Mint count for group

    auto lastGroup = GetLastGroupId(propertyId, denomination);
    auto mints = GetMintCount(propertyId, denomination, lastGroup);

    if (mints > groupSize) {
        throw std::runtime_error("mints count is exceed group limit");
    }
    uint16_t nextIdx = mints;

    if (mints == groupSize) {
        lastGroup++;
        nextIdx = 0;
    }

    auto keyData = CreateMintKey(propertyId, denomination, lastGroup, nextIdx);
    leveldb::Slice key = GetSlice(keyData);

    auto const &commitment = pubKey.GetCommitment();

    std::vector<uint8_t> buffer(commitment.memoryRequired() + sizeof(height));
    auto ptr = buffer.data();
    ptr = commitment.serialize(ptr);
    std::memcpy(ptr, &height, sizeof(height));

    pdb->Put(writeoptions, key, GetSlice(buffer));

    // Store key
    RecordKey(key);

    return {lastGroup, nextIdx};
}

void CMPMintList::RecordSerial(
    uint32_t propertyId, uint8_t denomination, exodus::SigmaProof const &proof, int32_t height)
{
    auto serial = GetSerial(proof);
    auto keyData = CreateSpendKey(propertyId, denomination, serial);
    RecordKey(GetSlice(keyData));

    std::array<uint8_t, sizeof(height)> buffer;
    std::copy_n(reinterpret_cast<char*>(&height), sizeof(height), buffer.data());

    auto status = pdb->Put(writeoptions, GetSlice(keyData), GetSlice(buffer));
    if (!status.ok()) {
        throw std::runtime_error("record serial fail");
    }
}

void CMPMintList::DeleteAll(int32_t startBlock)
{
    auto nextSequence = GetNextSequence();
    if (nextSequence == 0) {
        // No mint to delete
        return;
    }

    auto lastSequence = nextSequence - 1;

    auto sequenceKey = CreateSequenceKey(lastSequence);

    auto it = NewIterator();
    it->Seek(GetSlice(sequenceKey));

    std::vector<std::string> keyToDeletes;

    // Logic:
    // Start from last block
    // Store key to mint and key to key of mint which need to delete to vector
    // Then decrase mint count by 1
    // If mint count of the group reach to 0 then decrase group Id of denomination

    while (it->Valid() &&
        (it->key().size() > 0 && it->key().data()[0] == static_cast<char>(KeyType::Sequence))) {

        int32_t block;
        std::string data;
        auto status = pdb->Get(readoptions, it->value(), &data);
        if (!status.ok()) {
            throw std::runtime_error("DeleteAll() : fail to read mint from sequence");
        }

        if (it->value().empty()) {
            throw std::runtime_error("DeleteAll() : key in sequence is empty");
        }

        if (it->value().data()[0] == static_cast<char>(KeyType::Mint)) {
            std::tie(std::ignore, block) = ParseMint(data);
        } else if (it->value().data()[0] == static_cast<char>(KeyType::Spend)) {
            if (data.size() != sizeof(block)) {
                throw std::runtime_error("DeleteAll() : value of spend is invalid");
            }
            std::copy_n(data.data(), data.size(), reinterpret_cast<char*>(&block));
        } else {
            throw std::runtime_error("DeleteAll() : format of a key in sequence is invalid");
        }

        if (block >= startBlock) {
            keyToDeletes.emplace_back(it->key().ToString());
            keyToDeletes.emplace_back(it->value().ToString());
        } else {
            break;
        }

        it->Prev();
    }

    for (auto const & key : keyToDeletes) {
        auto status = pdb->Delete(writeoptions, key);
        if (!status.ok()) {
            throw std::runtime_error("DeleteAll() : fail to delete a key");
        }
    }
}

void CMPMintList::RecordKey(const leveldb::Slice& keyToStore)
{
    auto nextSequence = GetNextSequence();

    auto key = CreateSequenceKey(nextSequence);
    auto status = pdb->Put(writeoptions, GetSlice(key), keyToStore);

    if (!status.ok()) {
        LogPrintf("%s: Store last exodus mint sequence fail\n", __func__);
    }
}

void CMPMintList::RecordGroupSize(uint16_t groupSize)
{
    auto key = CreateGroupSizeKey();

    auto status = pdb->Put(writeoptions, GetSlice(key),
        leveldb::Slice(reinterpret_cast<char*>(&groupSize), sizeof(groupSize)));

    if (!status.ok()) {
        throw std::runtime_error("store sigma mint group size fail");
    }
}

uint16_t CMPMintList::GetGroupSize()
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

uint16_t CMPMintList::InitGroupSize(uint16_t groupSize)
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

size_t CMPMintList::GetAnonimityGroup(
    uint32_t propertyId, uint8_t denomination, uint32_t groupId, size_t count,
    std::function<void(exodus::SigmaPublicKey&)> insertF)
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

        exodus::SigmaPublicKey pub;
        std::tie(pub, std::ignore) = ParseMint(it->value().ToString());

        if (!pub.GetCommitment().isMember()) {
            throw std::runtime_error("GetAnonimityGroup() : coin is invalid");
        }
        insertF(pub);
    }

    return i;
}

uint32_t CMPMintList::GetLastGroupId(
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

size_t CMPMintList::GetMintCount(
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

uint64_t CMPMintList::GetNextSequence()
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
        exodus::swapByteOrder(nextSequence);
        nextSequence++;
    }

    return nextSequence;
}

std::pair<exodus::SigmaPublicKey, int32_t> CMPMintList::GetMint(
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

bool CMPMintList::HasSerial(
    uint32_t propertyId, uint8_t denomination, exodus::SigmaProof const &proof)
{
    auto serial = GetSerial(proof);
    auto keyData = CreateSpendKey(propertyId, denomination, serial);
    std::string data;
    auto status = pdb->Get(readoptions, GetSlice(keyData), &data);

    if (status.ok()) {
        return true;
    }

    if (status.IsNotFound()) {
        return false;
    }

    throw std::runtime_error("Error on serial checking");
}

std::unique_ptr<leveldb::Iterator> CMPMintList::NewIterator() const
{
    return std::unique_ptr<leveldb::Iterator>(CDBBase::NewIterator());
}

};
