#ifndef ZCOIN_EXODUS_SIGMADB_H
#define ZCOIN_EXODUS_SIGMADB_H

#include "convert.h"
#include "persistence.h"
#include "sigma.h"
#include "log.h"

#include <univalue.h>

#include <boost/filesystem/path.hpp>

#include <string>
#include <vector>

enum class MintKeyType : uint8_t
{
    Mint = 0,
    Sequence = 1
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
    if (sizeof(t) > 1) {
        exodus::swapByteOrder(t);
    }
    it = std::copy_n(reinterpret_cast<uint8_t*>(&t), sizeof(t), it);
    return SerializeKey(it, r...);
}

template<typename ...T, size_t S = SizeOf<MintKeyType, T...>::Value>
static std::array<uint8_t, S> CreateKey(MintKeyType type, T ...args)
{
    std::array<uint8_t, S> key;
    auto it = key.begin();
    it = std::copy_n(reinterpret_cast<uint8_t*>(&type), sizeof(type), it);

    SerializeKey(it, args...);

    return key;
}

// array size represent size of key
// <1 byte of type><4 bytes of property Id><1 byte of denomination><4 bytes of group id><4 bytes of idx>
static std::array<uint8_t, sizeof(MintKeyType) + sizeof(uint8_t) + 3 * sizeof(uint32_t)> CreateMintKey(
    uint32_t propertyId,
    uint8_t denomination,
    uint32_t groupId,
    uint32_t idx)
{
    return CreateKey(MintKeyType::Mint, propertyId, denomination, groupId, idx);
}

// array size represent size of key
// <1 byte of type><8 bytes of sequence>
static std::array<uint8_t, sizeof(MintKeyType) + sizeof(uint64_t)> CreateSequenceKey(
    uint64_t sequence)
{
    return CreateKey(MintKeyType::Sequence, sequence);
}

template<size_t S>
static leveldb::Slice GetSlice(const std::array<uint8_t, S>& v)
{
    return leveldb::Slice(reinterpret_cast<const char*>(v.data()), v.size());
}

template<typename T>
static leveldb::Slice GetSlice(const std::vector<T>& v)
{
    return leveldb::Slice(reinterpret_cast<const char*>(v.data()), v.size() * sizeof(T));
}

static std::pair<exodus::SigmaPublicKey, int> ParseMint(const std::string& val)
{
    if (val.size() !=
        secp_primitives::GroupElement::serialize_size + sizeof(int)) {
            throw std::runtime_error("ParseMint() : invalid key size");
    }

    std::vector<unsigned char> buffer(val.size());
    std::copy_n(val.data(), val.size(), buffer.data());
    auto ptr = buffer.data();

    secp_primitives::GroupElement commitment;
    ptr = commitment.deserialize(reinterpret_cast<unsigned char*>(ptr));

    int height(0);

    std::memcpy(&height, ptr, sizeof(height));

    exodus::SigmaPublicKey pubKey;
    pubKey.SetCommitment(commitment);

    return {pubKey, height};
}

static bool ParseMintKey(
    const leveldb::Slice& key, uint32_t& propertyId, uint8_t& denomination, uint32_t& groupId, uint32_t& idx)
{
    if (key.size() == sizeof(MintKeyType) + sizeof(uint8_t) + 3 * sizeof(uint32_t)) {

        auto it = key.data() + sizeof(MintKeyType);
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

static void SafeSeekToKeyBefore(leveldb::Iterator *it, const leveldb::Slice& key)
{
    it->Seek(key);
    if (it->Valid() && it->key() != key) {
        it->Prev();
    } else {
        it->SeekToLast();
    }
}

/** LevelDB based storage for sigma mints, with
*/
class CMPMintList : public CDBBase
{
public:
    CMPMintList(const boost::filesystem::path& path, bool fWipe);
    ~CMPMintList();

    std::pair<uint32_t, uint32_t> RecordMint(uint32_t propertyId, uint32_t denomination, const exodus::SigmaPublicKey& pubKey, int height);

    template<class OutputIt>
    void GetAnonimityGroup(uint32_t propertyId, uint8_t denomination, uint32_t groupId, size_t count,
        OutputIt first)
    {
        auto firstKey = CreateMintKey(propertyId, denomination, groupId, 0);

        auto it = NewIterator();
        it->Seek(GetSlice(firstKey));

        uint32_t mintPropId, mintGroupId, mintIdx;
        uint8_t mintDenom;

        if (!it->Valid()) {
            throw std::runtime_error("GetAnonimityGroup() : coins in group is not enough");
        }

        for (size_t i = 0; i < count && it->Valid(); i++, it->Next()) {
            if (!ParseMintKey(it->key(), mintPropId, mintDenom, mintGroupId, mintIdx) ||
                mintPropId != propertyId ||
                mintDenom != denomination ||
                mintGroupId != groupId) {
                throw std::runtime_error("GetAnonimityGroup() : coins in group is not enough");
            }

            if (mintIdx != i) {
                throw std::runtime_error("GetAnonimityGroup() : coin index is out of order");
            }

            exodus::SigmaPublicKey pub;
            std::tie(pub, std::ignore) = ParseMint(it->value().ToString());

            if (!pub.GetCommitment().isMember()) {
                throw std::runtime_error("GetAnonimityGroup() : coin is invalid");
            }
            *first++ = std::move(pub);
        }

        delete it;
    }

    void DeleteAll(int startBlock);

private:
    void RecordMintKey(const leveldb::Slice& mintKey);

public:
    uint32_t GetLastGroupId(uint32_t propertyId, uint8_t denomination);
    size_t GetMintCount(uint32_t propertyId, uint8_t denomination, uint32_t groupId);
    uint64_t GetNextSequence();
    std::pair<exodus::SigmaPublicKey, int> GetMint(uint32_t propertyId, uint32_t denomination, uint32_t groupId, uint32_t index);
};

#endif // ZCOIN_EXODUS_SIGMADB_H