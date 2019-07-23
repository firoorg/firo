#include "exodus/exodus.h"

#include "exodus/encoding.h"
#include "exodus/errors.h"
#include "exodus/log.h"
#include "exodus/sigmadb.h"
#include "exodus/sp.h"
#include "exodus/tally.h"
#include "exodus/tx.h"

#include "chainparams.h"
#include "init.h"
#include "main.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "secp256k1/include/GroupElement.h"
#include "sync.h"
#include "tinyformat.h"
#include "uint256.h"
#include "ui_interface.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "zerocoin_v3.h"
#ifdef ENABLE_WALLET
#include "script/ismine.h"
#include "wallet/wallet.h"
#endif

#include <univalue.h>

#include <boost/endian/conversion.hpp>
#include <boost/filesystem.hpp>

#include "leveldb/db.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include <string>
#include <vector>

enum class MintKeyType : uint8_t
{
    Mint = 0,
    IndirectMint = 1,
    LastMintSequence = 2,
    LastGroupID = 3,
    MintCount = 4
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
inline It SerializeKey(It it)
{
    return it;
}

template<typename T, typename ...R, typename It>
inline It SerializeKey(It it, T t, R ...r)
{
    t = boost::endian::native_to_big(t);
    std::copy_n((unsigned char*)&t, sizeof(t), it);
    return SerializeKey(it + sizeof(t), r...);
}

template<typename ...T, size_t S = SizeOf<MintKeyType, T...>::Value>
inline std::array<uint8_t, S> CreateKey(MintKeyType type, T ...args)
{
    std::array<uint8_t, S> key;
    auto it = key.begin();
    std::copy_n(reinterpret_cast<unsigned char*>(&type), sizeof(type), it);

    SerializeKey(it + sizeof(type), args...);

    return key;
}

std::array<uint8_t, sizeof(MintKeyType) + 4 * sizeof(uint32_t)> CreateMintKey(
    uint32_t propertyID,
    uint32_t denomination,
    uint32_t groupID,
    uint32_t idx)
{
    return CreateKey(MintKeyType::Mint, propertyID, denomination, groupID, idx);
}

std::array<uint8_t, sizeof(MintKeyType) + sizeof(uint64_t)> CreateIndirectMintKey(
    uint64_t sequence)
{
    return CreateKey(MintKeyType::IndirectMint, sequence);
}

std::array<uint8_t, sizeof(MintKeyType) + 3 * sizeof(uint32_t)>
CreateMintCountKey(uint32_t propertyID, uint32_t denomination, uint32_t groupID)
{
    return CreateKey(MintKeyType::MintCount, propertyID, denomination, groupID);
}

std::array<uint8_t, sizeof(MintKeyType) + 2 * sizeof(uint32_t)>
CreateLastGroupIDKey(uint32_t propertyID, uint32_t denomination)
{
    return CreateKey(MintKeyType::LastGroupID, propertyID, denomination);
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
            return {exodus::SigmaPublicKey(), 0};
    }

    std::vector<unsigned char> buffer(val.size());
    std::copy_n(val.data(), val.size(), buffer.data());
    auto ptr = buffer.data();

    secp_primitives::GroupElement commitment;
    int nBlock(0);

    ptr = commitment.deserialize(reinterpret_cast<unsigned char*>(ptr));

    std::memcpy(&nBlock, ptr, sizeof(nBlock));

    exodus::SigmaPublicKey pubKey;
    pubKey.SetCommitment(commitment);

    return {pubKey, nBlock};
}

static bool ParseMintKey(
    const leveldb::Slice& key, uint32_t& propertyID, uint32_t& denomination, uint32_t& groupID, uint32_t& idx)
{
    if (key.size() == sizeof(MintKeyType) + 4 * sizeof(uint32_t)) {

        std::array<uint32_t, 4> out;
        std::memcpy(&out[0], key.data() + sizeof(MintKeyType), 4 * sizeof(uint32_t));

        propertyID = out[0];
        denomination = out[1];
        groupID = out[2];
        idx = out[3];

        propertyID = boost::endian::big_to_native(propertyID);
        denomination = boost::endian::big_to_native(denomination);
        groupID = boost::endian::big_to_native(groupID);
        idx = boost::endian::big_to_native(idx);

        return true;
    }
    return false;
}

std::pair<uint32_t, uint32_t> CMPMintList::RecordMint(
    uint32_t propertyID,
    uint32_t denomination,
    const exodus::SigmaPublicKey& pubKey,
    int nBlock)
{
    // Logic:
    // Get next group id and index for new pubkey by get last group id and amount of coin in group
    // If the count is equal to limit then move to new group
    // Record mint by key `0<prob_id><denom><group_id><idx>` with value `<GroupElement><int>`
    // Record the key `0<prob_id><denom><group_id><idx>` as value of `1<sequence>`
    // Record Last group ID
    // Record Mint count for group

    auto lastGroup = GetLastGroupID(propertyID, denomination);
    auto mints = GetMintCount(propertyID, denomination, lastGroup);
    uint32_t nextIDx = mints;

    if (mints >= MaxCoinsPerGroup) {
        lastGroup++;
        nextIDx = 0;
    }

    auto rawMintKey = CreateMintKey(propertyID, denomination, lastGroup, nextIDx);
    leveldb::Slice mintKey = GetSlice(rawMintKey);

    auto commitment = pubKey.GetCommitment();

    std::vector<uint8_t> buffer(commitment.memoryRequired() + sizeof(int));
    auto ptr = buffer.data();
    ptr = commitment.serialize(ptr);
    std::memcpy(ptr, &nBlock, sizeof(nBlock));

    pdb->Put(writeoptions, mintKey, GetSlice(buffer));

    // Store key
    RecordMintKeyIndex(mintKey);

    // Store last group id
    RecordLastGroupID(propertyID, denomination, lastGroup);

    // Store mint count
    RecordMintCount(propertyID, denomination, lastGroup, nextIDx + 1);
}

std::vector<exodus::SigmaPublicKey> CMPMintList::GetAnonimityGroup(
    uint32_t propertyID, uint32_t denomination, uint32_t groupID, uint32_t idx)
{
    std::vector<exodus::SigmaPublicKey> pubKeys;

    auto firstKey = CreateMintKey(propertyID, denomination, groupID, 0);

    auto it = NewIterator();
    it->Seek(GetSlice(firstKey));

    uint32_t mintPropID, mintDenom, mintGroupID, mintIDx;

    for (uint32_t i = 0; i < idx && it->Valid(); i++, it->Next()) {
        if (!ParseMintKey(it->key(), mintPropID, mintDenom, mintGroupID, mintIDx) ||
            mintPropID != propertyID ||
            mintDenom != denomination ||
            mintGroupID != groupID) {
            LogPrintf("%s() : read invalid key", __func__);
            break;
        }

        if (mintIDx > idx) {
            LogPrintf("%s() : read exceed query index", __func__);
            break;
        }

        exodus::SigmaPublicKey pub;
        std::tie(pub, std::ignore) = ParseMint(it->value().ToString());

        if (pub.GetCommitment().isMember()) {
            pubKeys.push_back(pub);
        }
    }

    return pubKeys;
}

void CMPMintList::DeleteAll(int nBlock)
{
    auto nextSequence = GetNextSequence();
    if (nextSequence <= 0) {
        // No mint to delete
        return;
    }

    auto lastSequence = nextSequence - 1;

    auto rawLastSequenceKey = CreateIndirectMintKey(lastSequence);

    auto it = NewIterator();
    it->Seek(GetSlice(rawLastSequenceKey));

    std::vector<std::string> keyToDeletes;
    uint64_t lastDeleted = nextSequence;

    // Logic:
    // Start from last block
    // Store key to mint and key to key of mint which need to delete to vector
    // Then decrase mint count by 1
    // If mint count of the group reach to 0 then decrase group ID of denomination

    while (it->Valid() && lastDeleted > 0) {

        int mintBlock;
        std::string rawMint;
        auto status = pdb->Get(readoptions, it->value(), &rawMint);
        if (!status.ok()) {
            LogPrintf("%s() : read mint from sequence fail\n", __func__);
            break;
        }

        std::tie(std::ignore, mintBlock) = ParseMint(rawMint);
        if (mintBlock >= nBlock) {
            keyToDeletes.emplace_back(it->key().ToString());
            keyToDeletes.emplace_back(it->value().ToString());

            uint32_t propertyID, denomination, groupID, index;
            if (!ParseMintKey(it->value(), propertyID, denomination, groupID, index))
                break;

            auto mintCount = GetMintCount(propertyID, denomination, groupID);
            if (mintCount > 0) {
                mintCount--; // decrease one
                RecordMintCount(propertyID, denomination, groupID, mintCount);
            }

            if (mintCount == 0) {
                auto lastGroupID = GetLastGroupID(propertyID, denomination);
                if (lastGroupID > 0) {
                    RecordLastGroupID(propertyID, denomination, lastGroupID - 1);
                }
            }
        } else {
            break;
        }

        lastDeleted--;
        it->Prev();
    }

    for (auto const & key : keyToDeletes) {
        auto status = pdb->Delete(writeoptions, key);
        if (!status.ok()) {
            LogPrintf("%s() : Fail to delete a key\n", __func__);
        }
    }

    // Update sequence if also delete mint at 0 then delete the sequence's counter
    if (lastDeleted > 0) {
        RecordLastSequence(lastDeleted - 1);
    } else {
        auto key = CreateKey(MintKeyType::LastMintSequence);
        pdb->Delete(writeoptions, GetSlice(key));
    }
}

void CMPMintList::RecordLastGroupID(
    uint32_t propertyID, uint32_t denomination, uint32_t groupID)
{
    auto key = CreateLastGroupIDKey(propertyID, denomination);

    auto status = pdb->Put(
        writeoptions,
        GetSlice(key),
        leveldb::Slice(reinterpret_cast<const char*>(&groupID), sizeof(groupID))
    );

    if (!status.ok()) {
        LogPrintf("%s: Store last group id of exodus mint fail\n", __func__);
    }
}

void CMPMintList::RecordMintCount(
    uint32_t propertyID, uint32_t denomination, uint32_t groupID, size_t mintCount)
{
    auto key = CreateMintCountKey(propertyID, denomination, groupID);

    auto status = pdb->Put(
        writeoptions,
        GetSlice(key),
        leveldb::Slice(reinterpret_cast<const char*>(&mintCount), sizeof(mintCount))
    );

    if (!status.ok()) {
        LogPrintf("%s: Store exodus mint count fail\n", __func__);
    }
}

void CMPMintList::RecordMintKeyIndex(leveldb::Slice mintKey)
{
    auto nextSequence = GetNextSequence();

    auto key = CreateIndirectMintKey(nextSequence);
    auto status = pdb->Put(writeoptions, GetSlice(key), mintKey);

    if (!status.ok()) {
        LogPrintf("%s: Store last exodus mint sequence fail\n", __func__);
    }

    RecordLastSequence(nextSequence);
}

void CMPMintList::RecordLastSequence(uint64_t lastSequence)
{
    auto key = CreateKey(MintKeyType::LastMintSequence);

    auto status = pdb->Put(
        writeoptions,
        GetSlice(key),
        leveldb::Slice(reinterpret_cast<const char*>(&lastSequence), sizeof(lastSequence))
    );

    if (!status.ok()) {
        LogPrintf("%s: Store last exodus mint sequence fail\n", __func__);
    }
}

uint32_t CMPMintList::GetLastGroupID(
    uint32_t propertyID,
    uint32_t denomination)
{
    auto key = CreateLastGroupIDKey(propertyID, denomination);

    std::string val;
    leveldb::Status status = pdb->Get(readoptions, GetSlice(key), &val);

    if (status.ok()) {

        uint32_t id;

        if (val.size() == sizeof(id)) {

            std::copy_n(val.data(), val.size(),reinterpret_cast<char*>(&id));
            return id;
        }
    }

    return 0;
}

size_t CMPMintList::GetMintCount(
    uint32_t propertyID, uint32_t denomination, uint32_t groupID)
{
    auto key = CreateMintCountKey(propertyID, denomination, groupID);

    std::string count;
    leveldb::Status status = pdb->Get(readoptions, GetSlice(key), &count);

    if (status.ok()) {

        size_t mintCount;

        if (count.size() == sizeof(mintCount)) {

            std::copy_n(count.data(), count.size(), reinterpret_cast<char*>(&mintCount));
            return mintCount;
        }
    }

    return 0;
}

std::string CMPMintList::GetLastMintKeyIndex()
{
    auto nextSequnce = GetNextSequence();

    if (nextSequnce > 0) {

        uint64_t lastSequence = nextSequnce - 1;
        auto key = CreateIndirectMintKey(lastSequence);

        std::string val;

        auto status = pdb->Get(readoptions, GetSlice(key), &val);
        if (status.ok()) {
            return val;
        }
    }

    return std::string("");
}

uint64_t CMPMintList::GetNextSequence()
{
    auto key = CreateKey(MintKeyType::LastMintSequence);

    std::string val;
    auto status = pdb->Get(
        readoptions,
        leveldb::Slice(reinterpret_cast<char*>(key.data()), key.size()),
        &val);

    if (status.ok()) {

        uint64_t sequence;
        if (sizeof(sequence) == val.size()) {
            std::copy_n(val.data(), val.size(),
            reinterpret_cast<char*>(&sequence));

            return sequence + 1;
        }
    }

    return 0;
}

std::pair<exodus::SigmaPublicKey, int> CMPMintList::GetMint(
    uint32_t propertyID, uint32_t denomination, uint32_t groupID, uint32_t index)
{
    auto key = CreateMintKey(propertyID, denomination, groupID, index);

    std::string val;
    auto status = pdb->Get(
        readoptions,
        leveldb::Slice(reinterpret_cast<const char*>(key.data()), key.size()),
        &val
    );

    if (status.ok()) {
        return ParseMint(val);
    }

    return {exodus::SigmaPublicKey(), 0};
}
