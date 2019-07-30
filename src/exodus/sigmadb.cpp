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

#define MAX_COINS_PER_GROUP 16384 /* Limit of sigma anonimity group which is 2 ^ 14 */

// Database structure
// Index height and commitment
// 0<prob_id><denom><group_id><idx>=<GroupElement><int>
// Index key sorted by block to optimized deletion
// 1<seq uint64>=key
// Index last group
// 2<propertyId><denomination>=<uint32_t>
// Index last coin index
// 3<propertyId><denomination><cointGroupId>=<uint32_t>
// Last index of key to key of mint
// 4=<uint64_t>
CMPMintList::CMPMintList(const boost::filesystem::path& path, bool fWipe)
{
    leveldb::Status status = Open(path, fWipe);
    PrintToLog("Loading mint meta-info database: %s\n", status.ToString());
}

CMPMintList::~CMPMintList()
{
    if (exodus_debug_persistence) PrintToLog("CMPMintList closed\n");
}

std::pair<uint32_t, uint32_t> CMPMintList::RecordMint(
    uint32_t propertyId,
    uint32_t denomination,
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
    uint32_t nextIdx = mints;

    if (mints >= MAX_COINS_PER_GROUP) {
        lastGroup++;
        nextIdx = 0;
    }

    auto rawMintKey = CreateMintKey(propertyId, denomination, lastGroup, nextIdx);
    leveldb::Slice mintKey = GetSlice(rawMintKey);

    auto commitment = pubKey.GetCommitment();

    std::vector<uint8_t> buffer(commitment.memoryRequired() + sizeof(height));
    auto ptr = buffer.data();
    ptr = commitment.serialize(ptr);
    std::memcpy(ptr, &height, sizeof(height));

    pdb->Put(writeoptions, mintKey, GetSlice(buffer));

    // Store key
    RecordMintKey(mintKey);

    return {lastGroup, nextIdx};
}

void CMPMintList::DeleteAll(int32_t startBlock)
{
    auto nextSequence = GetNextSequence();
    if (nextSequence == 0) {
        // No mint to delete
        return;
    }

    auto lastSequence = nextSequence - 1;

    auto rawLastSequenceKey = CreateSequenceKey(lastSequence);

    auto it = NewIterator();
    it->Seek(GetSlice(rawLastSequenceKey));

    std::vector<std::string> keyToDeletes;

    // Logic:
    // Start from last block
    // Store key to mint and key to key of mint which need to delete to vector
    // Then decrase mint count by 1
    // If mint count of the group reach to 0 then decrase group Id of denomination

    auto firstKey = CreateSequenceKey(0);

    while (it->Valid() && it->key().data()[0] == static_cast<char>(MintKeyType::Sequence)) {

        int32_t mintBlock;
        std::string rawMint;
        auto status = pdb->Get(readoptions, it->value(), &rawMint);
        if (!status.ok()) {
            throw std::runtime_error("DeleteAll() : fail to read mint from sequence");
        }

        std::tie(std::ignore, mintBlock) = ParseMint(rawMint);
        if (mintBlock >= startBlock) {
            keyToDeletes.emplace_back(it->key().ToString());
            keyToDeletes.emplace_back(it->value().ToString());
        } else {
            break;
        }

        it->Prev();
    }

    delete it;

    for (auto const & key : keyToDeletes) {
        auto status = pdb->Delete(writeoptions, key);
        if (!status.ok()) {
            throw std::runtime_error("DeleteAll() : fail to delete a key");
        }
    }
}

void CMPMintList::RecordMintKey(const leveldb::Slice& mintKey)
{
    auto nextSequence = GetNextSequence();

    auto key = CreateSequenceKey(nextSequence);
    auto status = pdb->Put(writeoptions, GetSlice(key), mintKey);

    if (!status.ok()) {
        LogPrintf("%s: Store last exodus mint sequence fail\n", __func__);
    }
}

uint32_t CMPMintList::GetLastGroupId(
    uint32_t propertyId,
    uint8_t denomination)
{
    auto key = CreateMintKey(propertyId, denomination, INT32_MAX, INT32_MAX);
    uint32_t groupId = 0;

    auto it = NewIterator();
    SafeSeekToKeyBefore(it, GetSlice(key));

    if (it->Valid()) {
        auto key = it->key();

        uint32_t mintPropId, mintGroupId, mintIdx;
        uint8_t mintDenom;
        if (ParseMintKey(key, mintPropId, mintDenom, mintGroupId, mintIdx)
            && propertyId == mintPropId
            && denomination == mintDenom) {
            groupId = mintGroupId;
        }
    }

    delete it;
    return groupId;
}

size_t CMPMintList::GetMintCount(
    uint32_t propertyId, uint8_t denomination, uint32_t groupId)
{
    auto key = CreateMintKey(propertyId, denomination, groupId, INT32_MAX);
    size_t count = 0;

    auto it = NewIterator();
    SafeSeekToKeyBefore(it, GetSlice(key));

    if (it->Valid()) {
        auto key = it->key();

        uint32_t mintPropId, mintGroupId, mintIdx;
        uint8_t mintDenom;
        if (ParseMintKey(key, mintPropId, mintDenom, mintGroupId, mintIdx)
            && propertyId == mintPropId
            && denomination == mintDenom
            && groupId == mintGroupId) {
            count = mintIdx + 1;
        }
    }

    delete it;
    return count;
}

uint64_t CMPMintList::GetNextSequence()
{
    auto key = CreateSequenceKey(UINT64_MAX);
    auto it = NewIterator();

    uint64_t nextSequence = 0;
    SafeSeekToKeyBefore(it, GetSlice(key));

    if (it->Valid() && it->key().size() == sizeof(MintKeyType) + sizeof(nextSequence)) {
        auto lastKey = it->key();
        std::memcpy(&nextSequence, lastKey.data() + sizeof(MintKeyType), sizeof(nextSequence));
        exodus::swapByteOrder(nextSequence);
        nextSequence++;
    }

    delete it;
    return nextSequence;
}

std::pair<exodus::SigmaPublicKey, int32_t> CMPMintList::GetMint(
    uint32_t propertyId, uint32_t denomination, uint32_t groupId, uint32_t index)
{
    auto key = CreateMintKey(propertyId, denomination, groupId, index);

    std::string val;
    auto status = pdb->Get(
        readoptions,
        leveldb::Slice(reinterpret_cast<const char*>(key.data()), key.size()),
        &val
    );

    if (status.ok()) {
        return ParseMint(val);
    }

    throw std::runtime_error("not found sigma mint");
}
