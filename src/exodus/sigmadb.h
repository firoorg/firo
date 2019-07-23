#ifndef SIGMA_EXODUS_DB_H
#define SIGMA_EXODUS_DB_H

#include "exodus/persistence.h"
#include "exodus/sigma.h"
#include "exodus/log.h"

#include <univalue.h>

#include <boost/filesystem/path.hpp>

#include <string>
#include <vector>

/** LevelDB based storage for sigma mints, with
*/
class CMPMintList : public CDBBase
{
public:
    CMPMintList(const boost::filesystem::path& path, bool fWipe)
    {
        leveldb::Status status = Open(path, fWipe);
        PrintToLog("Loading mint meta-info database: %s\n", status.ToString());
    }

    virtual ~CMPMintList()
    {
        if (exodus_debug_persistence) PrintToLog("CMPMintList closed\n");
    }

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
    std::pair<uint32_t, uint32_t> RecordMint(uint32_t propertyId, uint32_t denomination, const exodus::SigmaPublicKey& pubKey, int nBlock);
    std::vector<exodus::SigmaPublicKey> GetAnonimityGroup(uint32_t propertyId, uint32_t denomination, uint32_t groupId, uint32_t idx);
    void DeleteAll(int nBlock);

    void RecordLastGroupID(uint32_t propertyId, uint32_t denomination, uint32_t groupId);
    void RecordMintCount(uint32_t propertyId, uint32_t denomination, uint32_t groupId, size_t mintCount);
    void RecordMintKeyIndex(const leveldb::Slice& mintKey);
    void RecordLastSequence(uint64_t lastSequence);

    uint32_t GetLastGroupID(uint32_t propertyId, uint32_t denomination);
    size_t GetMintCount(uint32_t propertyId, uint32_t denomination, uint32_t groupId);
    std::string GetLastMintKeyIndex();
    uint64_t GetNextSequence();
    std::pair<exodus::SigmaPublicKey, int> GetMint(uint32_t propertyId, uint32_t denomination, uint32_t groupID, uint32_t index);

private:
    const uint32_t MaxCoinsPerGroup = 15000;
};

#endif // SIGMA_EXODUS_DB_H