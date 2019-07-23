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
    // 0<prob_id><denom><group_id><idx>=<commitment><height>
    // Index key sorted by block to optimal deletion
    // 1<seq uint64>=key
    // Index last group
    // 2<propertyId><denomination>=key
    // Index last coin index
    // 3<propertyId><denomination><cointGroupId>=key
    std::pair<uint32_t, uint32_t> RecordMint(uint32_t propertyId, uint32_t denomination, const exodus::SigmaPublicKey& pubKey, int nBlock);
    std::vector<exodus::SigmaPublicKey> GetAnonimityGroup(uint32_t propertyId, uint32_t denomination, uint32_t groupId, uint32_t idx);
    void DeleteAll(int nBlock);

    // Tested
    void RecordLastGroupID(uint32_t propertyId, uint32_t denomination, uint32_t groupId);
    // Tested
    void RecordMintCount(uint32_t propertyId, uint32_t denomination, uint32_t groupId, size_t mintCount);
    // Tested
    void RecordMintKeyIndex(leveldb::Slice mintKey);
    // Tested
    void RecordLastSequence(uint64_t lastSequence);

    // Tested
    uint32_t GetLastGroupID(uint32_t propertyId, uint32_t denomination);
    // Tested
    size_t GetMintCount(uint32_t propertyId, uint32_t denomination, uint32_t groupId);
    // Tested
    std::string GetLastMintKeyIndex();
    // Tested
    uint64_t GetNextSequence();
    std::pair<exodus::SigmaPublicKey, int> GetMint(uint32_t propertyId, uint32_t denomination, uint32_t groupID, uint32_t index);

    uint32_t MaxCoinsPerGroup = 15000;
};

#endif // SIGMA_EXODUS_DB_H