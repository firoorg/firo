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

/** LevelDB based storage for sigma mints, with
*/
class CMPMintList : public CDBBase
{
public:
    CMPMintList(const boost::filesystem::path& path, bool fWipe);
    ~CMPMintList();

    std::pair<uint32_t, uint32_t> RecordMint(uint32_t propertyId, uint32_t denomination, const exodus::SigmaPublicKey& pubKey, int32_t height);

    template<class Container>
    void GetAnonimityGroup(uint32_t propertyId, uint8_t denomination, uint32_t groupId, size_t count, std::back_insert_iterator<Container> first)
    {
        GetAnonimityGroup(propertyId, denomination, groupId, count, [&](const exodus::SigmaPublicKey& pub) mutable {
            *first++ = std::move(pub);
        });
    }

    void DeleteAll(int32_t startBlock);

private:
    void RecordMintKey(const leveldb::Slice& mintKey);
    void GetAnonimityGroup(uint32_t propertyId, uint8_t denomination, uint32_t groupId, size_t count,
        std::function<void(const exodus::SigmaPublicKey&)> first);

public:
    uint32_t GetLastGroupId(uint32_t propertyId, uint8_t denomination);
    size_t GetMintCount(uint32_t propertyId, uint8_t denomination, uint32_t groupId);
    uint64_t GetNextSequence();
    std::pair<exodus::SigmaPublicKey, int32_t> GetMint(uint32_t propertyId, uint32_t denomination, uint32_t groupId, uint32_t index);
};

#endif // ZCOIN_EXODUS_SIGMADB_H