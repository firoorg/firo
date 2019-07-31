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

template<typename T, typename = void>
struct is_iterator
{
   static constexpr bool value = false;
};

template<typename T>
struct is_iterator<T, typename std::enable_if<!std::is_same<typename std::iterator_traits<T>::iterator_category, void>::value>::type>
{
   static constexpr bool value = true;
};

/** LevelDB based storage for sigma mints, with
*/
class CMPMintList : public CDBBase
{
    size_t GetAnonimityGroup(uint32_t propertyId, uint8_t denomination, uint32_t groupId, size_t count,
        std::function<void(exodus::SigmaPublicKey&)>);

public:
    CMPMintList(const boost::filesystem::path& path, bool fWipe);
    ~CMPMintList();

    std::pair<uint32_t, uint16_t> RecordMint(uint32_t propertyId, uint8_t denomination, const exodus::SigmaPublicKey& pubKey, int32_t height);

    template<
        class OutputIt,
        typename std::enable_if<is_iterator<OutputIt>::value, void>::type* = nullptr
    > OutputIt GetAnonimityGroup(uint32_t propertyId, uint8_t denomination, uint32_t groupId, size_t count, OutputIt firstIt)
    {
        GetAnonimityGroup(propertyId, denomination, groupId, count, [&](exodus::SigmaPublicKey& pub) mutable {
            *firstIt++ = std::move(pub);
        });

        return firstIt;
    }

    void DeleteAll(int32_t startBlock);

private:
    void RecordMintKey(const leveldb::Slice& mintKey);

public:
    uint32_t GetLastGroupId(uint32_t propertyId, uint8_t denomination);
    size_t GetMintCount(uint32_t propertyId, uint8_t denomination, uint32_t groupId);
    uint64_t GetNextSequence();
    std::pair<exodus::SigmaPublicKey, int32_t> GetMint(uint32_t propertyId, uint32_t denomination, uint32_t groupId, uint16_t index);
};

#endif // ZCOIN_EXODUS_SIGMADB_H