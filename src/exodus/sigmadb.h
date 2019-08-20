#ifndef ZCOIN_EXODUS_SIGMADB_H
#define ZCOIN_EXODUS_SIGMADB_H

#include "convert.h"
#include "persistence.h"
#include "property.h"
#include "sigma.h"

#include <univalue.h>

#include <boost/filesystem/path.hpp>
#include <boost/signals2/signal.hpp>

#include <cinttypes>
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

namespace exodus {

typedef std::uint32_t MintGroupId;
typedef std::uint16_t MintGroupIndex;

class CMPMintList : public CDBBase
{
public:
    static constexpr uint16_t MAX_GROUP_SIZE = 16384; // Limit of sigma anonimity group, which is 2 ^ 14.

public:
    CMPMintList(const boost::filesystem::path& path, bool fWipe, uint16_t groupSize = 0);
    virtual ~CMPMintList();

    std::pair<MintGroupId, MintGroupIndex> RecordMint(
        PropertyId propertyId,
        DenominationId denomination,
        const SigmaPublicKey& pubKey,
        int height);

    template<
        class OutputIt,
        typename std::enable_if<is_iterator<OutputIt>::value, void>::type* = nullptr
    > OutputIt GetAnonimityGroup(uint32_t propertyId, uint8_t denomination, uint32_t groupId, size_t count, OutputIt firstIt)
    {
        GetAnonimityGroup(propertyId, denomination, groupId, count, [&firstIt](exodus::SigmaPublicKey& pub) mutable {
            *firstIt++ = std::move(pub);
        });

        return firstIt;
    }
    size_t GetAnonimityGroup(uint32_t propertyId, uint8_t denomination, uint32_t groupId, size_t count,
        std::function<void(exodus::SigmaPublicKey&)>);

    void DeleteAll(int startBlock);

    uint32_t GetLastGroupId(uint32_t propertyId, uint8_t denomination);
    size_t GetMintCount(uint32_t propertyId, uint8_t denomination, uint32_t groupId);
    uint64_t GetNextSequence();
    std::pair<exodus::SigmaPublicKey, int32_t> GetMint(uint32_t propertyId, uint8_t denomination, uint32_t groupId, uint16_t index);

    uint16_t groupSize;

public:
    boost::signals2::signal<void(PropertyId, DenominationId, MintGroupId, MintGroupIndex, const SigmaPublicKey&, int)> MintAdded;
    boost::signals2::signal<void(PropertyId, DenominationId, const SigmaPublicKey&)> MintRemoved;

private:
    void RecordMintKey(const leveldb::Slice& mintKey);
    void RecordGroupSize(uint16_t groupSize);

    std::unique_ptr<leveldb::Iterator> NewIterator() const;

protected:
    uint16_t InitGroupSize(uint16_t groupSize);
    uint16_t GetGroupSize();
};

};

#endif // ZCOIN_EXODUS_SIGMADB_H
