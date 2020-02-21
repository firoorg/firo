#ifndef ELYSIUM_FEES_H
#define ELYSIUM_FEES_H

#include "leveldb/db.h"

#include "elysium/log.h"
#include "elysium/persistence.h"

#include <set>
#include <stdint.h>
#include <boost/filesystem.hpp>

typedef std::pair<int, int64_t> feeCacheItem;
typedef std::pair<std::string, int64_t> feeHistoryItem;

/** LevelDB based storage for the MetaDEx fee cache
 */
class CElysiumFeeCache : public CDBBase
{
public:
    CElysiumFeeCache(const boost::filesystem::path& path, bool fWipe)
    {
        leveldb::Status status = Open(path, fWipe);
        PrintToLog("Loading fee cache database: %s\n", status.ToString());
    }

    virtual ~CElysiumFeeCache()
    {
        if (elysium_debug_fees) PrintToLog("CElysiumFeeCache closed\n");
    }

    // Show Fee Cache DB statistics
    void printStats();
    // Show Fee Cache DB records
    void printAll();

    // Sets the distribution thresholds to total tokens for a property / ELYSIUM_FEE_THRESHOLD
    void UpdateDistributionThresholds(uint32_t propertyId);
    // Returns the distribution threshold for a property
    int64_t GetDistributionThreshold(const uint32_t &propertyId);
    // Return a set containing fee cache history items
    std::set<feeCacheItem> GetCacheHistory(const uint32_t &propertyId);
    // Gets the current amount of the fee cache for a property
    int64_t GetCachedAmount(const uint32_t &propertyId);
    // Prunes entries over 50 blocks old from the entry for a property
    void PruneCache(const uint32_t &propertyId, int block);
    // Rolls back the cache to an earlier state (eg in event of a reorg) - block is *inclusive* (ie entries=block will get deleted)
    void RollBackCache(int block);
    // Zeros a property in the fee cache
    void ClearCache(const uint32_t &propertyId, int block);
    // Adds a fee to the cache (eg on a completed trade)
    void AddFee(const uint32_t &propertyId, int block, const int64_t &amount);
    // Evaluates fee caches for all properties against threshold and executes distribution if threshold met
    void EvalCache(const uint32_t &propertyId, int block);
    // Performs distribution of fees
    void DistributeCache(const uint32_t &propertyId, int block);
};

/** LevelDB based storage for the MetaDEx fee distributions
 */
class CElysiumFeeHistory : public CDBBase
{
public:
    CElysiumFeeHistory(const boost::filesystem::path& path, bool fWipe)
    {
        leveldb::Status status = Open(path, fWipe);
        PrintToLog("Loading fee history database: %s\n", status.ToString());
    }

    virtual ~CElysiumFeeHistory()
    {
        if (elysium_debug_fees) PrintToLog("CElysiumFeeHistory closed\n");
    }

    // Show Fee History DB statistics
    void printStats();
    // Show Fee History DB records
    void printAll();

    // Roll back history in event of reorg
    void RollBackHistory(int block);
    // Count Fee History DB records
    int CountRecords();
    // Record a fee distribution
    void RecordFeeDistribution(const uint32_t &propertyId, int block, int64_t total, std::set<feeHistoryItem> feeRecipients);
    // Retrieve the recipients for a fee distribution
    std::set<feeHistoryItem> GetFeeDistribution(int id);
    // Retrieve fee distributions for a property
    std::set<int> GetDistributionsForProperty(const uint32_t &propertyId);
    // Populate data about a fee distribution
    bool GetDistributionData(int id, uint32_t *propertyId, int *block, int64_t *total);
    // Retrieve fee distribution receipts for an address
};

namespace elysium
{
    extern CElysiumFeeCache *p_feecache;
    extern CElysiumFeeHistory *p_feehistory;
}

#endif // ELYSIUM_FEES_H
