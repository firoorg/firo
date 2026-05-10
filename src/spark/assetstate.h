// Copyright (c) 2022 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_SPARK_ASSETSTATE_H
#define FIRO_SPARK_ASSETSTATE_H

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "serialize.h"
#include "uint256.h"

#include "sparkasset.h"

namespace spark {

Scalar GetSpatsRegistreM(const CSparkAssetTxData& assetData);

/**
 * In-memory registry of Spark asset definitions (payload from asset-registration
 * transactions). Each new registration gets the next uint64 asset type id (counter),
 * starting at 1 (0 reserved for the native/base asset in Spats).
 * Re-processing the same registeringTxid is idempotent (same id, entry refreshed).
 * Asset symbols are unique in this state (case-insensitive ASCII A–Z / a–z).
 * Callers that hold shared state should synchronize externally (e.g. wallet cs).
 */
class CAssetState {
public:
    /** Spats circulating supply bucket: registered asset type + on-coin identifier (spark::Coin::iota). */
    using CirculatingSupplyKey = std::pair<std::uint64_t, std::uint64_t>;
    using CirculatingSupplyMap = std::map<CirculatingSupplyKey, std::uint64_t>;

    CAssetState() = default;

    /**
     * Registers a new asset (next counter value) or refreshes an existing one
     * if registeringTxid already present. Returns nullopt if the symbol is taken
     * by another asset.
     */
    std::optional<std::uint64_t> Put(CSparkAssetTxData data, const uint256& registeringTxid, int nHeight);
    bool Erase(std::uint64_t assetType);
    void Clear()
    {
        entries_.clear();
        symbolToAssetType_.clear();
        nextAssetType_ = 1;
        circulating_supply_.clear();
    }

    bool Contains(std::uint64_t assetType) const;
    std::optional<CSparkAssetDBEntry> Get(std::uint64_t assetType) const;

    /** Case-insensitive lookup (ASCII letters); returns nullopt if unknown. */
    std::optional<std::uint64_t> GetAssetTypeBySymbol(const std::string& symbol) const;

    /** True if symbol is already mapped (case-insensitive ASCII). */
    bool IsSymbolTaken(const std::string& symbol) const;

    /** Next id that will be assigned on Put (1 + last issued, never reused after Erase). */
    std::uint64_t GetNextAssetTypeCounter() const { return nextAssetType_; }

    const std::map<std::uint64_t, std::vector<CSparkAssetDBEntry>>& Entries() const { return entries_; }
    std::size_t size() const { return entries_.size(); }

    /** Supply for one (asset type, identifier) pair. */
    std::uint64_t GetCirculatingSupply(std::uint64_t assetType, std::uint64_t identifier) const;

    /** Sum of circulating supply over all identifiers for this asset type (matches burn scripts that only name asset type). */
    std::uint64_t GetCirculatingSupplyAggregated(std::uint64_t assetType) const;

    const CirculatingSupplyMap& GetCirculatingSupplyMap() const { return circulating_supply_; }

    void AddCirculatingSupply(std::uint64_t assetType, std::uint64_t identifier, std::uint64_t amount);
    void SubCirculatingSupply(std::uint64_t assetType, std::uint64_t identifier, std::uint64_t amount);

    /** Drop only supply tracking (e.g. chain rewind); keeps registration entries and tx history. */
    void ClearCirculatingSupply() { circulating_supply_.clear(); }

    bool CanRegister(const CSparkAssetTxData& assetData) const;
    bool CanModify(const CSparkAssetTxData& assetData) const;

private:
    void RebuildSymbolIndex();
    void EnsureCounterPastMaxKey();

    std::map<std::uint64_t, std::vector<CSparkAssetDBEntry>> entries_;
    /** Normalized symbol (uppercase ASCII) -> asset type id. */
    std::map<std::string, std::uint64_t> symbolToAssetType_;

    std::map<std::uint64_t, bool> isNonFungable;;

    /** Next asset type to assign; must stay strictly greater than all keys in entries_. */
    std::uint64_t nextAssetType_ = 1;

    CirculatingSupplyMap circulating_supply_;
};

}

#endif // FIRO_SPARK_ASSETSTATE_H
