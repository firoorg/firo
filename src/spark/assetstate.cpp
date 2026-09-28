// Copyright (c) 2022 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assetstate.h"

#include "../util.h"

#include <algorithm>
#include <limits>

namespace spark {
/** Uppercase ASCII for symbol uniqueness (tickers are case-insensitive). */
std::string NormalizeSymbol(const std::string& symbol)
{
    std::string out;
    out.reserve(symbol.size());
    for (unsigned char c : symbol) {
        if (c >= 'a' && c <= 'z')
            out += static_cast<char>(c - 'a' + 'A');
        else
            out += static_cast<char>(c);
    }
    return out;
}

Scalar GetSpatsRegistreM(const CSparkAssetTxData& assetData)
{
    // The ownership proof is of this scalar, so the message must not include the proof.
    CSparkAssetTxData message = assetData;
    message.setOwnershipProof(OwnershipProof());
    spark::Hash hash("SpatsRegistreM");
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << message;
    hash.include(serialized);
    return hash.finalize_scalar();
}

void CAssetState::RebuildSymbolIndex()
{
    symbolToAssetType_.clear();
    for (const auto& [assetType, entries] : entries_) {
        if (entries.empty())
            continue;
        symbolToAssetType_[NormalizeSymbol(entries.front().symbol)] = assetType;
    }
}

void CAssetState::EnsureCounterPastMaxKey()
{
    std::uint64_t maxKey = 0;
    for (const auto& [k, unused] : entries_) {
        (void)unused;
        if (k > maxKey)
            maxKey = k;
    }
    if (nextAssetType_ <= maxKey)
        nextAssetType_ = maxKey + 1;
    if (nextAssetType_ == 0)
        nextAssetType_ = 1;
}

namespace {

std::optional<std::uint64_t> FindAssetByRegisteringTxid(
    const std::map<std::uint64_t, std::vector<CSparkAssetDBEntry>>& entries,
    const uint256& registeringTxid)
{
    for (const auto& [assetType, list] : entries) {
        if (!list.empty() && list.front().registeringTxid == registeringTxid)
            return assetType;
    }
    return std::nullopt;
}

bool AdminMatches(const CSparkAssetDBEntry& entry, const CSparkAssetTxData& assetData)
{
    return entry.adminPublicAddress == assetData.getAdminPublicAddress();
}

} // namespace

std::optional<std::uint64_t> CAssetState::Put(
    CSparkAssetTxData data,
    const uint256& registeringTxid,
    int nHeight)
{
    if (data.isRegister()) {
        if (const auto existing = FindAssetByRegisteringTxid(entries_, registeringTxid))
            return *existing;

        const std::string normSym = NormalizeSymbol(data.getSymbol());
        if (symbolToAssetType_.find(normSym) != symbolToAssetType_.end())
            return std::nullopt;

        EnsureCounterPastMaxKey();
        const std::uint64_t assetType = nextAssetType_++;
        CSparkAssetDBEntry entry(data);
        entry.registeringTxid = registeringTxid;
        entry.nHeight = nHeight;
        entries_[assetType] = {std::move(entry)};
        symbolToAssetType_[normSym] = assetType;
        const bool nonFungible = data.getAssetKind() == AssetKind::NonFungible;
        isNonFungable[assetType] = nonFungible;
        if (nonFungible && data.getIdentifier() != 0)
            nftIdentifiers_[assetType].insert(data.getIdentifier());
        return assetType;
    }

    const auto assetType = GetAssetTypeBySymbol(data.getSymbol());
    if (!assetType || entries_[*assetType].empty())
        return std::nullopt;

    CSparkAssetDBEntry& current = entries_[*assetType].front();
    if (!AdminMatches(current, data))
        return std::nullopt;

    if (data.isNameModify())
        current.name = data.getName();
    else if (data.isDescriptionModify())
        current.description = data.getDescription();
    else if (data.isMetadataModify())
        current.metadata = data.getMetadata();
    else if (data.isTransfer()) {
        if (data.getTransferAddress().empty())
            return std::nullopt;
        current.adminPublicAddress = data.getTransferAddress();
    } else
        return std::nullopt;

    return *assetType;
}

bool CAssetState::Erase(std::uint64_t assetType)
{
    const auto it = entries_.find(assetType);
    if (it == entries_.end() || it->second.empty())
        return false;
    const std::string norm = NormalizeSymbol(it->second.front().symbol);
    const auto sit = symbolToAssetType_.find(norm);
    if (sit != symbolToAssetType_.end() && sit->second == assetType)
        symbolToAssetType_.erase(sit);
    entries_.erase(it);
    isNonFungable.erase(assetType);
    nftIdentifiers_.erase(assetType);
    for (auto supply = circulating_supply_.lower_bound({assetType, 0});
         supply != circulating_supply_.end() && supply->first.first == assetType; ) {
        supply = circulating_supply_.erase(supply);
    }
    return true;
}

bool CAssetState::Contains(std::uint64_t assetType) const
{
    return entries_.find(assetType) != entries_.end();
}

std::optional<CSparkAssetDBEntry> CAssetState::Get(std::uint64_t assetType) const
{
    const auto it = entries_.find(assetType);
    if (it == entries_.end() || it->second.empty())
        return std::nullopt;
    return it->second.front();
}

std::optional<std::uint64_t> CAssetState::GetAssetTypeBySymbol(const std::string& symbol) const
{
    const std::string norm = NormalizeSymbol(symbol);
    const auto it = symbolToAssetType_.find(norm);
    if (it == symbolToAssetType_.end())
        return std::nullopt;
    return it->second;
}

bool CAssetState::IsSymbolTaken(const std::string& symbol) const
{
    return GetAssetTypeBySymbol(symbol).has_value();
}

std::uint64_t CAssetState::GetCirculatingSupply(std::uint64_t assetType, std::uint64_t identifier) const
{
    const auto it = circulating_supply_.find(CirculatingSupplyKey{assetType, identifier});
    if (it == circulating_supply_.end())
        return 0;
    return it->second;
}

std::uint64_t CAssetState::GetCirculatingSupplyAggregated(std::uint64_t assetType) const
{
    std::uint64_t sum = 0;
    for (auto it = circulating_supply_.lower_bound({assetType, 0});
         it != circulating_supply_.end() && it->first.first == assetType;
         ++it) {
        if (it->second > std::numeric_limits<std::uint64_t>::max() - sum) {
            return std::numeric_limits<std::uint64_t>::max();
        }
        sum += it->second;
    }
    return sum;
}

void CAssetState::AddCirculatingSupply(std::uint64_t assetType, std::uint64_t identifier, std::uint64_t amount)
{
    if (amount == 0)
        return;
    const CirculatingSupplyKey key{assetType, identifier};
    std::uint64_t& slot = circulating_supply_[key];
    if (amount > std::numeric_limits<std::uint64_t>::max() - slot) {
        LogPrintf("CAssetState::AddCirculatingSupply: overflow for asset %llu id %llu\n",
            static_cast<unsigned long long>(assetType),
            static_cast<unsigned long long>(identifier));
        slot = std::numeric_limits<std::uint64_t>::max();
        return;
    }
    slot += amount;
}

void CAssetState::SubCirculatingSupply(std::uint64_t assetType, std::uint64_t identifier, std::uint64_t amount)
{
    if (amount == 0)
        return;
    const CirculatingSupplyKey key{assetType, identifier};
    auto it = circulating_supply_.find(key);
    if (it == circulating_supply_.end() || it->second < amount) {
        LogPrintf("CAssetState::SubCirculatingSupply: underflow for asset %llu id %llu\n",
            static_cast<unsigned long long>(assetType),
            static_cast<unsigned long long>(identifier));
        if (it != circulating_supply_.end())
            circulating_supply_.erase(it);
        return;
    }
    it->second -= amount;
    if (it->second == 0)
        circulating_supply_.erase(it);
}

bool CAssetState::CanRegister(const CSparkAssetTxData& assetData) const
{
    return assetData.isRegister() && !IsSymbolTaken(assetData.getSymbol());
}

bool CAssetState::CanModify(const CSparkAssetTxData& assetData) const
{
    if (!assetData.isModify())
        return false;
    const auto assetType = GetAssetTypeBySymbol(assetData.getSymbol());
    if (!assetType)
        return false;
    const auto entry = Get(*assetType);
    return entry && AdminMatches(*entry, assetData);
}

bool CAssetState::CanTransfer(const CSparkAssetTxData& assetData) const
{
    if (!assetData.isTransfer() || assetData.getTransferAddress().empty())
        return false;
    const auto assetType = GetAssetTypeBySymbol(assetData.getSymbol());
    if (!assetType)
        return false;
    const auto entry = Get(*assetType);
    return entry && AdminMatches(*entry, assetData);
}

std::uint64_t CAssetState::NextNFTIdentifier(const std::string& symbol) const
{
    const auto assetType = GetAssetTypeBySymbol(symbol);
    if (!assetType)
        return 1;
    const auto it = nftIdentifiers_.find(*assetType);
    if (it == nftIdentifiers_.end() || it->second.empty())
        return 1;
    const std::uint64_t highest = *it->second.rbegin();
    if (highest == std::numeric_limits<std::uint64_t>::max())
        return highest;
    return highest + 1;
}

bool CAssetState::HasNFTIdentifier(const std::string& symbol, std::uint64_t identifier) const
{
    if (identifier == 0)
        return false;
    const auto assetType = GetAssetTypeBySymbol(symbol);
    if (!assetType)
        return false;
    const auto it = nftIdentifiers_.find(*assetType);
    return it != nftIdentifiers_.end() && it->second.count(identifier) != 0;
}

} //namespace spark
