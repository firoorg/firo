// Copyright (c) 2022 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assetstate.h"

#include "../util.h"

#include <algorithm>
#include <limits>

namespace {

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

} // namespace

namespace spark {

Scalar GetSpatsRegistreM(const CSparkAssetTxData& assetData)
{
    spark::Hash hash("SpatsRegistreM");
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << assetData;
    hash.include(serialized);
    return hash.finalize_scalar();
}

void CAssetState::RebuildSymbolIndex()
{
//    symbolToAssetType_.clear();
//    for (const auto& [assetType, entry] : entries_) {
//        const std::string norm = NormalizeSymbol(entry.symbol);
//        symbolToAssetType_[norm] = assetType;
//    }
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

std::optional<std::uint64_t> CAssetState::Put(
    CSparkAssetTxData data,
    const uint256& registeringTxid,
    int nHeight)
{
    //TODO levon
//    const std::string normSym = NormalizeSymbol(data.getSymbol());
//
//    for (const auto& [assetType, entry] : entries_) {
//        if (entry.registeringTxid == registeringTxid) {
//            const std::string oldNorm = NormalizeSymbol(entry.data.getSymbol());
//            if (oldNorm != normSym) {
//                const auto oldSit = symbolToAssetType_.find(oldNorm);
//                if (oldSit != symbolToAssetType_.end() && oldSit->second == assetType)
//                    symbolToAssetType_.erase(oldSit);
//            }
//            entries_[assetType] = Entry{std::move(data), registeringTxid, nHeight};
//            symbolToAssetType_[normSym] = assetType;
//            return assetType;
//        }
//    }
//
//    if (const auto symIt = symbolToAssetType_.find(normSym); symIt != symbolToAssetType_.end())
//        return std::nullopt;
//
//    const std::uint64_t assetType = nextAssetType_++;
//    entries_[assetType] = Entry{std::move(data), registeringTxid, nHeight};
//    symbolToAssetType_[normSym] = assetType;
//    return assetType;
}

bool CAssetState::Erase(std::uint64_t assetType)
{
//    const auto it = entries_.find(assetType);
//    if (it == entries_.end())
//        return false;
//    const std::string norm = NormalizeSymbol(it->second.data.getSymbol());
//    const auto sit = symbolToAssetType_.find(norm);
//    if (sit != symbolToAssetType_.end() && sit->second == assetType)
//        symbolToAssetType_.erase(sit);
//    entries_.erase(it);
//    for (auto sit = circulating_supply_.lower_bound({assetType, 0});
//         sit != circulating_supply_.end() && sit->first.first == assetType; ) {
//        sit = circulating_supply_.erase(sit);
//    }
//    asset_modifying_txids_.erase(assetType);
    return true;
}

bool CAssetState::Contains(std::uint64_t assetType) const
{
    return entries_.find(assetType) != entries_.end();
}

std::optional<CSparkAssetDBEntry> CAssetState::Get(std::uint64_t assetType) const
{
    const auto it = entries_.find(assetType);
    if (it == entries_.end())
        return std::nullopt;
    return it->second[0];
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
    //TODO levon
    return true;
}

bool CAssetState::CanModify(const CSparkAssetTxData& assetData) const
{
    //TODO levon
    return true;
}

} //namespace spark
