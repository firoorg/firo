// Copyright (c) 2022 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sparkasset.h"

#include "../amount.h"
#include "../base58.h"
#include "state.h"
#include "../libspark/keys.h"
#include "../libspark/util.h"

#include <stdexcept>

namespace {

// Field size limits (bytes). Chosen for consistency with common asset protocols:
// - Name: 256 (Counterparty subasset up to 250 chars; Solana 32; we allow longer display names).
// - Symbol: 16 (Solana/Metaplex 10; Counterparty 4-12; ERC-20 typically 3-5; 16 covers tickers).
// - Description: 4096 (4K common for on-chain; many protocols use URI to off-chain for longer text).
// - Metadata: 4096 (same as description; JSON or opaque blob).
// - Admin address: max Spark address encoded size (regular base58 addresses are shorter).
constexpr size_t MAX_NAME_BYTES = 256;
constexpr size_t MAX_SYMBOL_BYTES = 16;
constexpr size_t MAX_DESCRIPTION_BYTES = 4096;
constexpr size_t MAX_METADATA_BYTES = 4096;
constexpr size_t MAX_ADMIN_PUBLIC_ADDRESS_BYTES = spark::SPARK_ADDRESS_ENCODED_BYTES;

/** Ticker: non-empty, ASCII Latin letters only (A–Z, a–z). */
bool SymbolIsAsciiLatinLettersOnly(const std::string& s)
{
    if (s.empty())
        return false;
    for (unsigned char c : s) {
        const bool upper = c >= 'A' && c <= 'Z';
        const bool lower = c >= 'a' && c <= 'z';
        if (!upper && !lower)
            return false;
    }
    return true;
}

} // namespace

namespace spark {

CSparkAssetDBEntry::CSparkAssetDBEntry(const CSparkAssetTxData& assetTxData_)
{
    //TODO levon
}

CSparkAssetTxData::CSparkAssetTxData(std::uint32_t version_,
                                     AssetKind assetKind_,
                                     std::uint64_t identifier_,
                                     std::string name_,
                                     std::string symbol_,
                                     std::string description_,
                                     std::string metadata_,
                                     std::string adminPublicAddress_,
                                     unsigned precision_,
                                     std::uint64_t maxSupply_)
    : version(version_),
      assetKind(assetKind_),
      identifier(identifier_),
      name(std::move(name_)),
      symbol(std::move(symbol_)),
      description(std::move(description_)),
      metadata(std::move(metadata_)),
      adminPublicAddress(std::move(adminPublicAddress_)),
      precision(precision_),
      maxSupply(maxSupply_)
{
    if (!Verify())
        throw std::invalid_argument("CSparkAssetTxData: asset internals verification failed");
}

spark::Address CSparkAssetTxData::getAdminSparkAddress() const
{
    if (!isValidSparkAddress())
        throw std::invalid_argument("CSparkAssetTxData: adminPublicAddress is not a valid Spark address");
    spark::Address addr(spark::Params::get_default());
    addr.decode(adminPublicAddress);
    return addr;
}

CBitcoinAddress CSparkAssetTxData::getAdminBitcoinAddress() const
{
    if (!isValidRegularAddress())
        throw std::invalid_argument("CSparkAssetTxData: adminPublicAddress is not a valid regular address");
    return CBitcoinAddress(adminPublicAddress);
}

bool CSparkAssetTxData::isValidSparkAddress() const
{
    const spark::Params* params = spark::Params::get_default();
    unsigned char network = spark::GetNetworkType();
    spark::Address addr(params);
    try {
        unsigned char coinNetwork = addr.decode(adminPublicAddress);
        return network == coinNetwork;
    } catch (const std::exception&) {
        return false;
    }
}

bool CSparkAssetTxData::isValidRegularAddress() const
{
    CBitcoinAddress addr(adminPublicAddress);
    return addr.IsValid();
}

void CSparkAssetTxData::validateAdminPublicAddress() const
{
    if (adminPublicAddress.empty())
        throw std::invalid_argument("CSparkAssetTxData: adminPublicAddress cannot be empty");
    if (isValidSparkAddress())
        return;
    if (isValidRegularAddress())
        return;
    throw std::invalid_argument("CSparkAssetTxData: adminPublicAddress is not a valid Spark or regular address");
}

bool CSparkAssetTxData::Verify() const
{
    if (name.size() > MAX_NAME_BYTES)
        return false;
    if (symbol.size() > MAX_SYMBOL_BYTES)
        return false;
    if (!SymbolIsAsciiLatinLettersOnly(symbol))
        return false;
    if (description.size() > MAX_DESCRIPTION_BYTES)
        return false;
    if (metadata.size() > MAX_METADATA_BYTES)
        return false;
    if (adminPublicAddress.size() > MAX_ADMIN_PUBLIC_ADDRESS_BYTES)
        return false;
    if (maxSupply > 0 && maxSupply > static_cast<std::uint64_t>(MAX_MONEY))
        return false;
    if (assetKind == AssetKind::Fungible && identifier != 0)
        return false;
    if (assetKind == AssetKind::NonFungible && identifier == 0)
        return false;
    if (assetKind == AssetKind::NonFungible && maxSupply != 0)
        return false;
    try {
        validateAdminPublicAddress();
    } catch (const std::invalid_argument&) {
        return false;
    }
    return true;
}

void CSparkAssetTxData::setOwnershipProof(const spark::OwnershipProof& ownershipProof) {
    //TODO levon
}

void CSparkAssetTxData::setOperationType(OperationType operationType_)
{
    this->operationType = (uint8_t)operationType_;
}


}
