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
    : assetKind(static_cast<uint8_t>(assetTxData_.getAssetKind())),
      identifier(assetTxData_.getIdentifier()),
      name(assetTxData_.getName()),
      symbol(assetTxData_.getSymbol()),
      description(assetTxData_.getDescription()),
      metadata(assetTxData_.getMetadata()),
      adminPublicAddress(assetTxData_.getAdminPublicAddress()),
      precision(assetTxData_.getPrecision()),
      maxSupply(assetTxData_.getMaxSupply())
{
}

CSparkAssetTxData::CSparkAssetTxData(std::uint32_t version_,
                                     AssetKind assetKind_,
                                     std::uint64_t identifier_,
                                     std::string name_,
                                     std::string symbol_,
                                     std::string description_,
                                     std::string metadata_,
                                     std::string adminPublicAddress_,
                                     uint8_t precision_,
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

void CSparkAssetTxData::setDataFromDBentry(const CSparkAssetDBEntry& dbEntry) {
      assetKind = (AssetKind)dbEntry.assetKind;
      identifier = dbEntry.identifier;

      if (!isNameModify())
          name = dbEntry.name;
      symbol = dbEntry.symbol;
      if (!isDescriptionModify())
          description = dbEntry.description;
      if (!isMetadataModify())
          metadata = dbEntry.metadata;
      adminPublicAddress = dbEntry.adminPublicAddress;
      precision = dbEntry.precision;
      maxSupply = dbEntry.maxSupply;
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
    return isValidSparkAddress(adminPublicAddress);
}

bool CSparkAssetTxData::isValidSparkAddress(const std::string& address) const
{
    const spark::Params* params = spark::Params::get_default();
    unsigned char network = spark::GetNetworkType();
    spark::Address addr(params);
    try {
        unsigned char coinNetwork = addr.decode(address);
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
    std::string error;
    return Verify(error);
}

bool CSparkAssetTxData::Verify(std::string& error) const
{
    if (name.size() > MAX_NAME_BYTES) {
    	error = "Name too long";
        return false;
    }
    if (symbol.size() > MAX_SYMBOL_BYTES) {
        error = "Symbol too long";
        return false;
    }
    if (!SymbolIsAsciiLatinLettersOnly(symbol)) {
        error = "Symbol contains unsupported characters.";
        return false;
    }
    if (description.size() > MAX_DESCRIPTION_BYTES) {
        error = "Description too long";
        return false;
    }
    if (metadata.size() > MAX_METADATA_BYTES) {
     	error = "Metadata too long";
        return false;
    }
    if (adminPublicAddress.size() > MAX_ADMIN_PUBLIC_ADDRESS_BYTES) {
     	error = "Private address too long";
        return false;
    }
    if (maxSupply < 0 || maxSupply > static_cast<std::uint64_t>(MAX_ASSET_MONEY)) {
     	error = "Maximum money too high";
        return false;
    }
    if (assetKind == AssetKind::Fungible && identifier != 0) {
     	error = "Identifier should be 0 for fungable asset";
        return false;
    }

    if (assetKind == AssetKind::NonFungible && identifier == 0) {
     	error = "Identifier should be non-zero for non-fungible asset";
        return false;
    }
//    if (assetKind == AssetKind::NonFungible && maxSupply != 0) {
    //TODO levon finilize this idea
//        return false;
//    }

    if (precision > 8) {
     	error = "Precision too large for fungible asset";
        return false;
    }

    try {
        validateAdminPublicAddress();
    } catch (const std::invalid_argument&) {
        error = "Invalid address!";
        return false;
    }
    return true;
}

void CSparkAssetTxData::setOwnershipProof(const spark::OwnershipProof& proof)
{
    ownershipProof = proof;
}

void CSparkAssetTxData::setOperationType(OperationType operationType_)
{
    this->operationType = (uint8_t)operationType_;
}
}
