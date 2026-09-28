// Copyright (c) 2022 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_SPARK_SPARKASSET_H
#define FIRO_SPARK_SPARKASSET_H

#include <cstdint>
#include <string>

#include "serialize.h"
#include "../base58.h"
#include "../uint256.h"
#include "../libspark/keys.h"

namespace spark {
class CSparkAssetTxData;

/** Domain-separated hash of an asset payload. Used as the Spark V2 extension commitment. */
uint256 GetSpatsAssetBindHash(const CSparkAssetTxData& assetData);

static const CAmount MAX_ASSET_MONEY = 90000000000 * COIN;


enum AssetKind : std::uint8_t
{
    Fungible = 0,
    NonFungible
};

class CSparkAssetWalletEntry
{
public:
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(symbol);
        READWRITE(txids);
        READWRITE(nHeight);
        READWRITE(isTransfered);
        READWRITE(address);
        READWRITE(assetType);
        READWRITE(identifier);
    }

    std::string symbol;
    std::vector<uint256> txids;
    // block height, in which asset owning(registration or transfered to you) tx is included;
    int nHeight;
    // is true in case asset is transfered to someone else, and does not belong to you anymore;
    bool isTransfered;
    // ownership address
    std::string address;

    std::uint64_t assetType;
    std::uint64_t identifier;
};

class CSparkAssetDBEntry
{
public:
    CSparkAssetDBEntry() = default;
    CSparkAssetDBEntry(const CSparkAssetTxData& assetTxData_);

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(assetKind);
        READWRITE(identifier);
        READWRITE(name);
        READWRITE(symbol);
        READWRITE(description);
        READWRITE(metadata);
        READWRITE(adminPublicAddress);
        READWRITE(precision);
        READWRITE(maxSupply);
        READWRITE(registeringTxid);
        READWRITE(nHeight);
    }
    uint8_t assetKind{(uint8_t)AssetKind::Fungible};
    std::uint64_t identifier = 0;  // NFT instance id within the line; 0 for fungible
    std::string name;
    std::string symbol;
    std::string description;
    std::string metadata;
    std::string adminPublicAddress;
    uint8_t precision = 8;
    /** Maximum total supply in raw (smallest) units; 0 = no cap. Meaningful for fungible only. */
    std::uint64_t maxSupply = 0;
    uint256 registeringTxid;
    int nHeight = -1;
};

class CSparkAssetTxData 

{
public:
    enum OperationType
    {
        opRegister = 0,
        opModifyName,
        opModifyDescription,
        opModifyMetadata,
        opTransfer
    };

    /** Fungible: one asset type, many interchangeable units (supply, precision, resupplyable).
     *  NFT: one asset type (line) + identifier = one unique token instance. */


    CSparkAssetTxData() = default;

    CSparkAssetTxData(std::uint32_t version_,
                      AssetKind assetKind_,
                      std::uint64_t identifier_,
                      std::string name_,
                      std::string symbol_,
                      std::string description_,
                      std::string metadata_,
                      std::string adminPublicAddress_,
                      uint8_t precision_,
                      std::uint64_t maxSupply_);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(version);
        if (version != 1)
            throw std::ios_base::failure("CSparkAssetTxData: unsupported version");

        // Field set depends only on operationType. Admin address and ownership proof
        // are always present, including for a transparent admin.
        READWRITE(operationType);
        READWRITE(symbol);

        if (isRegister()) {
            READWRITE(name);
            std::uint8_t assetKindWire = static_cast<std::uint8_t>(assetKind);
            READWRITE(assetKindWire);
            if (ser_action.ForRead())
                assetKind = static_cast<AssetKind>(assetKindWire);
            READWRITE(identifier);
            READWRITE(description);
            READWRITE(metadata);
            READWRITE(adminPublicAddress);
            READWRITE(precision);
            READWRITE(maxSupply);
            READWRITE(ownershipProof);
        } else if (isNameModify()) {
            READWRITE(name);
            READWRITE(adminPublicAddress);
            READWRITE(ownershipProof);
        } else if (isDescriptionModify()) {
            READWRITE(description);
            READWRITE(adminPublicAddress);
            READWRITE(ownershipProof);
        } else if (isMetadataModify()) {
            READWRITE(metadata);
            READWRITE(adminPublicAddress);
            READWRITE(ownershipProof);
        } else if (isTransfer()) {
            READWRITE(adminPublicAddress);
            READWRITE(ownershipProof);
            READWRITE(transferPublicAddress);
            READWRITE(recieverOwnershipProof);
        } else {
            throw std::ios_base::failure("CSparkAssetTxData: unknown operation");
        }
    }

    void setDataFromDBentry(const CSparkAssetDBEntry& dbEntry);

    bool isRegister() const {
        return getOperationType() == (uint8_t)CSparkAssetTxData::opRegister;
    }

    bool isNameModify() const {
        return getOperationType() == (uint8_t)CSparkAssetTxData::opModifyName;
    }
    bool isDescriptionModify() const {
        return getOperationType() == (uint8_t)CSparkAssetTxData::opModifyDescription;
    }

    bool isMetadataModify() const {
        return getOperationType() == (uint8_t)CSparkAssetTxData::opModifyMetadata;
    }

    bool isModify() const {
        return isNameModify() || isDescriptionModify() || isMetadataModify();
    }

    bool isTransfer() const {
        return getOperationType() == (uint8_t)CSparkAssetTxData::opTransfer;
    }

    /** Return the admin address as stored (encoded string). */
    const std::string& getAdminPublicAddress() const { return adminPublicAddress; }
    void setAdminPublicAddress(const std::string& address) { adminPublicAddress = address; }

    /** Return the admin address as stored (encoded string). */
    const std::string& getTransferAddress() const { return transferPublicAddress; }
    void setTransferAddress(const std::string& transferPublicAddress_) { transferPublicAddress = transferPublicAddress_; }

    const std::string& getRecieverOwnershipProof() const { return recieverOwnershipProof; }
    void setRecieverProof(const std::string& recieverOwnershipProof_) { recieverOwnershipProof = recieverOwnershipProof_; }

    const std::string& getSymbol() const { return symbol; }
  	void setSymbol(const std::string& symbol_) { symbol = symbol_; }

    const std::string& getName() const { return name; }
    void setName(const std::string& name_) { name = name_; }

    const std::string& getDescription() const { return description; }
    void setDescription(const std::string& description_) { description = description_; }

    const std::string& getMetadata() const { return metadata; }
    void setMetadata(const std::string& metadata_) { metadata = metadata_; }

    AssetKind getAssetKind() const { return assetKind; }
    std::uint64_t getIdentifier() const { return identifier; }
    uint8_t getPrecision() const { return precision; }
    std::uint64_t getMaxSupply() const { return maxSupply; }


    uint8_t getOperationType() const { return operationType; }

    void setOperationType(OperationType operationType_);

    void setIdentifier(std::uint64_t identifier_) { identifier = identifier_; }

    void setAssetKind(AssetKind assetKind_) { assetKind = assetKind_; }

    void setPrecision(uint8_t precision_) { precision = precision_; }

    void setMaxSupply(uint64_t maxSupply_) { maxSupply = maxSupply_; }

    /** Return the admin address as a Spark address. Throws std::invalid_argument if not a valid Spark address. */
    spark::Address getAdminSparkAddress() const;

    /** Return the admin address as a regular (base58) address. Throws std::invalid_argument if not a valid regular address. */
    CBitcoinAddress getAdminBitcoinAddress() const;

    bool isValidSparkAddress() const;
    bool isValidSparkAddress(const std::string& address) const;

    bool isValidRegularAddress() const;
    void validateAdminPublicAddress() const;

    /** Check all asset internals (string limits, admin address, symbol = ASCII Latin letters only; NFTs not resupplyable). */
    bool Verify() const;

    bool Verify(std::string& error) const;

    void setOwnershipProof(const spark::OwnershipProof& ownershipProof);

private:
    std::uint32_t version = 1;
    uint8_t operationType{(uint8_t)opRegister};
    AssetKind assetKind = AssetKind::Fungible;
    std::uint64_t identifier = 0;  // NFT instance id within the line; 0 for fungible
    std::string name;
    std::string symbol;
    std::string description;
    std::string metadata;
    std::string adminPublicAddress;
    uint8_t precision = 8;
    /** Maximum total supply in raw (smallest) units; 0 = no cap. Meaningful for fungible only. */
    std::uint64_t maxSupply = 0;

    spark::OwnershipProof ownershipProof;

    std::string transferPublicAddress;
    std::string recieverOwnershipProof;
};

}

#endif // FIRO_SPARK_SPARKASSET_H
