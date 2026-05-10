// Copyright (c) 2022 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_SPARK_SPARKASSET_H
#define FIRO_SPARK_SPARKASSET_H

#include <cstdint>
#include <string>

#include "serialize.h"
#include "../base58.h"
#include "../libspark/keys.h"

namespace spark {
class CSparkAssetTxData;

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
    unsigned precision = 8;
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
        opModify
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
                      unsigned precision_,
                      std::uint64_t maxSupply_);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(version);
        READWRITE(operationType);
        READWRITE(assetKind);
        READWRITE(identifier);
        READWRITE(name);
        READWRITE(symbol);
        READWRITE(description);
        READWRITE(metadata);
        READWRITE(adminPublicAddress);
        READWRITE(precision);
        READWRITE(maxSupply);
        if (isValidSparkAddress())
            READWRITE(ownershipProof);
    }

    /** Return the admin address as stored (encoded string). */
    const std::string& getAdminPublicAddress() const { return adminPublicAddress; }

    const std::string& getSymbol() const { return symbol; }

    uint8_t getOperationType() const { return operationType; }

    void setOperationType(OperationType operationType_);

    /** Return the admin address as a Spark address. Throws std::invalid_argument if not a valid Spark address. */
    spark::Address getAdminSparkAddress() const;

    /** Return the admin address as a regular (base58) address. Throws std::invalid_argument if not a valid regular address. */
    CBitcoinAddress getAdminBitcoinAddress() const;

    bool isValidSparkAddress() const;
    bool isValidRegularAddress() const;
    void validateAdminPublicAddress() const;

    /** Check all asset internals (string limits, admin address, symbol = ASCII Latin letters only; NFTs not resupplyable). */
    bool Verify() const;

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
    unsigned precision = 8;
    /** Maximum total supply in raw (smallest) units; 0 = no cap. Meaningful for fungible only. */
    std::uint64_t maxSupply = 0;

    spark::OwnershipProof ownershipProof;
};

}

#endif // FIRO_SPARK_SPARKASSET_H
