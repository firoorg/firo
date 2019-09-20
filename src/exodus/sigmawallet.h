// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_EXODUS_SIGMAWALLET_H
#define ZCOIN_EXODUS_SIGMAWALLET_H

#include <map>

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index_container.hpp>

#include "../uint256.h"
#include "../primitives/zerocoin.h"
#include "../wallet/wallet.h"

#include "walletmodels.h"

namespace exodus {

struct MintPoolEntry {
    SigmaPublicKey key;
    CKeyID seedId;

    MintPoolEntry();
    MintPoolEntry(SigmaPublicKey const &key, CKeyID const &seedId);

    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(key);
        READWRITE(seedId);
    }
};

class SigmaWallet
{
private:

    struct MintPoolEntryPublicKeyIndex
    {
        typedef SigmaPublicKey result_type;
        result_type operator() (MintPoolEntry const &entry) const {
            return entry.key;
        }
    };

    typedef boost::multi_index_container<
        MintPoolEntry,
        boost::multi_index::indexed_by<
            // Sequence
            boost::multi_index::sequenced<>,
            // Public Key index
            boost::multi_index::hashed_unique<
                MintPoolEntryPublicKeyIndex, std::hash<SigmaPublicKey>
            >
        >
    > IndexedMintPool;

    std::string walletFile;
    IndexedMintPool mintPool;
    uint160 masterId;

public:
    SigmaWallet(std::string const &walletFile);

private:
    bool SetupWallet(const uint160& masterId);

    // Generator
private:
    uint32_t CreateNextSeed(CKeyID &seedId, uint512 &seed);
    uint32_t GenerateSeed(CKeyID const &seedId, uint512 &seed);
    uint32_t GetSeedIndex(CKeyID const &seedId);
    bool SeedToPrivateKey(uint512 const &seed, exodus::SigmaPrivateKey &coin);

    // Mint updating
public:
    bool AddToWallet(SigmaMint const &entry);
    bool GenerateMint(
        uint32_t propertyId,
        uint8_t denom,
        exodus::SigmaPrivateKey& coin,
        SigmaMint& dMint,
        boost::optional<MintPoolEntry> mintPoolEntry = boost::none);

    void ResetCoinsState();
    bool SetMintSeedSeen(
        MintPoolEntry const &mintPoolEntry,
        uint32_t propertyId,
        uint8_t denomination,
        exodus::SigmaMintChainState const &chainState,
        uint256 const &spendTx = uint256());

private:
    SigmaMint UpdateMint(SigmaMintId const &, std::function<void(SigmaMint &)> const &);

public:
    SigmaMint UpdateMintChainstate(SigmaMintId const &id, SigmaMintChainState const &state);
    SigmaMint UpdateMintSpendTx(SigmaMintId const &id, uint256 const &tx);

    // Mint querying
public:

    bool HasMint(SigmaMintId const &id) const;
    bool HasSerial(secp_primitives::Scalar const &serial) const;
    SigmaMint GetMint(SigmaMintId const &id) const;
    SigmaMint GetMint(secp_primitives::Scalar const &serial) const;
    SigmaMintId GetMintId(secp_primitives::Scalar const &serial) const;

    template<
        class OutIt,
        typename std::enable_if<is_iterator<OutIt>::value>::type* = nullptr
    > OutIt ListSigmaMints(OutIt it, bool unusedOnly, bool matureOnly) const
    {
        ListSigmaMints([&it](SigmaMint &m) {
            *it++ = m;
        }, unusedOnly, matureOnly);

        return it;
    }
    size_t ListSigmaMints(std::function<void(SigmaMint&)> const &, bool unusedOnly = true, bool matureOnly = true) const;
    bool RegenerateMint(const SigmaMint& mint, SigmaPrivateKey &privKey);

    // MintPool state
public:
    size_t CountInMintPool(SigmaPublicKey const &pubKey);
    bool GetMintPoolEntry(SigmaPublicKey const &pubKey, MintPoolEntry &entry);

private:
    void CleanUp(); // Remove MintPool entry that isn't belong to current masterId.
    size_t GenerateMintPool(size_t expectedCoins = 20);
    void LoadMintPool();
    void SaveMintPool();
    bool RemoveFromMintPool(SigmaPublicKey const &publicKey);
};

} // namespace exodus

#endif // ZCOIN_EXODUS_SIGMAWALLET_H
