// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_EXODUS_SIGMAWALLET_H
#define ZCOIN_EXODUS_SIGMAWALLET_H

#include "property.h"
#include "sigmaprimitives.h"
#include "walletmodels.h"

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/optional.hpp>

#include "../uint256.h"

#include "../wallet/walletdb.h"

#include <memory>
#include <utility>

namespace exodus {

class SigmaWallet
{
public:

    struct MintPoolEntry {
        SigmaPublicKey key;
        CKeyID seedId;
        uint32_t index;

        MintPoolEntry();
        MintPoolEntry(SigmaPublicKey const &key, CKeyID const &seedId, uint32_t index);

        bool operator==(MintPoolEntry const &) const;
        bool operator!=(MintPoolEntry const &) const;

        ADD_SERIALIZE_METHODS;

        template<typename Stream, typename Operation>
        void SerializationOp(Stream& s, Operation ser_action)
        {
            READWRITE(key);
            READWRITE(seedId);
            READWRITE(index);
        }
    };

    typedef boost::multi_index_container<
        MintPoolEntry,
        boost::multi_index::indexed_by<
            // Sequence
            boost::multi_index::ordered_unique<
                boost::multi_index::member<MintPoolEntry, uint32_t, &MintPoolEntry::index>
            >,
            // Public Key index
            boost::multi_index::hashed_unique<
                boost::multi_index::member<MintPoolEntry, SigmaPublicKey, &MintPoolEntry::key>,
                std::hash<SigmaPublicKey>
            >
        >
    > MintPool;

    std::string walletFile;
    MintPool mintPool;
    uint160 masterId;

    static constexpr unsigned MINTPOOL_CAPACITY = 20;

public:
    SigmaWallet();

public:
    void ReloadMasterKey();

    // Generator
private:
    uint32_t GenerateNewSeed(CKeyID &seedId, uint512 &seed);
    uint32_t GenerateSeed(CKeyID const &seedId, uint512 &seed);
    uint32_t GetSeedIndex(CKeyID const &seedId);

protected:
    SigmaPrivateKey GeneratePrivateKey(uint512 const &seed);

    // Mint updating
public:
    SigmaPrivateKey GeneratePrivateKey(CKeyID const &seedId);
    SigmaMintId GenerateMint(PropertyId property, SigmaDenomination denom, boost::optional<CKeyID> seedId = boost::none);

    void ClearMintsChainState();
    bool TryRecoverMint(
        SigmaMintId const &id,
        SigmaMintChainState const &chainState);
    bool TryRecoverMint(
        SigmaMintId const &id,
        SigmaMintChainState const &chainState,
        uint256 const &spendTx);

private:
    SigmaMint UpdateMint(SigmaMintId const &, std::function<void(SigmaMint &)> const &);
    void WriteMint(SigmaMintId const &id, SigmaMint const &entry);

public:
    void UpdateMintCreatedTx(const SigmaMintId& id, const uint256& tx);
    void UpdateMintChainstate(SigmaMintId const &id, SigmaMintChainState const &state);
    void UpdateMintSpendTx(SigmaMintId const &id, uint256 const &tx);

    // Mint querying
public:

    bool HasMint(SigmaMintId const &id) const;
    bool HasMint(secp_primitives::Scalar const &serial) const;
    SigmaMint GetMint(SigmaMintId const &id) const;
    SigmaMint GetMint(secp_primitives::Scalar const &serial) const;
    SigmaMintId GetMintId(secp_primitives::Scalar const &serial) const;

    template<class Output>
    Output ListMints(Output output, CWalletDB *db = nullptr)
    {
        std::unique_ptr<CWalletDB> local;

        if (!db) {
            db = new CWalletDB(walletFile);
            local.reset(db);
        }

        db->ListExodusMints<SigmaMintId, SigmaMint>([&](const SigmaMintId& id, const SigmaMint &m) {
            *output++ = std::make_pair(id, m);
        });

        return output;
    }

    // MintPool state
public:
    void DeleteUnconfirmedMint(SigmaMintId const &id);
    bool IsMintInPool(SigmaPublicKey const &pubKey);
    bool GetMintPoolEntry(SigmaPublicKey const &pubKey, MintPoolEntry &entry);

protected:
    void RemoveInvalidMintPoolEntries(); // Remove MintPool entry that isn't belong to current masterId.
    size_t FillMintPool();
    void LoadMintPool();
    void SaveMintPool();
    bool RemoveFromMintPool(SigmaPublicKey const &publicKey);
};

} // namespace exodus

#endif // ZCOIN_EXODUS_SIGMAWALLET_H
