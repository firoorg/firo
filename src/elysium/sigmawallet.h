// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_ELYSIUM_SIGMAWALLET_H
#define ZCOIN_ELYSIUM_SIGMAWALLET_H

#include "property.h"
#include "sigmaprimitives.h"
#include "walletmodels.h"

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/optional.hpp>

#include "../crypto/hmac_sha256.h"
#include "../crypto/hmac_sha512.h"
#include "../uint256.h"
#include "../wallet/wallet.h"
#include "../wallet/walletdb.h"
#include "../wallet/walletexcept.h"

#include <memory>
#include <utility>

namespace elysium {

class SigmaWallet
{
public:
    struct MintPoolEntry {
        SigmaPublicKey key;
        CKeyID seedId;
        uint32_t index;

        MintPoolEntry();
        MintPoolEntry(SigmaPublicKey const &key, CKeyID const &seedId, uint32_t index);

        bool operator==(MintPoolEntry const &another) const;
        bool operator!=(MintPoolEntry const &another) const;

        ADD_SERIALIZE_METHODS;

        template<typename Stream, typename Operation>
        void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
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
protected:
    uint32_t GenerateNewSeed(CKeyID &seedId, uint512 &seed);
    uint32_t GenerateSeed(CKeyID const &seedId, uint512 &seed);
    uint32_t GetSeedIndex(CKeyID const &seedId);

protected:
    virtual uint32_t ChangeIndex() = 0;
    virtual SigmaPrivateKey GeneratePrivateKey(uint512 const &seed) = 0;

    // DB
    virtual bool WriteExodusMint(SigmaMintId const &id, SigmaMint const &mint, CWalletDB *db = nullptr) = 0;
    virtual bool ReadExodusMint(SigmaMintId const &id, SigmaMint &mint, CWalletDB *db = nullptr) const = 0;
    virtual bool EraseExodusMint(SigmaMintId const &id, CWalletDB *db = nullptr) = 0;
    virtual bool HasExodusMint(SigmaMintId const &id, CWalletDB *db = nullptr) const = 0;

    virtual bool WriteExodusMintId(uint160 const &hash, SigmaMintId const &mintId, CWalletDB *db = nullptr) = 0;
    virtual bool ReadExodusMintId(uint160 const &hash, SigmaMintId &mintId, CWalletDB *db = nullptr) const = 0;
    virtual bool EraseExodusMintId(uint160 const &hash, CWalletDB *db = nullptr) = 0;
    virtual bool HasExodusMintId(uint160 const &hash, CWalletDB *db = nullptr) const = 0;

    virtual bool WriteExodusMintPool(std::vector<MintPoolEntry> const &mints, CWalletDB *db = nullptr) = 0;
    virtual bool ReadExodusMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db = nullptr) = 0;

    virtual void ListExodusMints(std::function<void(SigmaMintId&, SigmaMint&)>, CWalletDB *db = nullptr) = 0;

    // Helper
    std::unique_ptr<CWalletDB> EnsureDBConnection(CWalletDB* &db) const;

    // Mint updating
public:
    SigmaPrivateKey GeneratePrivateKey(CKeyID const &seedId);
    SigmaMintId GenerateMint(PropertyId property, SigmaDenomination denom, boost::optional<CKeyID> seedId = boost::none);

    void ClearMintsChainState();

    bool TryRecoverMint(SigmaMintId const &id, SigmaMintChainState const &chainState);
    bool TryRecoverMint(
        SigmaMintId const &id, SigmaMintChainState const &chainState, uint256 const &spendTx);

private:
    SigmaMint UpdateMint(SigmaMintId const &id, std::function<void(SigmaMint &)> const &modifier);

    void WriteMint(SigmaMintId const &id, SigmaMint const &mint);

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
        ListExodusMints([&](const SigmaMintId& id, const SigmaMint &m) {
            *output++ = std::make_pair(id, m);
        }, db);

        return output;
    }

    // MintPool state
public:
    void DeleteUnconfirmedMint(SigmaMintId const &id);
    bool IsMintInPool(SigmaPublicKey const &pubKey);

    bool GetMintPoolEntry(SigmaPublicKey const &pubKey, MintPoolEntry &entry);

protected:
    void RemoveInvalidMintPoolEntries(); // Remove MintPool entries that aren't belong to current masterId.
    size_t FillMintPool();

    void LoadMintPool();
    void SaveMintPool();

    bool RemoveFromMintPool(SigmaPublicKey const &publicKey);
};

} // namespace elysium

#endif // ZCOIN_ELYSIUM_SIGMAWALLET_H
