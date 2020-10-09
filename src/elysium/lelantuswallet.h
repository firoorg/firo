// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_ELYSIUM_LELANTUSWALLET_H
#define ZCOIN_ELYSIUM_LELANTUSWALLET_H

#include "property.h"
#include "lelantusprimitives.h"
#include "lelantuswalletmodels.h"

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

class LelantusWallet
{
public:
    struct MintPoolEntry {
        LelantusMintId coinId;
        CKeyID seedId;
        uint32_t index;

        MintPoolEntry();
        MintPoolEntry(LelantusMintId const &coinId, CKeyID const &seedId, uint32_t index);

        bool operator==(MintPoolEntry const &another) const;
        bool operator!=(MintPoolEntry const &another) const;

        ADD_SERIALIZE_METHODS;

        template<typename Stream, typename Operation>
        void SerializationOp(Stream& s, Operation ser_action)
        {
            READWRITE(coinId);
            READWRITE(seedId);
            READWRITE(index);
        }
    };

    typedef boost::multi_index_container<
        MintPoolEntry,
        boost::multi_index::indexed_by<
            // Sequence
            boost::multi_index::ordered_unique<
                boost::multi_index::member<MintPoolEntry, LelantusIndex, &MintPoolEntry::index>
            >,
            // Lelantus coin index
            boost::multi_index::hashed_unique<
                boost::multi_index::member<MintPoolEntry, LelantusMintId, &MintPoolEntry::coinId>,
                std::hash<LelantusMintId>
            >
        >
    > MintPool;

protected:
    class Database {
    public:
        Database();

    public:
        virtual bool WriteMint(LelantusMintId const &id, LelantusMint const &mint, CWalletDB *db = nullptr) = 0;
        virtual bool ReadMint(LelantusMintId const &id, LelantusMint &mint, CWalletDB *db = nullptr) const = 0;
        virtual bool EraseMint(LelantusMintId const &id, CWalletDB *db = nullptr) = 0;
        virtual bool HasMint(LelantusMintId const &id, CWalletDB *db = nullptr) const = 0;

        virtual bool WriteMintId(uint160 const &hash, LelantusMintId const &mintId, CWalletDB *db = nullptr) = 0;
        virtual bool ReadMintId(uint160 const &hash, LelantusMintId &mintId, CWalletDB *db = nullptr) const = 0;
        virtual bool EraseMintId(uint160 const &hash, CWalletDB *db = nullptr) = 0;
        virtual bool HasMintId(uint160 const &hash, CWalletDB *db = nullptr) const = 0;

        virtual bool WriteMintPool(std::vector<MintPoolEntry> const &mints, CWalletDB *db = nullptr) = 0;
        virtual bool ReadMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db = nullptr) = 0;

        virtual void ListMints(std::function<void(LelantusMintId&, LelantusMint&)> const&, CWalletDB *db = nullptr) = 0;

    protected:
        // Helper
        class Connection
        {
        public:
            Connection(CWalletDB *db);
            ~Connection();

        public:
            CWalletDB* operator->() noexcept;

        private:
            bool local;
            union {
                CWalletDB *db;
                unsigned char local[sizeof(CWalletDB)];
            } db;
        };
    };

public:
    std::unique_ptr<Database> database;
    std::string walletFile;
    MintPool mintPool;
    uint160 masterId;

    static constexpr unsigned MINTPOOL_CAPACITY = 20;

public:
    LelantusWallet(Database *database);

public:
    void ReloadMasterKey();

    // Generator
protected:
    uint32_t GenerateNewSeed(CKeyID &seedId, uint512 &seed);
    uint32_t GenerateSeed(CKeyID const &seedId, uint512 &seed);
    uint32_t GetSeedIndex(CKeyID const &seedId, uint32_t &change);

protected:
    virtual uint32_t BIP44ChangeIndex() const = 0;
    virtual lelantus::PrivateCoin GeneratePrivateKey(uint512 const &seed) = 0;

    // Mint updating
public:
    lelantus::PrivateCoin GeneratePrivateKey(CKeyID const &seedId);
    LelantusMintId GenerateMint(PropertyId property, LelantusAmount amount, boost::optional<CKeyID> seedId = boost::none);

    void ClearMintsChainState();

    bool TryRecoverMint(LelantusMintId const &id, LelantusMintChainState const &chainState);
    bool TryRecoverMint(
        LelantusMintId const &id, LelantusMintChainState const &chainState, uint256 const &spendTx);

private:
    LelantusMint UpdateMint(LelantusMintId const &id, std::function<void(LelantusMint &)> const &modifier);

    void WriteMint(LelantusMintId const &id, LelantusMint const &mint);

public:
    void UpdateMintCreatedTx(LelantusMintId const &id, const uint256& tx);
    void UpdateMintChainstate(LelantusMintId const &id, LelantusMintChainState const &state);
    void UpdateMintSpendTx(LelantusMintId const &id, uint256 const &tx);

    // Mint querying
public:

    bool HasMint(LelantusMintId const &id) const;
    bool HasMint(secp_primitives::Scalar const &serial) const;

    LelantusMint GetMint(LelantusMintId const &id) const;
    LelantusMint GetMint(secp_primitives::Scalar const &serial) const;
    LelantusMintId GetMintId(secp_primitives::Scalar const &serial) const;

    template<class Output>
    Output ListMints(Output output, CWalletDB *db = nullptr)
    {
        database->ListMints([&](const LelantusMintId& id, const LelantusMint &m) {
            *output++ = std::make_pair(id, m);
        }, db);

        return output;
    }

    // MintPool state
public:
    void DeleteUnconfirmedMint(LelantusMintId const &id);
    bool IsMintInPool(LelantusMintId const &id);

    bool GetMintPoolEntry(LelantusMintId const &id, MintPoolEntry &entry);

protected:
    void RemoveInvalidMintPoolEntries(); // Remove MintPool entries that aren't belong to current masterId.
    size_t FillMintPool();

    void LoadMintPool();
    void SaveMintPool();

    bool RemoveFromMintPool(LelantusMintId const &id);
};

} // namespace elysium

#endif // ZCOIN_ELYSIUM_LELANTUSWALLET_H
