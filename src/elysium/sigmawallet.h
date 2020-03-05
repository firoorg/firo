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

protected:
    class WalletDB {
    public:
        WalletDB(std::string const &walletFile);

    public:
        virtual bool WriteMint(SigmaMintId const &id, SigmaMint const &mint, CWalletDB *db = nullptr) = 0;
        virtual bool ReadMint(SigmaMintId const &id, SigmaMint &mint, CWalletDB *db = nullptr) const = 0;
        virtual bool EraseMint(SigmaMintId const &id, CWalletDB *db = nullptr) = 0;
        virtual bool HasMint(SigmaMintId const &id, CWalletDB *db = nullptr) const = 0;

        virtual bool WriteMintId(uint160 const &hash, SigmaMintId const &mintId, CWalletDB *db = nullptr) = 0;
        virtual bool ReadMintId(uint160 const &hash, SigmaMintId &mintId, CWalletDB *db = nullptr) const = 0;
        virtual bool EraseMintId(uint160 const &hash, CWalletDB *db = nullptr) = 0;
        virtual bool HasMintId(uint160 const &hash, CWalletDB *db = nullptr) const = 0;

        virtual bool WriteMintPool(std::vector<MintPoolEntry> const &mints, CWalletDB *db = nullptr) = 0;
        virtual bool ReadMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db = nullptr) = 0;

        virtual void ListMints(std::function<void(SigmaMintId&, SigmaMint&)> const&, CWalletDB *db = nullptr) = 0;

    protected:
        // Helper
        struct DBDeleter {
        private:
            bool mustDelete;

        public:
            DBDeleter(bool mustDelete);

        public:
            void operator()(CWalletDB* db);
        };

        std::unique_ptr<CWalletDB, DBDeleter> EnsureDBConnection(CWalletDB *db) const;

        std::string walletFile;
    };

public:
    std::string walletFile;
    std::unique_ptr<WalletDB> walletDB;
    MintPool mintPool;
    uint160 masterId;

    static constexpr unsigned MINTPOOL_CAPACITY = 20;

public:
    SigmaWallet(WalletDB *walletDB);

public:
    void ReloadMasterKey();

    // Generator
protected:
    uint32_t GenerateNewSeed(CKeyID &seedId, uint512 &seed);
    uint32_t GenerateSeed(CKeyID const &seedId, uint512 &seed);
    uint32_t GetSeedIndex(CKeyID const &seedId);

protected:
    virtual uint32_t BIP44ChangeIndex() const = 0;
    virtual SigmaPrivateKey GeneratePrivateKey(uint512 const &seed) = 0;

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
        walletDB->ListMints([&](const SigmaMintId& id, const SigmaMint &m) {
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
