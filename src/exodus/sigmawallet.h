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

#include "../crypto/hmac_sha256.h"
#include "../crypto/hmac_sha512.h"
#include "../uint256.h"
#include "../wallet/wallet.h"
#include "../wallet/walletdb.h"
#include "../wallet/walletexcept.h"

#include <memory>
#include <utility>

namespace exodus {

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

template<class PrivateKey>
class SigmaWallet
{
public:

    std::string walletFile;
    MintPool mintPool;
    uint160 masterId;

    static constexpr unsigned MINTPOOL_CAPACITY = 20;

public:
    SigmaWallet() : walletFile(pwalletMain->strWalletFile)
    {
    }

public:
    void ReloadMasterKey()
    {
        LOCK(pwalletMain->cs_wallet);

        if (pwalletMain->IsLocked()) {
            throw std::runtime_error("Unable to reload master key because wallet is locked");
        }

        masterId = pwalletMain->GetHDChain().masterKeyID;

        if (masterId.IsNull()) {
            throw std::runtime_error("Master id is null");
        }

        // Load mint pool from DB
        LoadMintPool();

        // Clean up any mint entry that isn't corresponded to current masterId
        RemoveInvalidMintPoolEntries();

        // Refill mint pool
        FillMintPool();
    }

    // Generator
private:
    uint32_t GenerateNewSeed(CKeyID &seedId, uint512 &seed)
    {
        LOCK(pwalletMain->cs_wallet);
        seedId = pwalletMain->GenerateNewKey(GetChange()).GetID();
        return GenerateSeed(seedId, seed);
    }

    uint32_t GenerateSeed(CKeyID const &seedId, uint512 &seed)
    {
        LOCK(pwalletMain->cs_wallet);
        CKey key;
        if (!pwalletMain->GetKey(seedId, key)) {
            throw std::runtime_error(
                "Unable to retrieve generated key for mint seed. Is the wallet locked?");
        }

        // HMAC-SHA512(key, count)
        // `count` is LE unsigned 32 bits integer
        std::array<unsigned char, CSHA512::OUTPUT_SIZE> result;
        auto seedIndex = GetSeedIndex(seedId);

        CHMAC_SHA512(key.begin(), key.size()).
            Write(reinterpret_cast<const unsigned char*>(&seedIndex), sizeof(seedIndex)).
            Finalize(result.data());

        seed = uint512(result);

        return seedIndex;
    }

    uint32_t GetSeedIndex(CKeyID const &seedId)
    {
        LOCK(pwalletMain->cs_wallet);
        auto it = pwalletMain->mapKeyMetadata.find(seedId);
        if (it == pwalletMain->mapKeyMetadata.end()) {
            throw std::runtime_error("key not found");
        }

        // parse last index
        uint32_t addressIndex;
        try {
            addressIndex = GetBIP44AddressIndex(it->second.hdKeypath);
        } catch (std::runtime_error const &e) {
            LogPrintf("%s : fail to get child from, %s\n", __func__, e.what());
            throw;
        }

        return addressIndex;
    }

protected:
    virtual PrivateKey GeneratePrivateKey(uint512 const &seed) = 0;

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
    std::unique_ptr<CWalletDB> EnsureDBConnection(CWalletDB* &db = nullptr) const
    {
        std::unique_ptr<CWalletDB> local;
        if (db == nullptr)
        {
            db = new CWalletDB(walletFile);
            local.reset(db);
        }

        return local;
    }

    // Mint updating
public:
    PrivateKey GeneratePrivateKey(CKeyID const &seedId)
    {
        uint512 seed;

        GenerateSeed(seedId, seed);
        return GeneratePrivateKey(seed);
    }

    SigmaMintId GenerateMint(PropertyId property, SigmaDenomination denom, boost::optional<CKeyID> seedId = boost::none)
    {
        LOCK(pwalletMain->cs_wallet);

        // If not specify seed to use that mean caller want to generate a new mint.
        if (!seedId) {
            if (pwalletMain->IsLocked()) {
                throw WalletLocked();
            }

            if (mintPool.empty()) {

                // Try to recover mint pools
                ReloadMasterKey();

                if (mintPool.empty()) {
                    throw std::runtime_error("Mint pool is empty");
                }
            }

            seedId = mintPool.begin()->seedId;
        }

        // Generate private & public key.
        auto priv = GeneratePrivateKey(seedId.get());
        SigmaPublicKey pub(priv, DefaultSigmaParams);

        // Create a new mint.
        auto serialId = GetSerialId(priv.serial);
        SigmaMint mint(property, denom, seedId.get(), serialId);
        SigmaMintId id(mint.property, mint.denomination, pub);

        WriteMint(id, mint);

        return id;
    }

    void ClearMintsChainState()
    {
        CWalletDB db(walletFile);
        std::vector<std::pair<SigmaMintId, SigmaMint>> mints;

        db.TxnBegin();

        ListMints(std::back_inserter(mints), &db);

        for (auto &m : mints) {
            m.second.chainState = SigmaMintChainState();
            m.second.spendTx = uint256();

            if (!WriteExodusMint(m.first, m.second)) {
                throw std::runtime_error("Failed to write " + walletFile);
            }
        }

        db.TxnCommit();
    }

    bool TryRecoverMint(
        SigmaMintId const &id,
        SigmaMintChainState const &chainState)
    {
        return TryRecoverMint(id, chainState, uint256());
    }

    bool TryRecoverMint(
        SigmaMintId const &id,
        SigmaMintChainState const &chainState,
        uint256 const &spendTx)
    {
        LOCK(pwalletMain->cs_wallet);

        MintPoolEntry entry;
        if (!GetMintPoolEntry(id.pubKey, entry)) {
            return false;
        }

        // Regenerate the mint
        auto const &seedId = entry.seedId;

        uint512 seed;
        GenerateSeed(seedId, seed);

        auto privKey = GeneratePrivateKey(seed);

        auto serialId = GetSerialId(privKey.serial);

        // Create mint object
        SigmaMint mint(
            id.property,
            id.denomination,
            seedId,
            serialId);
        mint.chainState = chainState;
        mint.spendTx = spendTx;

        WriteMint(id, mint);

        return true;
    }

private:
    SigmaMint UpdateMint(SigmaMintId const &id, std::function<void(SigmaMint &)> const &modifier)
    {
        auto m = GetMint(id);
        modifier(m);

        if (!WriteExodusMint(id, m)) {
            throw std::runtime_error("fail to update mint");
        }

        return m;
    }

    void WriteMint(SigmaMintId const &id, SigmaMint const &mint)
    {
        if (!WriteExodusMint(id, mint)) {
            throw std::runtime_error("fail to write hdmint");
        }

        if (!WriteExodusMintId(mint.serialId, id)) {
            throw std::runtime_error("fail to record id");
        }

        RemoveFromMintPool(id.pubKey);
        FillMintPool();
    }

public:
    void UpdateMintCreatedTx(const SigmaMintId& id, const uint256& tx)
    {
        UpdateMint(id, [&](SigmaMint& m) {
            m.createdTx = tx;
        });
    }

    void UpdateMintChainstate(SigmaMintId const &id, SigmaMintChainState const &state)
    {
        UpdateMint(id, [&](SigmaMint &m) {
            m.chainState = state;
        });
    }

    void UpdateMintSpendTx(SigmaMintId const &id, uint256 const &tx)
    {
        UpdateMint(id, [&](SigmaMint &m) {
            m.spendTx = tx;
        });
    }

    // Mint querying
public:

    bool HasMint(SigmaMintId const &id) const
    {
        return HasExodusMint(id);
    }

    bool HasMint(secp_primitives::Scalar const &serial) const
    {
        auto id = GetSerialId(serial);
        return HasExodusMintId(id);
    }

    SigmaMint GetMint(SigmaMintId const &id) const
    {
        SigmaMint m;
        if (!ReadExodusMint(id, m)) {
            throw std::runtime_error("fail to read hdmint");
        }

        return m;
    }

    SigmaMint GetMint(secp_primitives::Scalar const &serial) const
    {
        return GetMint(GetMintId(serial));
    }

    SigmaMintId GetMintId(secp_primitives::Scalar const &serial) const
    {
        SigmaMintId id;
        auto serialHash = GetSerialId(serial);
        if (!ReadExodusMintId(serialHash, id)) {
            throw std::runtime_error("fail to read id");
        }

        return id;
    }

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
    void DeleteUnconfirmedMint(SigmaMintId const &id)
    {
        SigmaMint mint;
        if (!ReadExodusMint(id, mint)) {
            throw std::runtime_error("no mint data in wallet");
        }

        if (mint.IsOnChain()) {
            throw std::invalid_argument("try to delete onchain mint");
        }

        SigmaPublicKey pubKey(GeneratePrivateKey(mint.seedId), DefaultSigmaParams);

        auto index = GetSeedIndex(mint.seedId);
        mintPool.insert(MintPoolEntry(pubKey, mint.seedId, index));
        SaveMintPool();

        if (!EraseExodusMint(id)) {
            throw std::runtime_error("fail to erase mint from wallet");
        }
    }

    bool IsMintInPool(SigmaPublicKey const &pubKey)
    {
        LOCK(pwalletMain->cs_wallet);
        return mintPool.get<1>().count(pubKey);
    }

    bool GetMintPoolEntry(SigmaPublicKey const &pubKey, MintPoolEntry &entry)
    {
        LOCK(pwalletMain->cs_wallet);

        auto &publicKeyIndex = mintPool.get<1>();
        auto it = publicKeyIndex.find(pubKey);

        if (it == publicKeyIndex.end()) {
            return false;
        }

        entry = *it;
        return true;
    }

protected:
    void RemoveInvalidMintPoolEntries() // Remove MintPool entry that isn't belong to current masterId.
    {
        LOCK(pwalletMain->cs_wallet);

        bool updated = false;
        for (auto it = mintPool.begin(); it != mintPool.end(); it++) {

            auto metaIt = pwalletMain->mapKeyMetadata.find(it->seedId);
            if (metaIt == pwalletMain->mapKeyMetadata.end() ||
                metaIt->second.hdMasterKeyID != masterId) {

                updated = true;
                mintPool.erase(it);
            }
        }

        if (updated) {
            SaveMintPool();
        }
    }

    size_t FillMintPool()
    {
        LOCK(pwalletMain->cs_wallet);

        size_t generatedCoins = 0;
        while (mintPool.size() < MINTPOOL_CAPACITY) {

            CKeyID seedId;
            uint512 seed;

            auto index = GenerateNewSeed(seedId, seed);
            auto privKey = GeneratePrivateKey(seed);

            SigmaPublicKey pubKey(privKey, DefaultSigmaParams);
            mintPool.insert(MintPoolEntry(pubKey, seedId, index));

            generatedCoins++;
        }

        if (generatedCoins)  {
            SaveMintPool();
        }

        return generatedCoins;
    }

    void LoadMintPool()
    {
        LOCK(pwalletMain->cs_wallet);

        mintPool.clear();

        std::vector<MintPoolEntry> mintPoolData;
        if (ReadExodusMintPool(mintPoolData)) {
            for (auto &entry : mintPoolData) {
                mintPool.insert(std::move(entry));
            }
        }

        LogPrintf("%s : load mint pool size %d\n", __func__, mintPool.size());
    }

    void SaveMintPool()
    {
        LOCK(pwalletMain->cs_wallet);

        std::vector<MintPoolEntry> mintPoolData;
        for (auto const &entry : mintPool) {
            mintPoolData.push_back(entry);
        }

        if (!WriteExodusMintPool(mintPoolData)) {
            throw std::runtime_error("fail to save mint pool to DB");
        }
    }

    bool RemoveFromMintPool(SigmaPublicKey const &publicKey)
    {
        LOCK(pwalletMain->cs_wallet);

        auto &publicKeyIndex = mintPool.get<1>();
        auto it = publicKeyIndex.find(publicKey);

        if (it != publicKeyIndex.end()) {

            publicKeyIndex.erase(it);
            SaveMintPool();
            return true;
        }

        // publicKey is not in the pool
        return false;
    }

    virtual unsigned GetChange() const = 0;

protected:
    static uint32_t GetBIP44AddressIndex(std::string const &path)
    {
        uint32_t index;
        if (sscanf(path.data(), "m/44'/%*u'/%*u'/%*u/%u", &index) != 1) {
            throw std::runtime_error("Fail to match BIP44 path");
        }

        return index;
    }
};

} // namespace exodus

#endif // ZCOIN_EXODUS_SIGMAWALLET_H
