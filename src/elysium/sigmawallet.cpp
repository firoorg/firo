// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sigmawallet.h"

#include "walletmodels.h"

#include "../uint256.h"

#include "../crypto/hmac_sha256.h"
#include "../crypto/hmac_sha512.h"

#include "../wallet/wallet.h"
#include "../wallet/walletdb.h"
#include "../wallet/walletexcept.h"

#include <boost/optional.hpp>

#include <iterator>
#include <stdexcept>
#include <utility>
#include <vector>

namespace exodus {

SigmaWallet::MintPoolEntry::MintPoolEntry()
{
}

SigmaWallet::MintPoolEntry::MintPoolEntry(SigmaPublicKey const &key, CKeyID const &seedId, uint32_t index)
    : key(key), seedId(seedId), index(index)
{
}

bool SigmaWallet::MintPoolEntry::operator==(MintPoolEntry const &another) const
{
    return key == another.key &&
        seedId == another.seedId &&
        index == another.index;
}

bool SigmaWallet::MintPoolEntry::operator!=(MintPoolEntry const &another) const
{
    return !(*this == another);
}

SigmaWallet::SigmaWallet() : walletFile(pwalletMain->strWalletFile)
{
}

void SigmaWallet::ReloadMasterKey()
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

    // Clean up any mint entries that aren't corresponded to current masterId
    RemoveInvalidMintPoolEntries();

    // Refill mint pool
    FillMintPool();
}

uint32_t SigmaWallet::GenerateNewSeed(CKeyID &seedId, uint512 &seed)
{
    LOCK(pwalletMain->cs_wallet);
    seedId = pwalletMain->GenerateNewKey(ChangeIndex()).GetID();
    return GenerateSeed(seedId, seed);
}

uint32_t SigmaWallet::GenerateSeed(CKeyID const &seedId, uint512 &seed)
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

namespace {

uint32_t GetBIP44AddressIndex(std::string const &path)
{
    uint32_t index;
    if (sscanf(path.data(), "m/44'/%*u'/%*u'/%*u/%u", &index) != 1) {
        throw std::runtime_error("Fail to match BIP44 path");
    }

    return index;
}

}

uint32_t SigmaWallet::GetSeedIndex(CKeyID const &seedId)
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

// Mint Updating
void SigmaWallet::WriteMint(SigmaMintId const &id, SigmaMint const &mint)
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

SigmaPrivateKey SigmaWallet::GeneratePrivateKey(CKeyID const &seedId)
{
    uint512 seed;

    GenerateSeed(seedId, seed);
    return GeneratePrivateKey(seed);
}

SigmaMintId SigmaWallet::GenerateMint(PropertyId property, SigmaDenomination denom, boost::optional<CKeyID> seedId)
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

SigmaMint SigmaWallet::UpdateMint(SigmaMintId const &id, std::function<void(SigmaMint &)> const &modifier)
{
    auto m = GetMint(id);
    modifier(m);

    if (!WriteExodusMint(id, m)) {
        throw std::runtime_error("fail to update mint");
    }

    return m;
}

void SigmaWallet::ClearMintsChainState()
{
    CWalletDB db(walletFile);
    std::vector<std::pair<SigmaMintId, SigmaMint>> mints;

    db.TxnBegin();

    ListMints(std::back_inserter(mints), &db);

    for (auto &m : mints) {
        m.second.chainState = SigmaMintChainState();
        m.second.spendTx = uint256();

        if (!WriteExodusMint(m.first, m.second, &db)) {
            throw std::runtime_error("Failed to write " + walletFile);
        }
    }

    db.TxnCommit();
}

bool SigmaWallet::TryRecoverMint(
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

bool SigmaWallet::TryRecoverMint(
    SigmaMintId const &id,
    SigmaMintChainState const &chainState)
{
    return TryRecoverMint(id, chainState, uint256());
}

void SigmaWallet::UpdateMintCreatedTx(const SigmaMintId& id, const uint256& tx)
{
    UpdateMint(id, [&](SigmaMint& m) {
        m.createdTx = tx;
    });
}

void SigmaWallet::UpdateMintChainstate(SigmaMintId const &id, SigmaMintChainState const &state)
{
    UpdateMint(id, [&](SigmaMint &m) {
        m.chainState = state;
    });
}

void SigmaWallet::UpdateMintSpendTx(SigmaMintId const &id, uint256 const &tx)
{
    UpdateMint(id, [&](SigmaMint &m) {
        m.spendTx = tx;
    });
}

// Mint querying
bool SigmaWallet::HasMint(SigmaMintId const &id) const
{
    return HasExodusMint(id);
}

bool SigmaWallet::HasMint(secp_primitives::Scalar const &serial) const
{
    auto id = GetSerialId(serial);
    return HasExodusMintId(id);
}

SigmaMint SigmaWallet::GetMint(SigmaMintId const &id) const
{
    SigmaMint m;
    if (!ReadExodusMint(id, m)) {
        throw std::runtime_error("fail to read hdmint");
    }

    return m;
}

SigmaMint SigmaWallet::GetMint(secp_primitives::Scalar const &serial) const
{
    return GetMint(GetMintId(serial));
}

SigmaMintId SigmaWallet::GetMintId(secp_primitives::Scalar const &serial) const
{
    SigmaMintId id;
    auto serialHash = GetSerialId(serial);
    if (!ReadExodusMintId(serialHash, id)) {
        throw std::runtime_error("fail to read id");
    }

    return id;
}

// MintPool state
void SigmaWallet::RemoveInvalidMintPoolEntries() // Remove MintPool entry that isn't belong to current masterId.
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

void SigmaWallet::DeleteUnconfirmedMint(SigmaMintId const &id)
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

bool SigmaWallet::IsMintInPool(SigmaPublicKey const &pubKey)
{
    LOCK(pwalletMain->cs_wallet);
    return mintPool.get<1>().count(pubKey);
}

bool SigmaWallet::GetMintPoolEntry(SigmaPublicKey const &pubKey, MintPoolEntry &entry)
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

// Generate coins to mint pool until amount of coins in mint pool touch the expected amount.
size_t SigmaWallet::FillMintPool()
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

void SigmaWallet::LoadMintPool()
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

void SigmaWallet::SaveMintPool()
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

bool SigmaWallet::RemoveFromMintPool(SigmaPublicKey const &publicKey)
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

// Helper
std::unique_ptr<CWalletDB> SigmaWallet::EnsureDBConnection(CWalletDB* &db) const
{
    std::unique_ptr<CWalletDB> local;
    if (db == nullptr)
    {
        db = new CWalletDB(walletFile);
        local.reset(db);
    }

    return local;
}

} // exodus
