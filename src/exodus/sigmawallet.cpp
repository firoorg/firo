// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sigmawallet.h"

#include "exodus.h"

#include "../crypto/hmac_sha256.h"
#include "../crypto/hmac_sha512.h"
#include "../sigma/openssl_context.h"

#include <boost/optional.hpp>

namespace exodus {

MintPoolEntry::MintPoolEntry()
{
}

MintPoolEntry::MintPoolEntry(
    SigmaPublicKey const &key, CKeyID const &seedId, uint32_t index)
    : key(key), seedId(seedId), index(index)
{
}

bool MintPoolEntry::operator==(MintPoolEntry const &another) const
{
    return key == another.key &&
        seedId == another.seedId &&
        index == another.index;
}

bool MintPoolEntry::operator!=(MintPoolEntry const &another) const
{
    return !(*this == another);
}

SigmaWallet::SigmaWallet() : walletFile(pwalletMain->strWalletFile)
{
    ReloadMasterKey();
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

    // Clean up any mint entry that isn't corresponded to current masterId
    RemoveInvalidMintPoolEntries();

    // Refill mint pool
    FillMintPool();
}

// Generator
uint32_t SigmaWallet::GenerateNewSeed(CKeyID &seedId, uint512& seed)
{
    LOCK(pwalletMain->cs_wallet);
    seedId = pwalletMain->GenerateNewKey(BIP44_EXODUS_MINT_INDEX).GetID();
    return GenerateSeed(seedId, seed);
}

uint32_t SigmaWallet::GenerateSeed(CKeyID const &seedId, uint512& seed)
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

std::uint32_t GetBIP44AddressIndex(std::string const &path)
{
    auto lastSlash = path.find_last_of('/');
    if (lastSlash == std::string::npos) {
        throw std::runtime_error("Fail to match BIP44 path");
    }

    auto child = std::stol(path.substr(lastSlash + 1));
    if (child > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("Address index is exceed limit");
    }

    return child;
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
        error("%s : fail to get child from, %s\n", __func__, e.what());
        throw;
    }

    return addressIndex;
}

SigmaPrivateKey SigmaWallet::GeneratePrivateKey(const uint512& seed)
{
    SigmaPrivateKey priv;

    // first 32 bytes as seed
    uint256 serialSeed;
    std::copy(seed.begin(), seed.begin() + 32, serialSeed.begin());
    priv.serial.memberFromSeed(serialSeed.begin());

    // last 32 bytes as seed
    uint256 randomnessSeed;
    std::copy(seed.begin() + 32, seed.end(), randomnessSeed.begin());
    priv.randomness.memberFromSeed(randomnessSeed.begin());

    return priv;
}

// Mint Updating
void SigmaWallet::WriteMint(SigmaMintId const &id, SigmaMint const &mint)
{
    CWalletDB walletdb(walletFile);

    if (!walletdb.WriteExodusMint(id, mint)) {
        throw std::runtime_error("fail to write hdmint");
    }

    if (!walletdb.WriteExodusMintID(mint.serialId, id)) {
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

std::pair<SigmaMint, SigmaPrivateKey> SigmaWallet::GenerateMint(
    uint32_t propertyId,
    uint8_t denomination,
    boost::optional<CKeyID> seedId)
{
    LOCK(pwalletMain->cs_wallet);
    if (seedId == boost::none) {

        if (mintPool.empty()) {
            throw std::runtime_error("unable to generate mint");
        }

        seedId = mintPool.begin()->seedId;
    }

    auto privKey = GeneratePrivateKey(seedId.get());

    SigmaPublicKey pubKey(privKey, DefaultSigmaParams);

    LogPrintf("%s: publicKey: %s seedId: %s\n",
        __func__, pubKey.commitment.GetHex(), seedId->GetHex());

    auto serialId = GetSerialId(privKey.serial);
    auto mint = SigmaMint(
        propertyId,
        denomination,
        seedId.get(),
        serialId
    );

    WriteMint(SigmaMintId(propertyId, denomination, pubKey), mint);

    LogPrintf("%s: pubcoin: %s\n", __func__, pubKey.commitment.GetHex());
    return {mint, privKey};
}

SigmaMint SigmaWallet::UpdateMint(const SigmaMintId &id, const std::function<void(SigmaMint &)> &modifier)
{
    CWalletDB walletdb(walletFile);
    auto m = GetMint(id);
    modifier(m);

    if (!walletdb.WriteExodusMint(id, m)) {
        throw std::runtime_error("fail to update mint");
    }

    return m;
}

void SigmaWallet::ClearMintsChainState()
{
    CWalletDB walletdb(walletFile);
    walletdb.TxnBegin();

    std::vector<SigmaMint> mints;
    ListMints(std::back_inserter(mints), &walletdb);

    for (auto &m : mints) {
        m.chainState = SigmaMintChainState();
        m.spendTx = uint256();

        auto priv = GeneratePrivateKey(m.seedId);
        SigmaPublicKey pub(priv, DefaultSigmaParams);

        if (!walletdb.WriteExodusMint(
            SigmaMintId(m.property, m.denomination, pub), m)) {

            throw std::runtime_error("fail to update hdmint");
        }
    }

    walletdb.TxnCommit();
}

bool SigmaWallet::TryRecoverMint(
    SigmaMintId const &id,
    SigmaMintChainState const &chainState,
    uint256 const &spendTx)
{
    LOCK(pwalletMain->cs_wallet);

    if (!IsMintInPool(id.pubKey)) {
        return false;
    }

    MintPoolEntry entry;
    if (!GetMintPoolEntry(id.pubKey, entry)) {
        throw std::runtime_error("Fail to get mint from pool");
    }

    // Regenerate the mint
    auto const &pubcoin = id.pubKey;
    auto const &seedId = entry.seedId;
    auto seedIndex = GetSeedIndex(seedId);

    uint512 seed;
    GenerateSeed(seedId, seed);

    auto coin = GeneratePrivateKey(seed);

    auto serialId = GetSerialId(coin.serial);

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

SigmaMint SigmaWallet::UpdateMintChainstate(SigmaMintId const &id, SigmaMintChainState const &state)
{
    return UpdateMint(id, [&state](SigmaMint &m) {
        m.chainState = state;
    });
}

SigmaMint SigmaWallet::UpdateMintSpendTx(SigmaMintId const &id, uint256 const &tx)
{
    return UpdateMint(id, [&tx](SigmaMint &m) {
        m.spendTx = tx;
    });
}

// Mint querying
bool SigmaWallet::HasMint(SigmaMintId const &id) const
{
    CWalletDB walletdb(walletFile);
    return walletdb.HasExodusMint(id);
}

bool SigmaWallet::HasMint(secp_primitives::Scalar const &serial) const
{
    CWalletDB walletdb(walletFile);
    auto id = GetSerialId(serial);
    return walletdb.HasExodusMintID(id);
}

SigmaMint SigmaWallet::GetMint(SigmaMintId const &id) const
{
    CWalletDB walletdb(walletFile);
    SigmaMint m;
    if (!walletdb.ReadExodusMint(id, m)) {
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
    CWalletDB walletdb(walletFile);

    SigmaMintId id;
    auto serialHash = GetSerialId(serial);
    if (!walletdb.ReadExodusMintID(serialHash, id)) {
        throw std::runtime_error("fail to read id");
    }

    return id;
}

size_t SigmaWallet::ListMints(
    std::function<void(SigmaMint const&)> const &f, CWalletDB* db) const
{
    std::unique_ptr<CWalletDB> localDB;
    if (!db) {
        db = new CWalletDB(walletFile);
        localDB.reset(db);
    }

    size_t counter = 0;
    db->ListExodusMints<SigmaMintId, SigmaMint>([&](SigmaMint const &m) {
        counter++;
        f(m);
    });

    return counter;
}

// MintPool state

void SigmaWallet::RemoveInvalidMintPoolEntries()
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
    CWalletDB walletdb(walletFile);
    SigmaMint mint;
    if (!walletdb.ReadExodusMint(id, mint)) {
        throw std::runtime_error("no mint data in wallet");
    }

    if (mint.IsOnChain()) {
        throw std::invalid_argument("try to delete onchain mint");
    }

    SigmaPublicKey pubKey(GeneratePrivateKey(mint.seedId), DefaultSigmaParams);

    auto index = GetSeedIndex(mint.seedId);
    mintPool.emplace(pubKey, mint.seedId, index);
    SaveMintPool();

    if (!walletdb.EraseExodusMint(id)) {
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

    size_t generatedCoins;
    while (mintPool.size() < MintPoolCapacity) {

        CKeyID seedId;
        uint512 seed;

        auto index = GenerateNewSeed(seedId, seed);
        auto privKey = GeneratePrivateKey(seed);

        SigmaPublicKey pubKey(privKey, DefaultSigmaParams);
        mintPool.emplace(pubKey, seedId, index);

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

    CWalletDB walletdb(walletFile);

    std::vector<MintPoolEntry> mintPoolData;
    if (walletdb.ReadExodusMintPool(mintPoolData)) {
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

    if (!CWalletDB(walletFile).WriteExodusMintPool(mintPoolData)) {
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

} // exodus
