// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sigmawallet.h"

#include "exodus.h"

#include "../main.h"
#include "../init.h"

#include "../sigma/openssl_context.h"
#include "../crypto/hmac_sha256.h"
#include "../crypto/hmac_sha512.h"

#include <boost/optional.hpp>

namespace exodus {

MintPoolEntry::MintPoolEntry()
{
}

MintPoolEntry::MintPoolEntry(SigmaPublicKey const &key, CKeyID const &seedId)
    : key(key), seedId(seedId)
{
}

bool MintPoolEntry::operator==(MintPoolEntry const &another) const
{
    return key == another.key && seedId == another.seedId;
}

bool MintPoolEntry::operator!=(MintPoolEntry const &another) const
{
    return !(*this == another);
}

SigmaWallet::SigmaWallet(const std::string& walletFile) : walletFile(walletFile)
{
    ReloadMasterKey();
}

void SigmaWallet::ReloadMasterKey()
{
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
    CleanUp();

    // Refill mint pool
    GenerateMintPool();
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

    // HMAC-SHA512(SHA256(count), key)
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> countHash;

    std::vector<unsigned char> result;
    result.resize(CSHA512::OUTPUT_SIZE);

    auto count = std::to_string(GetSeedIndex(seedId));
    CSHA256().
        Write(
            reinterpret_cast<const unsigned char*>(count.data()),
            count.size()
        ).
        Finalize(countHash.data());

    CHMAC_SHA512(countHash.data(), sizeof(countHash)).
        Write(key.begin(), key.size()).
        Finalize(result.data());

    seed = uint512(result);

    return GetSeedIndex(seedId);
}

bool GetChildFromPath(string const &path, std::pair<uint32_t, bool> &child)
{
    auto startPos = path.find_last_of('/') + 1;
    if (startPos >= path.size()) {
        return false;
    }

    auto childData = path.substr(startPos);

    auto isHardened = childData.back() == '\'';
    if (isHardened) {
        childData.resize(childData.size() - 1);
    }

    if (childData.empty()) {
        return false;
    }

    auto childPos = std::stol(childData);

    if (childPos > std::numeric_limits<uint32_t>::max()) {
        return false;
    }

    child = {static_cast<uint32_t>(childPos), isHardened};

    return true;
}

uint32_t SigmaWallet::GetSeedIndex(CKeyID const &seedId)
{
    if (!pwalletMain->mapKeyMetadata.count(seedId)) {
        throw std::runtime_error("key not found");
    }

    auto const &meta = pwalletMain->mapKeyMetadata[seedId];

    // parse last index
    std::pair<uint32_t, bool> child;
    if (!GetChildFromPath(meta.hdKeypath, child)) {
        throw std::runtime_error("fail to parse HD key path");
    }

    if (child.second) {
        throw std::runtime_error("hardened is not allowed");
    }

    return child.first;
}

bool SigmaWallet::SeedToPrivateKey(
    const uint512& seedZerocoin, exodus::SigmaPrivateKey& coin)
{
    //convert state seed into a seed for the private key
    uint256 nSeedPrivKey = seedZerocoin.trim256();
    nSeedPrivKey = Hash(nSeedPrivKey.begin(), nSeedPrivKey.end());

    // generate serial and randomness
    sigma::PrivateCoin priv(sigma::Params::get_default(), sigma::CoinDenomination::SIGMA_DENOM_1);
    priv.setEcdsaSeckey(nSeedPrivKey);

    // Create a key pair
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(OpenSSLContext::get_context(), &pubkey, priv.getEcdsaSeckey())) {
        return false;
    }

    // Hash the public key in the group to obtain a serial number
    auto serialNumber = priv.serialNumberFromSerializedPublicKey(OpenSSLContext::get_context(), &pubkey);

    //hash randomness seed with Bottom 256 bits of seedZerocoin
    Scalar randomness;
    auto randomnessSeed = ArithToUint512(UintToArith512(seedZerocoin) >> 256).trim256();
    randomness.memberFromSeed(randomnessSeed.begin());

    coin.serial = serialNumber;
    coin.randomness = randomness;

    return true;
}

// Mint Updating
bool SigmaWallet::AddToWallet(const SigmaMint& mint)
{
    bool isNew = false;

    CWalletDB walletdb(walletFile);
    SigmaMintId id(
        mint.property,
        mint.denomination,
        SigmaPublicKey(
            GetPrivateKeyFromSeedId(mint.seedId),
            DefaultSigmaParams
        )
    );

    if (!walletdb.HasExodusHDMint(id)) {

        isNew = true;

        if (!walletdb.WriteExodusHDMint(id, mint)) {
            throw std::runtime_error("fail to write hdmint");
        }

        if (!walletdb.WriteExodusMintID(mint.serialId, id)) {
            throw std::runtime_error("fail to record id");
        }
    }

    RemoveFromMintPool(id.pubKey);
    GenerateMintPool();

    return isNew;
}

SigmaPrivateKey SigmaWallet::GetPrivateKeyFromSeedId(CKeyID const &seedId)
{
    uint512 seed;
    SigmaPrivateKey priv;

    GenerateSeed(seedId, seed);
    if (!SeedToPrivateKey(seed, priv)) {
        throw std::runtime_error("fail to generate private key from seed");
    }

    return priv;
}

bool SigmaWallet::GenerateMint(
    uint32_t propertyId,
    uint8_t denomination,
    SigmaPrivateKey& coin,
    SigmaMint& mint,
    boost::optional<MintPoolEntry> mintPoolEntry)
{
    if (mintPoolEntry == boost::none) {

        if (masterId.IsNull()) {
            throw std::runtime_error("unable to generate mint: HashSeedMaster not set");
        }

        mintPoolEntry = mintPool.front();
    }

    LogPrintf("%s: publicKey: %s seedId: %s\n",
        __func__, mintPoolEntry->key.commitment.GetHex(), mintPoolEntry->seedId.GetHex());

    coin = GetPrivateKeyFromSeedId(mintPoolEntry->seedId);

    SigmaPublicKey key(coin, DefaultSigmaParams);
    auto serialId = GetSerialId(coin.serial);
    mint = SigmaMint(
        propertyId,
        denomination,
        mintPoolEntry->seedId,
        serialId
    );

    LogPrintf("%s: pubcoin: %s\n", __func__, key.commitment.GetHex());
    return true;
}

SigmaMint SigmaWallet::UpdateMint(const SigmaMintId &id, const std::function<void(SigmaMint &)> &modifier)
{
    CWalletDB walletdb(walletFile);
    auto m = GetMint(id);
    modifier(m);

    if (!walletdb.WriteExodusHDMint(id, m)) {
        throw std::runtime_error("fail to update mint");
    }

    return m;
}

bool SigmaWallet::RegenerateMint(const SigmaMint& mint, SigmaPrivateKey &privKey)
{
    SigmaMint dummyMint;

    auto priv = GetPrivateKeyFromSeedId(mint.seedId);
    SigmaPublicKey pub(priv, DefaultSigmaParams);

    MintPoolEntry mintPoolEntry(pub, mint.seedId);
    if (!GenerateMint(mint.property, mint.denomination, privKey, dummyMint, mintPoolEntry)) {
        return error("%s: failed to generate mint", __func__);
    }

    // Verify regenered
    exodus::SigmaPublicKey pubKey(privKey, DefaultSigmaParams);
    if (pubKey != pub) {
        return error("%s: failed to correctly generate mint, pubcoin mismatch", __func__);
    }

    if (GetSerialId(privKey.serial) != mint.serialId) {
        return error("%s: failed to correctly generate mint, serial hash mismatch", __func__);
    }

    return true;
}

void SigmaWallet::ResetCoinsState()
{
    try {
        CWalletDB walletdb(walletFile);

        ListMints([&](SigmaMint &m) {

            m.chainState = SigmaMintChainState();
            m.spendTx = uint256();

            auto priv = GetPrivateKeyFromSeedId(m.seedId);
            SigmaPublicKey pub(priv, DefaultSigmaParams);

            if (!walletdb.WriteExodusHDMint(
                SigmaMintId(m.property, m.denomination, pub), m)) {

               throw std::runtime_error("fail to update hdmint");
            }

        }, false, false);

    } catch (std::runtime_error const &e) {
        LogPrintf("%s : fail to reset all mints chain state, %s\n", __func__, e.what());
        throw;
    }
}

bool SigmaWallet::SetMintSeedSeen(
    MintPoolEntry const &mintPoolEntry,
    uint32_t propertyId,
    uint8_t denomination,
    exodus::SigmaMintChainState const &chainState,
    uint256 const &spendTx)
{
    // Regenerate the mint
    auto const &pubcoin = mintPoolEntry.key;
    auto const &seedId = mintPoolEntry.seedId;
    auto seedIndex = GetSeedIndex(seedId);

    SigmaMintId id(propertyId, denomination, pubcoin);

    uint160 serialId;

    // Can regenerate if unlocked (cheaper)
    if (!pwalletMain->IsLocked()) {

        uint512 seed;
        GenerateSeed(seedId, seed);

        SigmaPrivateKey coin;
        if (!SeedToPrivateKey(seed, coin)) {
            return false;
        }

        serialId = GetSerialId(coin.serial);
    } else {

        SigmaMint mint;
        if (!CWalletDB(walletFile).ReadExodusHDMint(id, mint)) {
            return false;
        }

        serialId = mint.serialId;
    }

    // Create mint object
    SigmaMint mint(
        propertyId,
        denomination,
        seedId,
        serialId);
    mint.chainState = chainState;
    mint.spendTx = spendTx;

    AddToWallet(mint);

    return true;
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
    return walletdb.HasExodusHDMint(id);
}

bool SigmaWallet::HasSerial(secp_primitives::Scalar const &scalar) const
{
    CWalletDB walletdb(walletFile);
    auto serialHash = GetSerialId(scalar);
    return walletdb.HasExodusMintID(serialHash);
}

SigmaMint SigmaWallet::GetMint(SigmaMintId const &id) const
{
    CWalletDB walletdb(walletFile);
    SigmaMint m;
    if (!walletdb.ReadExodusHDMint(id, m)) {
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
    std::function<void(SigmaMint &)> const &f, bool unusedOnly, bool matureOnly) const
{
    LOCK(pwalletMain->cs_wallet);
    CWalletDB walletdb(walletFile);

    size_t counter = 0;
    walletdb.ListExodusHDMints<SigmaMintId, SigmaMint>([&](SigmaMint &m) {
        auto used = !m.spendTx.IsNull();
        if (unusedOnly && used) {
            return;
        }

        auto confirmed = m.chainState.block >= 0;
        if (matureOnly && !confirmed) {
            return;
        }

        counter++;
        f(m);
    });

    return counter;
}

// MintPool state

void SigmaWallet::CleanUp()
{
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

size_t SigmaWallet::CountInMintPool(SigmaPublicKey const &pubKey)
{
    return mintPool.get<1>().count(pubKey);
}

bool SigmaWallet::GetMintPoolEntry(SigmaPublicKey const &pubKey, MintPoolEntry &entry)
{
    auto &publicKeyIndex = mintPool.get<1>();
    auto it = publicKeyIndex.find(pubKey);

    if (it == publicKeyIndex.end()) {
        return false;
    }

    entry = *it;
    return true;
}

// Generate coins to mint pool until amount of coins in mint pool touch the expected amount.
size_t SigmaWallet::GenerateMintPool(size_t expectedCoins)
{
    size_t generatedCoins;

    while (mintPool.size() < expectedCoins) {

        CKeyID seedId;
        uint512 seed;
        auto index = GenerateNewSeed(seedId, seed);

        SigmaPrivateKey coin;
        if (!SeedToPrivateKey(seed, coin)) {
            continue;
        }

        SigmaPublicKey publicKey(coin, DefaultSigmaParams);
        mintPool.push_back(MintPoolEntry(publicKey, seedId));

        generatedCoins++;
    }

    if (generatedCoins)  {
        SaveMintPool();
    }

    return generatedCoins;
}

void SigmaWallet::LoadMintPool()
{
    mintPool.clear();

    CWalletDB walletdb(walletFile);

    if (walletdb.HasExodusMintPool()) {

        std::vector<MintPoolEntry> mintPoolData;
        if (!walletdb.ReadExodusMintPool(mintPoolData)) {
            throw std::runtime_error("fail to load mint pool from DB");
        }

        for (auto &entry : mintPoolData) {
            mintPool.push_back(std::move(entry));
        }
    }
}

void SigmaWallet::SaveMintPool()
{
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
    auto &publicKeyIndex = mintPool.get<1>();
    auto it = publicKeyIndex.find(publicKey);

    if (it != publicKeyIndex.end()) {
        publicKeyIndex.erase(it);
        SaveMintPool();
    }

    // publicKey is not in the pool
    return false;
}

}; // exodus
