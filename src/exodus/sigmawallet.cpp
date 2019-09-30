// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sigmawallet.h"

#include "exodus.h"

#include "../crypto/hmac_sha256.h"
#include "../crypto/hmac_sha512.h"
#include "../sigma/openssl_context.h"

#include <regex>
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

SigmaWallet::SigmaWallet() : walletFile(pwalletMain->strWalletFile)
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
    const std::regex re(R"delim(^m/44'/\d+'/\d+'/\d+/(\d+)$)delim");

    std::smatch match;
    if (!std::regex_match(path, match, re)) {
        throw std::runtime_error("Fail to match BIP44 path");
    }

    auto child = std::stol(match.str(1));
    if (child > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("Address index is exceed limit");
    }

    return child;
}

secp_primitives::Scalar GetSerialFromPublicKey(
    secp256k1_context const *context,
    secp256k1_pubkey *pubkey)
{
    std::array<uint8_t, 32> pubkey_hash;

    static const unsigned char one[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };

    if (!secp256k1_ecdh(context, pubkey_hash.data(), pubkey, &one[0])) {
        throw std::runtime_error("Unable to compute public key hash with secp256k1_ecdh.");
    }

    std::string zpts(ZEROCOIN_PUBLICKEY_TO_SERIALNUMBER);
    std::array<uint8_t, sizeof(ZEROCOIN_PUBLICKEY_TO_SERIALNUMBER) - 1 +
        std::tuple_size<typeof(pubkey_hash)>::value> pre;

    auto ptr = std::copy(
        reinterpret_cast<unsigned char const*>(zpts.data()),
        reinterpret_cast<unsigned char const*>(zpts.data() + zpts.size()),
        pre.data()
    );

    std::copy(pubkey_hash.begin(), pubkey_hash.end(), ptr);

    std::array<unsigned char, CSHA256::OUTPUT_SIZE>  hash;
    CSHA256().Write(pre.data(), pre.size()).Finalize(hash.data());

    return Scalar(hash.data());
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

bool SigmaWallet::GeneratePrivateKey(
    const uint512& seed, exodus::SigmaPrivateKey& coin)
{
    //convert state seed into a seed for the private key
    uint256 privkey = seed.trim256();
    privkey = Hash(privkey.begin(), privkey.end());

    // Create a key pair
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(OpenSSLContext::get_context(), &pubkey, privkey.begin())) {
        return false;
    }

    // Hash the public key in the group to obtain a serial number
    auto serial = GetSerialFromPublicKey(OpenSSLContext::get_context(), &pubkey);

    //hash randomness seed with Bottom 256 bits of seedZerocoin
    Scalar randomness;
    auto randomnessSeed = ArithToUint512(UintToArith512(seed) >> 256).trim256();
    randomness.memberFromSeed(randomnessSeed.begin());

    coin.serial = serial;
    coin.randomness = randomness;

    return true;
}

// Mint Updating
void SigmaWallet::WriteMint(SigmaMintId const &id, SigmaMint const &mint)
{
    bool isNew = false;

    CWalletDB walletdb(walletFile);

    if (!walletdb.WriteExodusHDMint(id, mint)) {
        throw std::runtime_error("fail to write hdmint");
    }

    if (!walletdb.WriteExodusMintID(mint.serialId, id)) {
        throw std::runtime_error("fail to record id");
    }

    RemoveFromMintPool(id.pubKey);
    GenerateMintPool();
}

SigmaPrivateKey SigmaWallet::GeneratePrivateKey(CKeyID const &seedId)
{
    uint512 seed;
    SigmaPrivateKey priv;

    GenerateSeed(seedId, seed);
    if (!GeneratePrivateKey(seed, priv)) {
        throw std::runtime_error("fail to generate private key from seed");
    }

    return priv;
}

std::pair<SigmaMint, SigmaPrivateKey> SigmaWallet::GenerateMint(
    uint32_t propertyId,
    uint8_t denomination,
    boost::optional<CKeyID> seedId)
{
    if (seedId == boost::none) {

        if (mintPool.empty()) {
            throw std::runtime_error("unable to generate mint");
        }

        seedId = mintPool.front().seedId;
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

    if (!walletdb.WriteExodusHDMint(id, m)) {
        throw std::runtime_error("fail to update mint");
    }

    return m;
}

void SigmaWallet::ClearMintsChainState()
{
    try {
        CWalletDB walletdb(walletFile);

        std::vector<SigmaMint> coins;
        ListMints(std::back_inserter(coins), false, false);

        for (auto &coin : coins) {
            coin.chainState = SigmaMintChainState();
            coin.spendTx = uint256();

            auto priv = GeneratePrivateKey(coin.seedId);
            SigmaPublicKey pub(priv, DefaultSigmaParams);

            if (!walletdb.WriteExodusHDMint(
                SigmaMintId(coin.property, coin.denomination, pub), coin)) {

               throw std::runtime_error("fail to update hdmint");
            }
        }

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

    uint512 seed;
    GenerateSeed(seedId, seed);

    SigmaPrivateKey coin;
    if (!GeneratePrivateKey(seed, coin)) {
        return false;
    }

    serialId = GetSerialId(coin.serial);

    // Create mint object
    SigmaMint mint(
        propertyId,
        denomination,
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
    if (!CountInMintPool(id.pubKey)) {
        return false;
    }

    MintPoolEntry entry;
    if (!GetMintPoolEntry(id.pubKey, entry)) {
        return error("%s : Fail to get mint pool entry from public key\n", __func__);
    }

    return SetMintSeedSeen(entry, id.property, id.denomination, chainState, uint256());
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
    std::function<void(SigmaMint const&)> const &f) const
{
    CWalletDB walletdb(walletFile);

    size_t counter = 0;
    walletdb.ListExodusHDMints<SigmaMintId, SigmaMint>([&](SigmaMint const &m) {
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
        if (!GeneratePrivateKey(seed, coin)) {
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
