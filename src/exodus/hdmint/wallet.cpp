// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet.h"

#include "../exodus.h"

#include "../../main.h"
#include "../../init.h"

#include "../../sigma/openssl_context.h"
#include "../../crypto/hmac_sha256.h"
#include "../../crypto/hmac_sha512.h"

#include <boost/optional.hpp>

namespace exodus
{

HDMintWallet::HDMintWallet(const std::string& walletFile) : walletFile(walletFile)
{
    //Don't try to do anything else if the wallet is locked.
    if (pwalletMain->IsLocked()) {
        return;
    }

    // Use MasterKeyId from HDChain as index for mintpool
    auto hashSeedMaster = pwalletMain->GetHDChain().masterKeyID;
    LogPrintf("hashSeedMaster: %d\n", hashSeedMaster.GetHex());

    if (!SetupWallet(hashSeedMaster)) {
        LogPrintf("%s: failed to save deterministic seed for hashseed %s\n", __func__, hashSeedMaster.GetHex());
        throw std::runtime_error("fail to setup wallet");
    }

    if (!LoadMintPoolFromDB()) {
        throw std::runtime_error("fail to load mint pool from DB");
    }
}

bool HDMintWallet::SetupWallet(const uint160& hashSeedMaster, bool resetCount)
{
    LOCK(pwalletMain->cs_wallet);
    CWalletDB walletdb(walletFile);

    if (pwalletMain->IsLocked()) {
        return false;
    }

    if (hashSeedMaster.IsNull()) {
        return error("%s: failed to set master seed.", __func__);
    }

    this->hashSeedMaster = hashSeedMaster;

    countNextUse = COUNT_DEFAULT;
    countNextGenerate = COUNT_DEFAULT;

    if (resetCount) {

        walletdb.WriteExodusMintCount(countNextUse);
        walletdb.WriteExodusMintSeedCount(countNextGenerate);
    } else {

        if (!walletdb.ReadExodusMintCount(countNextUse)) {
            countNextUse = COUNT_DEFAULT;
        }

        if (!walletdb.ReadExodusMintSeedCount(countNextGenerate)) {
            countNextGenerate = COUNT_DEFAULT;
        }
    }

    return true;
}

std::pair<uint256, uint160> HDMintWallet::RegenerateMintPoolEntry(
    const uint160& mintHashSeedMaster, CKeyID& seedId, const int32_t& count)
{
    LOCK(pwalletMain->cs_wallet);

    CWalletDB walletdb(walletFile);
    if (pwalletMain->IsLocked()) {
        throw std::runtime_error("Error: Please enter the wallet passphrase with walletpassphrase first.");
    }

    uint512 seed;
    if (!CreateZerocoinSeed(seed, count, seedId, false)) {
        throw std::runtime_error("Unable to create seed for mint regeneration.");
    }

    GroupElement commitment;
    exodus::SigmaPrivateKey coin;
    if (!SeedToZerocoin(seed, commitment, coin)) {
        throw std::runtime_error("Unable to create zerocoin from seed in mint regeneration.");
    }

    auto hashPubcoin = primitives::GetPubCoinValueHash(commitment);
    auto hashSerial = primitives::GetSerialHash160(coin.GetSerial());

    MintPoolEntry mintPoolEntry(mintHashSeedMaster, seedId, count);
    mintPool.Add(make_pair(hashPubcoin, mintPoolEntry));

    if (!CWalletDB(walletFile).WriteExodusPubcoin(hashSerial, commitment)) {
        throw std::runtime_error("fail to store pubcoin");
    }

    if (!CWalletDB(walletFile).WriteExodusMintPoolPair(hashPubcoin, mintPoolEntry)) {
        throw std::runtime_error("fail to store mint pool");
    }

    LogPrintf("%s : hashSeedMaster=%s hashPubcoin=%s seedId=%s\n count=%d\n",
        __func__, hashSeedMaster.GetHex(), hashPubcoin.GetHex(), seedId.GetHex(), count);

    return {hashPubcoin, hashSerial};
}

// Add up to index + 20 new mints to the mint pool (defaults to adding 20 mints if no param passed)
void HDMintWallet::GenerateMintPool(int32_t index)
{
    LOCK(pwalletMain->cs_wallet);

    CWalletDB walletdb(walletFile);

    // Is locked
    if (pwalletMain->IsLocked())
        return;

    // Only generate new values (ie. if last generated less than or the same, proceed)
    if (index == 0 && countNextGenerate > countNextUse) {
        return;
    }

    auto start = countNextGenerate;
    auto stop = std::max(start + 20, index);

    LogPrintf("%s : start=%d stop=%d\n", __func__, start, stop);
    for (; start <= stop; ++start) {

        if (ShutdownRequested()) {
            return;
        }

        CKeyID seedId;
        uint512 seed;
        if (!CreateZerocoinSeed(seed, start, seedId)) {
            continue;
        }

        GroupElement commitment;
        exodus::SigmaPrivateKey coin;
        if (!SeedToZerocoin(seed, commitment, coin)) {
            continue;
        }

        auto hashPubcoin = primitives::GetPubCoinValueHash(commitment);

        MintPoolEntry entry(hashSeedMaster, seedId, start);
        mintPool.Add(make_pair(hashPubcoin, entry));

        if (!CWalletDB(walletFile).WriteExodusPubcoin(primitives::GetSerialHash160(coin.GetSerial()), commitment)) {
            throw std::runtime_error("fail to store public key");
        }

        if (!CWalletDB(walletFile).WriteExodusMintPoolPair(hashPubcoin, entry)) {
            throw std::runtime_error("fail to store mint pool data");
        }

        LogPrintf("%s : hashSeedMaster=%s hashPubcoin=%s seedId=%d count=%d\n",
            __func__, hashSeedMaster.GetHex(), hashPubcoin.GetHex(), seedId.GetHex(), start);
    }

    // Update local + DB entries for count last generated
    countNextGenerate = start;
    if (!walletdb.WriteExodusMintSeedCount(countNextGenerate)) {
        throw std::runtime_error("fail to store mint seed count");
    }
}

bool HDMintWallet::LoadMintPoolFromDB()
{
    LOCK(pwalletMain->cs_wallet);
    mintPool.clear();

    std::vector<std::pair<uint256, MintPoolEntry>> listMintPool =
        CWalletDB(walletFile).ListExodusMintPool();

    for (auto const &mintPoolPair : listMintPool) {

        LogPrintf("%s : hashPubcoin: %d hashSeedMaster: %d seedId: %d count: %s\n",
            __func__,
            mintPoolPair.first.GetHex(),
            std::get<0>(mintPoolPair.second).GetHex(),
            std::get<1>(mintPoolPair.second).GetHex(),
            std::get<2>(mintPoolPair.second)
        );

        mintPool.Add(mintPoolPair);
    }

    return true;
}

bool HDMintWallet::SetMintSeedSeen(
    std::pair<uint256, MintPoolEntry> const &mintPoolEntryPair,
    uint32_t propertyId,
    uint8_t denomination,
    exodus::SigmaMintChainState const &chainState,
    uint256 const &spendTx)
{
    // Regenerate the mint
    auto hashPubcoin = mintPoolEntryPair.first;
    auto seedId = std::get<1>(mintPoolEntryPair.second);
    auto mintCount = std::get<2>(mintPoolEntryPair.second);

    GroupElement commitment;
    uint160 hashSerial;

    // Can regenerate if unlocked (cheaper)
    if (!pwalletMain->IsLocked()) {

        uint512 seedZerocoin;
        if (!CreateZerocoinSeed(seedZerocoin, mintCount, seedId, false)) {
            return false;
        }

        SigmaPrivateKey coin;
        if (!SeedToZerocoin(seedZerocoin, commitment, coin)) {
            return false;
        }

        hashSerial = primitives::GetSerialHash160(coin.GetSerial());
    } else {

        // Get serial and pubcoin data from the db
        CWalletDB walletdb(walletFile);
        auto serialPubcoinPairs = walletdb.ListExodusSerialPubcoinPairs();
        bool found = false;

        for (auto const &serialPubcoinPair : serialPubcoinPairs) {

            GroupElement pubcoin = serialPubcoinPair.second;
            if (hashPubcoin == primitives::GetPubCoinValueHash(pubcoin)) {

                commitment = pubcoin;
                hashSerial = serialPubcoinPair.first;
                found = true;
                break;
            }
        }

        if (!found) {
            return false;
        }
    }

    // Create mint object
    SigmaPublicKey k;
    k.SetCommitment(commitment);

    HDMint mint(SigmaMintId(propertyId, denomination, k), mintCount, seedId, hashSerial);
    mint.chainState = chainState;
    mint.spendTx = spendTx;

    // Add to tracker which also adds to database
    Record(mint);

    // Remove from mint pool
    auto it = mintPool.find(hashPubcoin);
    if (it != mintPool.end()) {
        mintPool.erase(it);
        GenerateMintPool(countNextGenerate + 1);
    }

    return true;
}

bool HDMintWallet::SeedToZerocoin(
    const uint512& seedZerocoin, GroupElement& commitment, exodus::SigmaPrivateKey& coin)
{
    //convert state seed into a seed for the private key
    uint256 nSeedPrivKey = seedZerocoin.trim256();
    nSeedPrivKey = Hash(nSeedPrivKey.begin(), nSeedPrivKey.end());

    // generate serial and randomness
    sigma::PrivateCoin priv(sigma::Params::get_default(), sigma::CoinDenomination::SIGMA_DENOM_1);
    priv.setEcdsaSeckey(nSeedPrivKey);

    // Create a key pair
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(OpenSSLContext::get_context(), &pubkey, priv.getEcdsaSeckey())){
        return false;
    }

    // Hash the public key in the group to obtain a serial number
    auto serialNumber = priv.serialNumberFromSerializedPublicKey(OpenSSLContext::get_context(), &pubkey);

    //hash randomness seed with Bottom 256 bits of seedZerocoin
    Scalar randomness;
    auto randomnessSeed = ArithToUint512(UintToArith512(seedZerocoin) >> 256).trim256();
    randomness.memberFromSeed(randomnessSeed.begin());

    coin.SetSerial(serialNumber);
    coin.SetRandomness(randomness);

    commitment = exodus::SigmaPublicKey(coin).GetCommitment();

    return true;
}

CKeyID HDMintWallet::GetZerocoinSeedID(int32_t count)
{
    // Get CKeyID for n from mintpool
    std::pair<uint256, MintPoolEntry> mintPoolEntryPair;

    if (!mintPool.Get(count, hashSeedMaster, mintPoolEntryPair)) {

        // Add up to mintPool index + 20
        GenerateMintPool(count);
        if (!mintPool.Get(count, hashSeedMaster, mintPoolEntryPair)) {

            ResetCount();
            throw std::runtime_error("Unable to retrieve mint seed ID");
        }
    }

    return std::get<1>(mintPoolEntryPair.second);
}

bool HDMintWallet::CreateZerocoinSeed(uint512& seedZerocoin, int32_t n, CKeyID& seedId, bool checkIndex)
{
    LOCK(pwalletMain->cs_wallet);
    CKey key;

    // Ensures value of child index is valid for seed being generated
    if (checkIndex) {
        if (n < pwalletMain->GetHDChain().nExternalChainCounters[BIP44_EXODUS_MINT_INDEX]) {
            // The only scenario where this can occur is if the counter in wallet did not correctly catch up with the chain during a resync.
            return false;
        }
    }

    // if passed seedId, we assume generation of seed has occured.
    // Otherwise get new key to be used as seed
    if (seedId.IsNull()) {
        auto pubKey = pwalletMain->GenerateNewKey(BIP44_EXODUS_MINT_INDEX);
        seedId = pubKey.GetID();
    }

    if (!pwalletMain->CCryptoKeyStore::GetKey(seedId, key)) {
        ResetCount();
        throw std::runtime_error("Unable to retrieve generated key for mint seed. Is the wallet locked?");
    }

    // HMAC-SHA512(SHA256(count), key)
    unsigned char countHash[CSHA256().OUTPUT_SIZE];
    std::vector<unsigned char> result(CSHA512().OUTPUT_SIZE);

    auto count = std::to_string(n);
    CSHA256().Write(reinterpret_cast<const unsigned char*>(count.data()), count.size()).Finalize(countHash);

    CHMAC_SHA512(countHash, CSHA256().OUTPUT_SIZE).Write(key.begin(), key.size()).Finalize(&result[0]);

    seedZerocoin = uint512(result);

    return true;
}

int32_t HDMintWallet::GetCount()
{
    return countNextUse;
}

void HDMintWallet::ResetCount()
{
    LOCK(pwalletMain->cs_wallet);
    CWalletDB walletdb(walletFile);
    if (!walletdb.ReadExodusMintCount(countNextUse)) {
        throw std::runtime_error("fail to reset count");
    }
}

void HDMintWallet::SetCount(int32_t count)
{
    countNextUse = count;
}

void HDMintWallet::UpdateCountLocal()
{
    countNextUse++;
    LogPrintf("%s : Updating count local to %s\n", __func__, countNextUse);
}

void HDMintWallet::UpdateCountDB()
{
    LogPrintf("%s : Updating count in DB to %s\n", __func__, countNextUse);

    LOCK(pwalletMain->cs_wallet);
    CWalletDB walletdb(walletFile);

    if (!walletdb.WriteExodusMintCount(countNextUse)) {
        throw std::runtime_error("fail to store next count to use to db");
    }

    GenerateMintPool();
}

void HDMintWallet::UpdateCount()
{
    UpdateCountLocal();
    UpdateCountDB();
}

size_t HDMintWallet::ListHDMints(
    std::function<void(HDMint &)> const &f, bool unusedOnly, bool matureOnly) const
{
    LOCK(pwalletMain->cs_wallet);
    CWalletDB walletdb(walletFile);

    size_t counter = 0;
    walletdb.ListExodusHDMints<SigmaMintId, HDMint>([&](HDMint &m) {
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

void HDMintWallet::ResetCoinsState()
{
    try {
        CWalletDB walletdb(walletFile);

        ListHDMints([&walletdb](HDMint &m) {

            m.chainState = SigmaMintChainState();
            m.spendTx = uint256();

            if (!walletdb.WriteExodusHDMint(m.id, m)) {
               throw std::runtime_error("fail to update hdmint");
            }

        }, false, false);
    } catch (std::runtime_error const &e) {
        LogPrintf("%s : fail to reset all mints chain state, %s\n", __func__, e.what());
        throw;
    }

    if (!LoadMintPoolFromDB()) {
        LogPrintf("%s : fail to reload mint pool after reset all mint chain state\n");
    }
}

bool HDMintWallet::GenerateMint(
    uint32_t propertyId,
    uint8_t denomination,
    SigmaPrivateKey& coin,
    HDMint& mint,
    boost::optional<MintPoolEntry> mintPoolEntry)
{
    if (mintPoolEntry == boost::none) {
        if(hashSeedMaster.IsNull())
            throw std::runtime_error("unable to generate mint: HashSeedMaster not set");

        auto seedId = GetZerocoinSeedID(countNextUse);
        mintPoolEntry = MintPoolEntry(hashSeedMaster, seedId, countNextUse);

        // Empty mintPoolEntry implies this is a new mint being created, so update countNextUse
        UpdateCount();
    }

    LogPrintf("%s: hashSeedMaster: %s seedId: %s count: %d\n",
        __func__,
        std::get<0>(mintPoolEntry.get()).GetHex(),
        std::get<1>(mintPoolEntry.get()).GetHex(),
        std::get<2>(mintPoolEntry.get()));

    uint512 seedZerocoin;
    if (!CreateZerocoinSeed(seedZerocoin, std::get<2>(mintPoolEntry.get()), std::get<1>(mintPoolEntry.get()), false)) {
        return false;
    }

    GroupElement commitment;
    if (!SeedToZerocoin(seedZerocoin, commitment, coin)) {
        return false;
    }

    SigmaPublicKey key;
    key.SetCommitment(commitment);
    auto serialHash = primitives::GetSerialHash160(coin.GetSerial());
    mint = HDMint(
        SigmaMintId(propertyId, denomination, key),
        std::get<2>(mintPoolEntry.get()),
        std::get<1>(mintPoolEntry.get()),
        serialHash);

    // erase from mempool
    auto pubCoinHash = primitives::GetPubCoinValueHash(commitment);
    auto it = mintPool.find(pubCoinHash);
    if (it != mintPool.end()) {
        mintPool.erase(it);
    }

    LogPrintf("%s: hashPubcoin: %s\n", __func__, pubCoinHash.ToString());

    return true;
}

bool HDMintWallet::RegenerateMint(const HDMint& mint, SigmaPrivateKey &privKey)
{
    HDMint dummyMint;

    MintPoolEntry mintPoolEntry(hashSeedMaster, mint.seedId, mint.count);
    GenerateMint(mint.id.property, mint.id.denomination, privKey, dummyMint, mintPoolEntry);

    //Fill in the zerocoinmint object's details
    exodus::SigmaPublicKey pubKey(privKey);
    if (pubKey.GetCommitment() != mint.id.key.GetCommitment()) {
        return error("%s: failed to correctly generate mint, pubcoin hash mismatch", __func__);
    }

    auto &serial = privKey.GetSerial();
    if (primitives::GetSerialHash160(serial) != mint.hashSerial) {
        return error("%s: failed to correctly generate mint, serial hash mismatch", __func__);
    }

    return true;
}

bool HDMintWallet::HasMint(SigmaMintId const &id) const
{
    CWalletDB walletdb(walletFile);
    return walletdb.HasExodusHDMint(id);
}

bool HDMintWallet::HasSerial(secp_primitives::Scalar const &scalar) const
{
    CWalletDB walletdb(walletFile);
    auto serialHash = primitives::GetSerialHash160(scalar);
    return walletdb.HasExodusMintID(serialHash);
}

HDMint HDMintWallet::GetMint(SigmaMintId const &id) const
{
    CWalletDB walletdb(walletFile);
    HDMint m;
    if (!walletdb.ReadExodusHDMint(id, m)) {
        throw std::runtime_error("fail to read hdmint");
    }

    return m;
}

HDMint HDMintWallet::GetMint(secp_primitives::Scalar const &serial) const
{
    return GetMint(GetMintId(serial));
}

SigmaMintId HDMintWallet::GetMintId(secp_primitives::Scalar const &serial) const
{
    CWalletDB walletdb(walletFile);

    SigmaMintId id;
    auto serialHash = primitives::GetSerialHash160(serial);
    if (!walletdb.ReadExodusMintID(serialHash, id)) {
        throw std::runtime_error("fail to read id");
    }

    return id;
}

HDMint HDMintWallet::UpdateMint(SigmaMintId const &id, std::function<void(HDMint &)> const &modF)
{
    CWalletDB walletdb(walletFile);
    auto m = GetMint(id);
    modF(m);

    if (!walletdb.WriteExodusHDMint(id, m)) {
        throw std::runtime_error("fail to update mint");
    }

    return m;
}

HDMint HDMintWallet::UpdateMintSpendTx(SigmaMintId const &id, uint256 const &tx)
{
    return UpdateMint(id, [&tx](HDMint &m) {
        m.spendTx = tx;
    });
}

HDMint HDMintWallet::UpdateMintChainstate(SigmaMintId const &id, SigmaMintChainState const &state)
{
    return UpdateMint(id, [&state](HDMint &m) {
        m.chainState = state;
    });
}

void HDMintWallet::Record(const HDMint& mint)
{
    CWalletDB walletdb(walletFile);
    if (!walletdb.WriteExodusHDMint(mint.id, mint)) {
        throw std::runtime_error("fail to write hdmint");
    }

    if (!walletdb.WriteExodusMintID(mint.hashSerial, mint.id)) {
        throw std::runtime_error("fail to record id");
    }
}

}; // exodus
