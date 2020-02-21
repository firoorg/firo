// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sigmawalletv1.h"

#include "../libzerocoin/Zerocoin.h"
#include "../sigma/openssl_context.h"
#include "../wallet/wallet.h"

namespace elysium {

SigmaWalletV1::SigmaWalletV1() : SigmaWallet()
{
}

bool SigmaWalletV1::GeneratePublicKey(ECDSAPrivateKey const &priv, secp256k1_pubkey &out)
{
    return secp256k1_ec_pubkey_create(
        OpenSSLContext::get_context(),
        &out,
        priv.data());
}

void SigmaWalletV1::GenerateSerial(secp256k1_pubkey const &pubkey, secp_primitives::Scalar &serial)
{
    std::array<uint8_t, 33> compressedPub;

    size_t outSize = sizeof(compressedPub);
    secp256k1_ec_pubkey_serialize(
        OpenSSLContext::get_context(),
        compressedPub.begin(),
        &outSize,
        &pubkey,
        SECP256K1_EC_COMPRESSED);

    if (outSize != 33) {
        throw std::runtime_error("Compressed public key size is invalid.");
    }

    std::array<uint8_t, CSHA256::OUTPUT_SIZE> hash;
    CSHA256().Write(compressedPub.begin(), sizeof(compressedPub)).Finalize(hash.data());

    serial.memberFromSeed(hash.begin());
}

uint32_t SigmaWalletV1::ChangeIndex()
{
    return BIP44_ELYSIUM_MINTV1_INDEX;
}

SigmaPrivateKey SigmaWalletV1::GeneratePrivateKey(uint512 const &seed)
{
    std::array<uint8_t, 32> ecdsaKeyOut;
    return GeneratePrivateKey(seed, ecdsaKeyOut);
}

SigmaPrivateKey SigmaWalletV1::GeneratePrivateKey(
    uint512 const &seed, ECDSAPrivateKey &ecdsaKeyOut)
{
    // first 32 bytes as seed of ecdsa key and serial
    std::array<uint8_t, 32> tmp;
    std::copy(seed.begin(), seed.begin() + 32, ecdsaKeyOut.begin());

    // hash until get valid private key
    secp256k1_pubkey pubkey;
    do {
        std::copy(ecdsaKeyOut.begin(), ecdsaKeyOut.end(), tmp.begin());
        CSHA256().Write(tmp.begin(), tmp.size()).Finalize(ecdsaKeyOut.begin());
    } while(!GeneratePublicKey(ecdsaKeyOut, pubkey));

    secp_primitives::Scalar serial;
    GenerateSerial(pubkey, serial);

    // last 32 bytes as seed of randomness
    std::array<uint8_t, 32> randomnessSeed;
    std::copy(seed.begin() + 32, seed.end(), randomnessSeed.data());
    secp_primitives::Scalar randomness;
    randomness.memberFromSeed(randomnessSeed.begin());

    return SigmaPrivateKey(serial, randomness);
}

bool SigmaWalletV1::WriteExodusMint(SigmaMintId const &id, SigmaMint const &mint, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->WriteExodusMintV1(id, mint);
}

bool SigmaWalletV1::ReadExodusMint(SigmaMintId const &id, SigmaMint &mint, CWalletDB *db) const
{
    auto local = EnsureDBConnection(db);
    return db->ReadExodusMintV1(id, mint);
}

bool SigmaWalletV1::EraseExodusMint(SigmaMintId const &id, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->EraseExodusMintV1(id);
}

bool SigmaWalletV1::HasExodusMint(SigmaMintId const &id, CWalletDB *db) const
{
    auto local = EnsureDBConnection(db);
    return db->HasExodusMintV1(id);
}

bool SigmaWalletV1::WriteExodusMintId(uint160 const &hash, SigmaMintId const &mintId, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->WriteExodusMintIDV1(hash, mintId);
}

bool SigmaWalletV1::ReadExodusMintId(uint160 const &hash, SigmaMintId &mintId, CWalletDB *db) const
{
    auto local = EnsureDBConnection(db);
    return db->ReadExodusMintIDV1(hash, mintId);
}

bool SigmaWalletV1::EraseExodusMintId(uint160 const &hash, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->EraseExodusMintIDV1(hash);
}

bool SigmaWalletV1::HasExodusMintId(uint160 const &hash, CWalletDB *db) const
{
    auto local = EnsureDBConnection(db);
    return db->HasExodusMintIDV1(hash);
}

bool SigmaWalletV1::WriteExodusMintPool(std::vector<MintPoolEntry> const &mints, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->WriteExodusMintPoolV1(mints);
}

bool SigmaWalletV1::ReadExodusMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->ReadExodusMintPoolV1(mints);
}

void SigmaWalletV1::ListExodusMints(std::function<void(SigmaMintId&, SigmaMint&)> inserter, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    db->ListExodusMintsV1<SigmaMintId, SigmaMint>(inserter);
}

CoinSigner SigmaWalletV1::GetSigner(SigmaMintId const &id)
{
    auto mint = GetMint(id);
    uint512 seed;
    std::array<uint8_t, 32> ecdsaKey;

    GenerateSeed(mint.seedId, seed);
    GeneratePrivateKey(seed, ecdsaKey);

    return CoinSigner(ecdsaKey);
}

}