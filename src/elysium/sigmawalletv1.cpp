// Copyright (c) 2020 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sigmawalletv1.h"

#include "../wallet/wallet.h"

namespace elysium {

SigmaWalletV1::SigmaWalletV1()
    : SigmaWallet(new SigmaWalletV1::Database()),
    context(ECDSAContext::CreateSignContext())
{
}

bool SigmaWalletV1::GetPublicKey(ECDSAPrivateKey const &priv, secp256k1_pubkey &out)
{
    return 1 == secp256k1_ec_pubkey_create(
        context.Get(),
        &out,
        priv.data());
}

secp_primitives::Scalar SigmaWalletV1::GenerateSerial(secp256k1_pubkey const &pubkey)
{
    std::array<uint8_t, 33> compressedPub;

    size_t outSize = compressedPub.size();
    secp256k1_ec_pubkey_serialize(
        context.Get(),
        compressedPub.data(),
        &outSize,
        &pubkey,
        SECP256K1_EC_COMPRESSED);

    if (outSize != 33) {
        throw std::runtime_error("Compressed public key size is invalid.");
    }

    std::array<uint8_t, CSHA256::OUTPUT_SIZE> hash;
    CSHA256().Write(compressedPub.data(), compressedPub.size()).Finalize(hash.data());

    secp_primitives::Scalar serial;
    serial.memberFromSeed(hash.data());

    return serial;
}

uint32_t SigmaWalletV1::BIP44ChangeIndex() const
{
    return BIP44_ELYSIUM_MINT_INDEX_V1;
}

SigmaPrivateKey SigmaWalletV1::GeneratePrivateKey(uint512 const &seed)
{
    ECDSAPrivateKey signatureKey;
    return GeneratePrivateKey(seed, signatureKey);
}

SigmaPrivateKey SigmaWalletV1::GeneratePrivateKey(
    uint512 const &seed, ECDSAPrivateKey &signatureKey)
{
    // last 32 bytes as seed of randomness
    std::array<uint8_t, 32> randomnessSeed;
    std::copy(seed.begin() + 32, seed.end(), randomnessSeed.begin());
    secp_primitives::Scalar randomness;
    randomness.memberFromSeed(randomnessSeed.data());

    // first 32 bytes as seed of ecdsa key and serial
    std::copy(seed.begin(), seed.begin() + 32, signatureKey.begin());

    SigmaPrivateKey key;

    // hash until get valid private key
    do {
        secp256k1_pubkey pubkey;
        do {
            CSHA256().Write(signatureKey.data(), signatureKey.size()).Finalize(signatureKey.data());
        } while (!GetPublicKey(signatureKey, pubkey));

        auto serial = GenerateSerial(pubkey);

        key = SigmaPrivateKey(serial, randomness);
    } while (!key.IsValid());

    return key;
}

CKey SigmaWalletV1::GetSignatureKey(SigmaMintId const &id)
{
    auto mint = GetMint(id);
    uint512 seed;
    ECDSAPrivateKey signatureKey;

    GenerateSeed(mint.seedId, seed);
    GeneratePrivateKey(seed, signatureKey);

    CKey key;
    key.Set(signatureKey.begin(), signatureKey.end(), true);

    return key;
}


// DB
SigmaWalletV1::Database::Database()
{
}

bool SigmaWalletV1::Database::WriteMint(SigmaMintId const &id, SigmaMint const &mint, CWalletDB *db)
{
    auto local = Connection(db);
    return local->WriteElysiumMintV1(id, mint);
}

bool SigmaWalletV1::Database::ReadMint(SigmaMintId const &id, SigmaMint &mint, CWalletDB *db) const
{
    auto local = Connection(db);
    return local->ReadElysiumMintV1(id, mint);
}

bool SigmaWalletV1::Database::EraseMint(SigmaMintId const &id, CWalletDB *db)
{
    auto local = Connection(db);
    return local->EraseElysiumMintV1(id);
}

bool SigmaWalletV1::Database::HasMint(SigmaMintId const &id, CWalletDB *db) const
{
    auto local = Connection(db);
    return local->HasElysiumMintV1(id);
}

bool SigmaWalletV1::Database::WriteMintId(uint160 const &hash, SigmaMintId const &mintId, CWalletDB *db)
{
    auto local = Connection(db);
    return local->WriteElysiumMintIdV1(hash, mintId);
}

bool SigmaWalletV1::Database::ReadMintId(uint160 const &hash, SigmaMintId &mintId, CWalletDB *db) const
{
    auto local = Connection(db);
    return local->ReadElysiumMintIdV1(hash, mintId);
}

bool SigmaWalletV1::Database::EraseMintId(uint160 const &hash, CWalletDB *db)
{
    auto local = Connection(db);
    return local->EraseElysiumMintIdV1(hash);
}

bool SigmaWalletV1::Database::HasMintId(uint160 const &hash, CWalletDB *db) const
{
    auto local = Connection(db);
    return local->HasElysiumMintIdV1(hash);
}

bool SigmaWalletV1::Database::WriteMintPool(std::vector<MintPoolEntry> const &mints, CWalletDB *db)
{
    auto local = Connection(db);
    return local->WriteElysiumMintPoolV1(mints);
}

bool SigmaWalletV1::Database::ReadMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db)
{
    auto local = Connection(db);
    return local->ReadElysiumMintPoolV1(mints);
}

void SigmaWalletV1::Database::ListMints(
    std::function<void(SigmaMintId&, SigmaMint&)> const &inserter, CWalletDB *db)
{
    auto local = Connection(db);
    local->ListElysiumMintsV1<SigmaMintId, SigmaMint>(inserter);
}

}