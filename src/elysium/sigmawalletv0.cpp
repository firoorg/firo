// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sigmawalletv0.h"

#include "../wallet/wallet.h"

namespace elysium {

SigmaWalletV0::SigmaWalletV0() : SigmaWallet()
{
}

uint32_t SigmaWalletV0::ChangeIndex()
{
    return BIP44_ELYSIUM_MINT_INDEX;
}

SigmaPrivateKey SigmaWalletV0::GeneratePrivateKey(uint512 const &seed)
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

bool SigmaWalletV0::WriteElysiumMint(SigmaMintId const &id, SigmaMint const &mint, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->WriteElysiumMint(id, mint);
}

bool SigmaWalletV0::ReadElysiumMint(SigmaMintId const &id, SigmaMint &mint, CWalletDB *db) const
{
    auto local = EnsureDBConnection(db);
    return db->ReadElysiumMint(id, mint);
}

bool SigmaWalletV0::EraseElysiumMint(SigmaMintId const &id, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->EraseElysiumMint(id);
}

bool SigmaWalletV0::HasElysiumMint(SigmaMintId const &id, CWalletDB *db) const
{
    auto local = EnsureDBConnection(db);
    return db->HasElysiumMint(id);
}

bool SigmaWalletV0::WriteElysiumMintId(uint160 const &hash, SigmaMintId const &mintId, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->WriteElysiumMintID(hash, mintId);
}

bool SigmaWalletV0::ReadElysiumMintId(uint160 const &hash, SigmaMintId &mintId, CWalletDB *db) const
{
    auto local = EnsureDBConnection(db);
    return db->ReadElysiumMintID(hash, mintId);
}

bool SigmaWalletV0::EraseElysiumMintId(uint160 const &hash, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->EraseElysiumMintId(hash);
}

bool SigmaWalletV0::HasElysiumMintId(uint160 const &hash, CWalletDB *db) const
{
    auto local = EnsureDBConnection(db);
    return db->HasElysiumMintId(hash);
}

bool SigmaWalletV0::WriteElysiumMintPool(std::vector<MintPoolEntry> const &mints, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->WriteElysiumMintPool(mints);
}

bool SigmaWalletV0::ReadElysiumMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->ReadElysiumMintPool(mints);
}

void SigmaWalletV0::ListElysiumMints(std::function<void(SigmaMintId&, SigmaMint&)> inserter, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    db->ListElysiumMints<SigmaMintId, SigmaMint>(inserter);
}

}