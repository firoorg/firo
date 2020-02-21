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

bool SigmaWalletV0::WriteExodusMint(SigmaMintId const &id, SigmaMint const &mint, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->WriteExodusMint(id, mint);
}

bool SigmaWalletV0::ReadExodusMint(SigmaMintId const &id, SigmaMint &mint, CWalletDB *db) const
{
    auto local = EnsureDBConnection(db);
    return db->ReadExodusMint(id, mint);
}

bool SigmaWalletV0::EraseExodusMint(SigmaMintId const &id, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->EraseExodusMint(id);
}

bool SigmaWalletV0::HasExodusMint(SigmaMintId const &id, CWalletDB *db) const
{
    auto local = EnsureDBConnection(db);
    return db->HasExodusMint(id);
}

bool SigmaWalletV0::WriteExodusMintId(uint160 const &hash, SigmaMintId const &mintId, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->WriteExodusMintID(hash, mintId);
}

bool SigmaWalletV0::ReadExodusMintId(uint160 const &hash, SigmaMintId &mintId, CWalletDB *db) const
{
    auto local = EnsureDBConnection(db);
    return db->ReadExodusMintID(hash, mintId);
}

bool SigmaWalletV0::EraseExodusMintId(uint160 const &hash, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->EraseExodusMintID(hash);
}

bool SigmaWalletV0::HasExodusMintId(uint160 const &hash, CWalletDB *db) const
{
    auto local = EnsureDBConnection(db);
    return db->HasExodusMintID(hash);
}

bool SigmaWalletV0::WriteExodusMintPool(std::vector<MintPoolEntry> const &mints, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->WriteExodusMintPool(mints);
}

bool SigmaWalletV0::ReadExodusMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    return db->ReadExodusMintPool(mints);
}

void SigmaWalletV0::ListExodusMints(std::function<void(SigmaMintId&, SigmaMint&)> inserter, CWalletDB *db)
{
    auto local = EnsureDBConnection(db);
    db->ListExodusMints<SigmaMintId, SigmaMint>(inserter);
}

}