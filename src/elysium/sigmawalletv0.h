// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_ELYSIUM_SIGMAWALLETV0_H
#define ZCOIN_ELYSIUM_SIGMAWALLETV0_H

#include "sigmawallet.h"

namespace elysium {

class SigmaWalletV0 : public SigmaWallet
{
public:
    SigmaWalletV0();

protected:
    uint32_t BIP44ChangeIndex() const;
    SigmaPrivateKey GeneratePrivateKey(uint512 const &seed);

    class WalletDB : public SigmaWallet::WalletDB {
    public:
        WalletDB();

    public:
        bool WriteMint(SigmaMintId const &id, SigmaMint const &mint, CWalletDB *db = nullptr);
        bool ReadMint(SigmaMintId const &id, SigmaMint &mint, CWalletDB *db = nullptr) const;
        bool EraseMint(SigmaMintId const &id, CWalletDB *db = nullptr);
        bool HasMint(SigmaMintId const &id, CWalletDB *db = nullptr) const;

        bool WriteMintId(uint160 const &hash, SigmaMintId const &mintId, CWalletDB *db = nullptr);
        bool ReadMintId(uint160 const &hash, SigmaMintId &mintId, CWalletDB *db = nullptr) const;
        bool EraseMintId(uint160 const &hash, CWalletDB *db = nullptr);
        bool HasMintId(uint160 const &hash, CWalletDB *db = nullptr) const;

        bool WriteMintPool(std::vector<MintPoolEntry> const &mints, CWalletDB *db = nullptr);
        bool ReadMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db = nullptr);

        void ListMints(std::function<void(SigmaMintId&, SigmaMint&)> const&, CWalletDB *db = nullptr);
    };

public:
    using SigmaWallet::GeneratePrivateKey;
};

}

#endif // ZCOIN_ELYSIUM_SIGMAWALLETV0_H