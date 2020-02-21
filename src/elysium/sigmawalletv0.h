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
    uint32_t ChangeIndex();
    SigmaPrivateKey GeneratePrivateKey(uint512 const &seed);

    bool WriteElysiumMint(SigmaMintId const &id, SigmaMint const &mint, CWalletDB *db = nullptr);
    bool ReadElysiumMint(SigmaMintId const &id, SigmaMint &mint, CWalletDB *db = nullptr) const;
    bool EraseElysiumMint(SigmaMintId const &id, CWalletDB *db = nullptr);
    bool HasElysiumMint(SigmaMintId const &id, CWalletDB *db = nullptr) const;

    bool WriteElysiumMintId(uint160 const &hash, SigmaMintId const &mintId, CWalletDB *db = nullptr);
    bool ReadElysiumMintId(uint160 const &hash, SigmaMintId &mintId, CWalletDB *db = nullptr) const;
    bool EraseElysiumMintId(uint160 const &hash, CWalletDB *db = nullptr);
    bool HasElysiumMintId(uint160 const &hash, CWalletDB *db = nullptr) const;

    bool WriteElysiumMintPool(std::vector<MintPoolEntry> const &mints, CWalletDB *db = nullptr);
    bool ReadElysiumMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db = nullptr);

    void ListElysiumMints(std::function<void(SigmaMintId&, SigmaMint&)>, CWalletDB *db = nullptr);

public:
    using SigmaWallet::GeneratePrivateKey;
};

}

#endif // ZCOIN_ELYSIUM_SIGMAWALLETV0_H