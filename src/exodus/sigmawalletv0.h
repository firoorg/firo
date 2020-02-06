// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_EXODUS_SIGMAWALLETV0_H
#define ZCOIN_EXODUS_SIGMAWALLETV0_H

#include "sigmawallet.h"

namespace exodus {

class SigmaWalletV0 : public SigmaWallet<SigmaPrivateKey>
{
public:
    SigmaWalletV0();

protected:
    SigmaPrivateKey GeneratePrivateKey(uint512 const &seed);
    unsigned GetChange() const;

    bool WriteExodusMint(SigmaMintId const &id, SigmaMint const &mint, CWalletDB *db = nullptr);
    bool ReadExodusMint(SigmaMintId const &id, SigmaMint &mint, CWalletDB *db = nullptr) const;
    bool EraseExodusMint(SigmaMintId const &id, CWalletDB *db = nullptr);
    bool HasExodusMint(SigmaMintId const &id, CWalletDB *db = nullptr) const;

    bool WriteExodusMintId(uint160 const &hash, SigmaMintId const &mintId, CWalletDB *db = nullptr);
    bool ReadExodusMintId(uint160 const &hash, SigmaMintId &mintId, CWalletDB *db = nullptr) const;
    bool EraseExodusMintId(uint160 const &hash, CWalletDB *db = nullptr);
    bool HasExodusMintId(uint160 const &hash, CWalletDB *db = nullptr) const;

    bool WriteExodusMintPool(std::vector<MintPoolEntry> const &mints, CWalletDB *db = nullptr);
    bool ReadExodusMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db = nullptr);

    void ListExodusMints(std::function<void(SigmaMintId const&, SigmaMint const&)>, CWalletDB *db = nullptr);

public:
    using SigmaWallet::GeneratePrivateKey;
};

}

#endif // ZCOIN_EXODUS_SIGMAWALLETV0_H