// Copyright (c) 2020 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_ELYSIUM_SIGMAWALLETV1_H
#define FIRO_ELYSIUM_SIGMAWALLETV1_H

#include "ecdsa_context.h"
#include "sigmawallet.h"

namespace elysium {


class SigmaWalletV1 : public SigmaWallet
{
protected:
    typedef std::array<uint8_t, 32> ECDSAPrivateKey;

public:
    SigmaWalletV1();

protected:
    bool GetPublicKey(ECDSAPrivateKey const &priv, secp256k1_pubkey &out);
    secp_primitives::Scalar GenerateSerial(secp256k1_pubkey const &pubkey);

protected:
    uint32_t BIP44ChangeIndex() const;
    SigmaPrivateKey GeneratePrivateKey(uint512 const &seed);
    SigmaPrivateKey GeneratePrivateKey(uint512 const &seed, ECDSAPrivateKey &signatureKey);

    class Database : public SigmaWallet::Database
    {
    public:
        Database();

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

public:
    CKey GetSignatureKey(SigmaMintId const &id);

private:
    ECDSAContext context;
};

}

#endif // FIRO_ELYSIUM_SIGMAWALLETV1_H