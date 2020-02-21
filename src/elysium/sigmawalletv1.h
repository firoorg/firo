// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_ELYSIUM_SIGMAWALLETV1_H
#define ZCOIN_ELYSIUM_SIGMAWALLETV1_H

#include "coinsigner.h"
#include "sigmawallet.h"

namespace elysium {

typedef std::array<uint8_t, 32> ECDSAPrivateKey;

class SigmaWalletV1 : public SigmaWallet
{
public:
    SigmaWalletV1();

protected:
    bool GeneratePublicKey(ECDSAPrivateKey const &priv, secp256k1_pubkey &out);
    void GenerateSerial(secp256k1_pubkey const &pubkey, secp_primitives::Scalar &serial);

protected:
    uint32_t ChangeIndex();
    SigmaPrivateKey GeneratePrivateKey(uint512 const &seed);
    SigmaPrivateKey GeneratePrivateKey(uint512 const &seed, ECDSAPrivateKey &ecdsaKeyOut);

    // DB
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

public:
    CoinSigner GetSigner(SigmaMintId const &id);
};

}

#endif // ZCOIN_ELYSIUM_SIGMAWALLETV1_H