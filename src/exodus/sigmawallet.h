// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_EXODUS_SIGMAWALLET_H
#define ZCOIN_EXODUS_SIGMAWALLET_H

#include <map>

#include "../uint256.h"
#include "../primitives/zerocoin.h"
#include "../wallet/wallet.h"

#include "walletmodels.h"

namespace exodus {

class HDMintWallet
{
private:
    int32_t countNextUse;
    int32_t countNextGenerate;
    std::string walletFile;
    CMintPool mintPool;
    uint160 hashSeedMaster;

public:
    int static const COUNT_DEFAULT = 0;

    HDMintWallet(std::string const &walletFile);

    bool SetupWallet(const uint160& hashSeedMaster, bool resetCount = false);
    bool GenerateMint(
        uint32_t propertyId,
        uint8_t denom,
        exodus::SigmaPrivateKey& coin,
        HDMint& dMint,
        boost::optional<MintPoolEntry> mintPoolEntry = boost::none);

    bool RegenerateMint(const HDMint& mint, SigmaPrivateKey &privKey);
    std::pair<uint256, uint160> RegenerateMintPoolEntry(const uint160& mintHashSeedMaster, CKeyID& seedId, const int32_t& count);

    void GenerateMintPool(int32_t nIndex = 0);
    CMintPool & GetMintPool() { return mintPool; }

    bool SetMintSeedSeen(
        std::pair<uint256, MintPoolEntry> const &mintPoolEntryPair,
        uint32_t propertyId,
        uint8_t denomination,
        exodus::SigmaMintChainState const &chainState,
        uint256 const &spendTx = uint256());

    bool SeedToZerocoin(const uint512& seedZerocoin, GroupElement& bnValue, exodus::SigmaPrivateKey& coin);

    // Get and Set count function
    int32_t GetCount();
    void ResetCount();
    void SetCount(int32_t count);
    void UpdateCountLocal();
    void UpdateCountDB();
    void UpdateCount();

    template<
        class OutIt,
        typename std::enable_if<is_iterator<OutIt>::value>::type* = nullptr
    > OutIt ListHDMints(OutIt it, bool unusedOnly, bool matureOnly) const
    {
        ListHDMints([&it](HDMint &m) {
            *it++ = m;
        }, unusedOnly, matureOnly);

        return it;
    }

    size_t ListHDMints(std::function<void(HDMint&)> const &, bool unusedOnly = true, bool matureOnly = true) const;

    void Record(const HDMint &mint);
    void ResetCoinsState();

    bool HasMint(SigmaMintId const &id) const;
    bool HasSerial(secp_primitives::Scalar const &serial) const;
    HDMint GetMint(SigmaMintId const &id) const;
    HDMint GetMint(secp_primitives::Scalar const &serial) const;
    SigmaMintId GetMintId(secp_primitives::Scalar const &serial) const;

    HDMint UpdateMintSpendTx(SigmaMintId const &id, uint256 const &tx);
    HDMint UpdateMintChainstate(SigmaMintId const &id, SigmaMintChainState const &state);

private:

    bool CreateZerocoinSeed(uint512& seedZerocoin, int32_t n, CKeyID& seedId, bool checkIndex = true);
    CKeyID GetZerocoinSeedID(int32_t count);
    bool LoadMintPoolFromDB();
    HDMint UpdateMint(SigmaMintId const &, std::function<void(HDMint &)> const &);
};

} // namespace exodus

#endif // ZCOIN_EXODUS_SIGMAWALLET_H
