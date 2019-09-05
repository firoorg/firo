// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EXODUS_HDMINT_WALLET_H
#define EXODUS_HDMINT_WALLET_H

#include <map>

#include "../uint256.h"
#include "../primitives/zerocoin.h"
#include "../wallet/wallet.h"
#include "../walletmodels.h"

#include "tracker.h"
#include "hdmint.h"

namespace exodus
{

class HDMintWallet
{
private:
    int32_t countNextUse;
    int32_t countNextGenerate;
    std::string walletFile;
    CMintPool mintPool;
    HDMintTracker tracker;
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

    bool RegenerateMint(const HDMint& mint, SigmaMint& entry);

    std::pair<uint256, uint256> RegenerateMintPoolEntry(const uint160& mintHashSeedMaster, CKeyID& seedId, const int32_t& count);
    void GenerateMintPool(int32_t nIndex = 0);
    HDMintTracker & GetTracker() { return tracker; }
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

    void ResetCoinsState();

private:
    bool CreateZerocoinSeed(uint512& seedZerocoin, int32_t n, CKeyID& seedId, bool checkIndex = true);
    CKeyID GetZerocoinSeedID(int32_t count);
    bool LoadMintPoolFromDB();
};

} // namespace exodus

#endif // EXODUS_HDMINT_WALLET_H
