// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hdmint/hdmint.h>
#include <primitives/zerocoin.h>

#include "tracker.h"
#include "wallet.h"
#include "hdmint.h"

#include "../wallet.h"
#include "../walletmodels.h"

#include "../../util.h"
#include "../../sync.h"
#include "../../txdb.h"
#include "../../libzerocoin/Zerocoin.h"
#include "../../main.h"
#include "../../sigma.h"
#include "../../txmempool.h"
#include "../../wallet/wallet.h"
#include "../../wallet/walletdb.h"

#include "../../hdmint/mintpool.h"

namespace exodus {

GroupElement const &MintMeta::GetPubCoinValue() const
{
    return pubCoinValue;
}

void MintMeta::SetPubCoinValue(GroupElement const &other)
{
    if (other == pubCoinValue)
        return;
    pubCoinValue = other;
    pubCoinValueHash = primitives::GetPubCoinValueHash(pubCoinValue);
}

uint256 const & MintMeta::GetPubCoinValueHash() const
{
    return pubCoinValueHash;
}

HDMintTracker::HDMintTracker(std::string walletFile, HDMintWallet *wallet)
    : initialized(false), walletFile(walletFile), mintWallet(wallet)
{
    //Load all CZerocoinEntries and CHDMints from the database
    if (!initialized) {
        ListMetas(false, false, true);
        initialized = true;
    }
}

bool HDMintTracker::Archive(MintMeta &meta)
{
    LOCK(pwalletMain->cs_wallet);

    uint256 hashPubcoin = meta.GetPubCoinValueHash();

    if (HasSerialHash(meta.hashSerial))
        mapSerialHashes.at(meta.hashSerial).isArchived = true;

    CWalletDB walletdb(walletFile);
    HDMint mint;

    if (!walletdb.ReadExodusHDMint(hashPubcoin, mint))
        return error("%s: could not find pubcoinhash %s in db", __func__, hashPubcoin.GetHex());

    if (!walletdb.ArchiveExodusHDMint(mint))
        return error("%s: failed to archive deterministic orphaned mint", __func__);

    LogPrintf("%s: archived pubcoinhash %s\n", __func__, hashPubcoin.GetHex());
    return true;
}

bool HDMintTracker::UnArchive(const uint256& hashPubcoin)
{
    CWalletDB walletdb(walletFile);
    HDMint mint;

    if (!walletdb.UnarchiveExodusHDMint(hashPubcoin, mint))
        return error("%s: failed to unarchive deterministic mint", __func__);

    Add(mint, false);
    LogPrintf("%s: unarchived %s\n", __func__, hashPubcoin.GetHex());

    return true;
}

bool HDMintTracker::GetMetaFromSerial(const uint256 &hashSerial, MintMeta& meta)
{
    auto it = mapSerialHashes.find(hashSerial);
    if (it == mapSerialHashes.end()) {
        return false;
    }

    meta = it->second;
    return true;
}

bool HDMintTracker::GetMetaFromPubcoin(const uint256 &hashPubcoin, MintMeta& meta)
{
    for (auto const &it : mapSerialHashes) {
        if (it.second.GetPubCoinValueHash() == hashPubcoin){
            meta = it.second;
            return true;
        }
    }

    return false;
}

std::vector<uint256> HDMintTracker::GetSerialHashes()
{
    std::vector<uint256> serialHashes;
    for (auto const &it : mapSerialHashes) {
        if (it.second.isArchived)
            continue;

        serialHashes.push_back(it.first);
    }

    return serialHashes;
}

std::list<MintMeta> HDMintTracker::GetMints(bool confirmedOnly, bool inactive) const
{
    std::list<MintMeta> mints;

    for (auto const &it : mapSerialHashes) {
        auto mint = it.second;

        if ((mint.isArchived || mint.isUsed()) && inactive) {
            continue;
        }

        bool confirmed = mint.chainState.block >= 0;
        if (confirmedOnly && !confirmed) {
            continue;
        }

        mints.push_back(mint);
    }

    return mints;
}

bool HDMintTracker::HasPubcoinHash(const uint256& hashPubcoin) const
{
    for (auto const &it : mapSerialHashes) {

        if (it.second.GetPubCoinValueHash() == hashPubcoin) {
            return true;
        }
    }
    return false;
}

bool HDMintTracker::HasSerialHash(const uint256& hashSerial) const
{
    auto it = mapSerialHashes.find(hashSerial);
    return it != mapSerialHashes.end();
}

bool HDMintTracker::UpdateState(const MintMeta &meta)
{
    LOCK(pwalletMain->cs_wallet);

    auto hashPubcoin = meta.GetPubCoinValueHash();
    CWalletDB walletdb(walletFile);

    HDMint mint;
    if (!walletdb.ReadExodusHDMint(hashPubcoin, mint)) {

        // Check archive just in case
        if (!meta.isArchived)
            return error("%s: failed to read deterministic mint from database", __func__);

        // Unarchive this mint since it is being requested and updated
        if (!walletdb.UnarchiveExodusHDMint(hashPubcoin, mint))
            return error("%s: failed to unarchive deterministic mint from database", __func__);
    }

    mint.SetChainState(meta.chainState);
    mint.SetSpendTx(meta.spendTx);

    if (!walletdb.WriteExodusHDMint(mint))
        return error("%s: failed to update deterministic mint when writing to db", __func__);

    mapSerialHashes[meta.hashSerial] = meta;

    return true;
}

void HDMintTracker::Add(const HDMint& mint, bool isNew, bool isArchived)
{
    MintMeta meta;

    meta.propertyId = mint.GetPropertyId();
    meta.denomination = mint.GetDenomination();
    meta.hashSerial = mint.GetSerialHash();

    meta.SetPubCoinValue(mint.GetPubCoinValue());

    meta.spendTx = mint.GetSpendTx();
    meta.isArchived = isArchived;
    meta.chainState = mint.GetChainState();

    mapSerialHashes[meta.hashSerial] = meta;

    if (isNew) {
        if (!CWalletDB(walletFile).WriteExodusHDMint(mint)) {
            throw std::runtime_error("fail to store hdmint");
        }
    }
}

void HDMintTracker::SetMintSpendTx(const uint256& pubcoinHash, const uint256& spendTx)
{
    MintMeta meta;
    if (!GetMetaFromPubcoin(pubcoinHash, meta))
        return;

    meta.spendTx = spendTx;
    UpdateState(meta);
}

void HDMintTracker::SetChainState(const uint256& pubcoinHash, const SigmaMintChainState& chainState)
{
    MintMeta meta;
    if (!GetMetaFromPubcoin(pubcoinHash, meta))
        return;

    meta.chainState = chainState;
    UpdateState(meta);
}

std::vector<SigmaMint> HDMintTracker::ListMints(bool unusedOnly, bool matureOnly)
{
    LOCK(pwalletMain->cs_wallet);

    std::vector<SigmaMint> mints;
    CWalletDB walletdb(walletFile);

    auto metas = ListMetas(unusedOnly, matureOnly, false);

    for (auto const &meta : metas) {

        SigmaMint entry;
        HDMint mint;

        if (!walletdb.ReadExodusMint(meta.GetPubCoinValueHash(), mint)) {
            throw std::runtime_error("get exodus hd mint fail");
        }

        if (!mintWallet->RegenerateMint(mint, entry)) {
            throw std::runtime_error("fail to regenerate mint");
        }

        mints.push_back(entry);
    }

    return mints;
}

std::vector<MintMeta> HDMintTracker::ListMetas(bool unusedOnly, bool matureOnly, bool load)
{
    LOCK(pwalletMain->cs_wallet);
    std::vector<MintMeta> mints;
    CWalletDB walletdb(walletFile);

    if (load) {
        int count = 0;
        walletdb.ListExodusHDMints<uint256, HDMint>([this, &count](HDMint const &mint) {
            count++;
            Add(mint, false, false);
        });

        LogPrintf("%s: added %d hdmint(s) from DB\n", __func__, count);
    }

    for (auto const &it : mapSerialHashes) {
        auto mint = it.second;

        if (unusedOnly && !mint.spendTx.IsNull())
            continue;

        if (matureOnly && mint.chainState.block < 0) {
            continue;
        }

        mints.push_back(mint);
    }

    return mints;
}

void HDMintTracker::Clear()
{
    mapSerialHashes.clear();
}

};