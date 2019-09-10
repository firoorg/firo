// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hdmint/hdmint.h>
#include <primitives/zerocoin.h>

#include "tracker.h"
#include "wallet.h"
#include "hdmint.h"

namespace exodus {

HDMintTracker::HDMintTracker(
    std::string const &walletFile,
    HDMintWallet *wallet)
    : walletFile(walletFile),
    mintWallet(wallet)
{
    LoadHDMintsFromDB();
}

bool HDMintTracker::GetMintFromSerialHash(const uint256 &hashSerial, HDMint &mint) const
{
    auto it = mints.find(hashSerial);
    if (it == mints.end()) {
        return false;
    }

    mint = *it;
    return true;
}

bool HDMintTracker::GetMintFromPubcoinHash(const uint256 &hashPubcoin, HDMint& mint) const
{
    auto it = mints.get<1>().find(hashPubcoin);
    if (it == mints.get<1>().end()) {
        return false;
    }

    mint = *it;
    return true;
}

std::vector<uint256> HDMintTracker::GetSerialHashes()
{
    std::vector<uint256> serialHashes;
    for (auto const &it : mints) {
        serialHashes.push_back(it.GetSerialHash());
    }

    return serialHashes;
}

std::vector<HDMint> HDMintTracker::GetMints(bool unusedOnly, bool matureOnly) const
{
    std::vector<HDMint> result;

    for (auto const &mint : mints) {

        if (unusedOnly && !mint.GetSpendTx().IsNull()) {
            continue;
        }

        bool confirmed = mint.GetChainState().block >= 0;
        if (matureOnly && !confirmed) {
            continue;
        }

        result.push_back(mint);
    }

    return result;
}

bool HDMintTracker::HasPubcoinHash(const uint256& hashPubcoin) const
{
    HDMint m;
    return GetMintFromPubcoinHash(hashPubcoin, m);
}

bool HDMintTracker::HasSerialHash(const uint256& hashSerial) const
{
    HDMint m;
    return GetMintFromSerialHash(hashSerial, m);
}

bool HDMintTracker::UpdateState(const HDMint &mint)
{
    LOCK(pwalletMain->cs_wallet);

    CWalletDB walletdb(walletFile);

    auto it = mints.find(mint.GetSerialHash());
    if (it == mints.end()) {
        throw std::runtime_error("mint is not exists");
    }

    if (!mints.replace(it, mint)) {
        throw std::runtime_error("fail to update mint state");
    }

    if (!walletdb.WriteExodusHDMint(mint)) {
        return error("%s: failed to update deterministic mint when writing to db", __func__);
    }

    return true;
}

void HDMintTracker::Add(const HDMint& mint, bool isNew)
{
    auto it = mints.find(mint.GetSerialHash());
    if (it != mints.end()) {
        throw std::runtime_error("mint is already exists");
    }

    if (!mints.insert(mint).second) {
        throw std::runtime_error("fail to insert");
    }

    if (isNew) {
        if (!CWalletDB(walletFile).WriteExodusHDMint(mint)) {
            throw std::runtime_error("fail to store hdmint");
        }
    }
}

void HDMintTracker::ResetAllMintsChainState()
{
    for (auto it = mints.begin(); it != mints.end(); it++) {

        mints.modify(it, [](HDMint &m) {
            m.SetChainState(SigmaMintChainState());
            m.SetSpendTx(uint256());
        });

        if (!CWalletDB(walletFile).WriteExodusHDMint(*it)) {
            throw std::runtime_error("fail to store hdmint");
        }
    }
}

void HDMintTracker::SetMintSpendTx(const uint256& pubcoinHash, const uint256& spendTx)
{
    HDMint m;
    if (!GetMintFromPubcoinHash(pubcoinHash, m)) {
        return;
    }

    m.SetSpendTx(spendTx);
    UpdateState(m);
}

void HDMintTracker::SetChainState(const uint256& pubcoinHash, const SigmaMintChainState& chainState)
{
    HDMint m;
    if (!GetMintFromPubcoinHash(pubcoinHash, m)) {
        return;
    }

    m.SetChainState(chainState);
    UpdateState(m);
}

std::vector<SigmaMint> HDMintTracker::ListMints(bool unusedOnly, bool matureOnly) const
{
    LOCK(pwalletMain->cs_wallet);

    std::vector<SigmaMint> entries;
    for (auto const &mint : mints) {

        SigmaMint entry;
        if (!mintWallet->RegenerateMint(mint, entry)) {
            throw std::runtime_error("fail to regenerate mint");
        }

        entries.push_back(entry);
    }

    return entries;
}

void HDMintTracker::LoadHDMintsFromDB()
{
    LOCK(pwalletMain->cs_wallet);

    Clear();
    CWalletDB(walletFile).ListExodusHDMints<uint256, HDMint>(
        [this](HDMint const &m) {
            Add(m, false);
        }
    );

    LogPrintf("%s : load %d hdmints from DB\n", __func__, mints.size());
}

void HDMintTracker::Clear()
{
    mints.clear();
}

};