// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_EXODUS_HDMINT_TRACKER_H
#define ZCOIN_EXODUS_HDMINT_TRACKER_H

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/hashed_index.hpp>

#include "hdmint.h"
#include "../../wallet/wallet.h"

namespace exodus {

// extracts serial hash from HDMint
struct SerialHashExtractor
{
    typedef uint256 result_type;
    result_type operator() (const HDMint &m) const {
        return m.GetSerialHash();
    }
};

// extracts pubcoin hash from HDMint
struct PubcoinHashExtractor
{
    typedef uint256 result_type;
    result_type operator() (const HDMint &m) const {
        return m.GetPubCoinHash();
    }
};

typedef boost::multi_index_container<
    HDMint,
    boost::multi_index::indexed_by<
        // sorted by serial hash
        boost::multi_index::hashed_unique<SerialHashExtractor, std::hash<uint256>>,
        // sorted by pubcoin hash
        boost::multi_index::hashed_unique<PubcoinHashExtractor, std::hash<uint256>>
    >
> MintsSet;

class HDMintWallet;

class MintTracker
{
private:
    std::string walletFile;
    HDMintWallet *mintWallet;
    MintsSet mints;

public:
    MintTracker(std::string const &walletFile, HDMintWallet *mintWallet);
    void Add(const HDMint& dMint, bool isNew = false);
    bool HasPubcoinHash(const uint256& hashPubcoin) const;
    bool HasSerialHash(const uint256& hashSerial) const;
    bool IsEmpty() const { return mints.empty(); }

    bool GetMintFromSerialHash(const uint256& hashSerial, HDMint& meta) const;
    bool GetMintFromPubcoinHash(const uint256& hashPubcoin, HDMint& meta) const;

    template<class OutIt>
    OutIt ListHDMints(OutIt it, bool unusedOnly = true, bool matureOnly = true) const
    {
        for (auto const &mint : mints) {

            if (unusedOnly && !mint.GetSpendTx().IsNull()) {
                continue;
            }

            bool confirmed = mint.GetChainState().block >= 0;
            if (matureOnly && !confirmed) {
                continue;
            }

            *it++ = mint;
        }

        return it;
    }

    template<class OutIt>
    OutIt ListSigmaMints(OutIt it, bool unusedOnly = true, bool matureOnly = true) const
    {
        LOCK(pwalletMain->cs_wallet);
        for (auto const &mint : mints) {

            SigmaMint entry;
            if (!mintWallet->RegenerateMint(mint, entry)) {
                throw std::runtime_error("fail to regenerate mint");
            }

            *it++ = entry;
        }

        return it;
    }

    void ResetAllMintsChainState();
    void SetMintSpendTx(const uint256& hashPubcoin, const uint256& txid);
    void SetChainState(const uint256& pubcoinHash, const SigmaMintChainState& chainState);

    bool UpdateState(const HDMint &meta);
    void Clear();

private:
    void LoadHDMintsFromDB();
};

} // namespace exodus

#endif // ZCOIN_EXODUS_HDMINT_TRACKER_H
