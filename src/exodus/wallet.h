#ifndef ZCOIN_EXODUS_WALLET_H
#define ZCOIN_EXODUS_WALLET_H

#include <string>

#include "sigma.h"
#include "sp.h"
#include "walletdb.h"
#include "../wallet/wallet.h"

namespace exodus {

class Wallet
{
public:
    Wallet(const std::string& walletFile)
        : walletFile(walletFile)
    {
    }

    SigmaMintId CreateSigmaMint(
        uint32_t propertyId,
        uint8_t denomination
    );

    template<class InItr, class OutItr,
    typename std::enable_if<std::is_same<uint8_t, typename std::iterator_traits<InItr>::value_type>::value>::type* = nullptr>
    OutItr CreateSigmaMints(uint32_t propertyId, InItr begin, InItr end, OutItr mintItr)
    {
        LOCK(pwalletMain->cs_wallet);
        for (auto it = begin; it != end; it++) {
            uint8_t denomination = *it;
            auto mint = CreateSigmaMint(propertyId, denomination);
            *mintItr++ = std::make_pair(denomination, mint.publicKey);
        }

        return mintItr;
    }

    template<class InItr, class OutItr>
    OutItr GetCoinsToSpend(uint32_t propertyId, InItr begin, InItr end, OutItr coins)
    {
        LOCK(pwalletMain->cs_wallet);

        std::list<exodus::SigmaEntry> allCoins;
        ListSigmaEntries(propertyId, std::back_inserter(allCoins));

        // TODO(panu): filter out unusable coins
        std::unordered_map<uint8_t, std::vector<exodus::SigmaEntry>> allCoinSet;
        for (auto const &c : allCoins) {
            allCoinSet[c.denomination].push_back(c);
        }

        // shuffle for security
        for (auto &c : allCoinSet) {
            std::random_shuffle(c.second.begin(), c.second.end());
        }

        for (auto it = begin; it != end; it++) {

            if (allCoinSet[*it].empty()) {
                throw std::invalid_argument("no coin to spend");
            }

            *coins++ = allCoinSet[*it].back();
            allCoinSet[*it].pop_back();
        }

        return coins;
    }

protected:
    template<class OutputIt>
    void ListSigmaEntries(OutputIt it)
    {
        LOCK(pwalletMain->cs_wallet);

        auto insertF = [&it] (exodus::SigmaEntry& entry) {
            *it++ = std::move(entry);
        };
        CWalletDB(walletFile).ListExodusMint<SigmaMintId, exodus::SigmaEntry>(insertF);
    }
    template<class OutputIt>
    void ListSigmaEntries(uint32_t propertyId, OutputIt it)
    {
        LOCK(pwalletMain->cs_wallet);

        auto insertF = [propertyId, &it](exodus::SigmaEntry& entry) {
            if (entry.propertyId == propertyId) {
                *it++ = std::move(entry);
            }
        };

        CWalletDB(walletFile).ListExodusMint<SigmaMintId, exodus::SigmaEntry>(insertF);
    }

    bool HasSigmaEntry(const SigmaMintId& id);
    SigmaEntry GetSigmaEntry(const SigmaMintId& id);

    void SetSigmaMintUsedStatus(const SigmaMintId& id, bool isUsed);

    void UpdateSigmaMint(
        const SigmaMintId& id,
        uint32_t groupId,
        uint16_t index,
        int32_t block
    );

    void ClearSigmaMintChainState(const SigmaMintId& id);

private:
    std::string walletFile;
};

}

#endif // ZCOIN_EXODUS_WALLET_H
