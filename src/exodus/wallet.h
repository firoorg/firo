#ifndef ZCOIN_EXODUS_WALLET_H
#define ZCOIN_EXODUS_WALLET_H

#include "exodus.h"
#include "sigma.h"
#include "sigmadb.h"
#include "sp.h"
#include "walletdb.h"

#include "../wallet/wallet.h"

#include <boost/optional.hpp>

#include <forward_list>
#include <string>

namespace exodus {

class Wallet
{
public:
    Wallet(const std::string& walletFile, CMPMintList& sigmaDb);
    virtual ~Wallet();

public:
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

    SigmaMintChainState GetSigmaMintChainState(const SigmaMintId& id);

    boost::optional<SigmaEntry> GetSpendableSigmaMint(uint32_t propertyId, uint8_t denomination);
    void SetSigmaMintUsedTransaction(SigmaMintId const &id, uint256 const &tx);

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

    void SetSigmaMintChainState(const SigmaMintId& id, const SigmaMintChainState& state);
private:
    void OnMintAdded(
        PropertyId property,
        DenominationId denomination,
        MintGroupId group,
        MintGroupIndex idx,
        const SigmaPublicKey& pubKey,
        int block);

    void OnMintRemoved(PropertyId property, DenominationId denomination, const SigmaPublicKey& pubKey);

private:
    std::string walletFile;
    std::forward_list<boost::signals2::scoped_connection> eventConnections;
};

extern Wallet *wallet;

}

#endif // ZCOIN_EXODUS_WALLET_H
