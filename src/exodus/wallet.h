#ifndef ZCOIN_EXODUS_WALLET_H
#define ZCOIN_EXODUS_WALLET_H

#include "exodus.h"
#include "property.h"
#include "sigmaprimitives.h"
#include "sp.h"
#include "walletmodels.h"

#include "../wallet/walletdb.h"

#include <boost/optional.hpp>

#include <forward_list>
#include <string>

namespace exodus {

class Wallet
{
public:
    Wallet(const std::string& walletFile);
    virtual ~Wallet();

public:
    SigmaMintId CreateSigmaMint(PropertyId property, SigmaDenomination denomination);

    template<class Denomination, class Output>
    Output CreateSigmaMints(PropertyId property, Denomination begin, Denomination end, Output output)
    {
        for (auto it = begin; it != end; it++) {
            *output++ = CreateSigmaMint(property, *it);
        }

        return output;
    }

    SigmaSpend CreateSigmaSpend(PropertyId property, SigmaDenomination denomination);

public:
    template<class OutputIt>
    void ListSigmaMints(OutputIt it)
    {
        auto insertF = [&it] (SigmaMint& mint) {
            *it++ = std::move(mint);
        };

        CWalletDB(walletFile).ListExodusMint<SigmaMintId, SigmaMint>(insertF);
    }

    template<class OutputIt>
    void ListSigmaMints(uint32_t propertyId, OutputIt it)
    {
        auto insertF = [propertyId, &it](SigmaMint& mint) {
            if (mint.property == propertyId) {
                *it++ = std::move(mint);
            }
        };

        CWalletDB(walletFile).ListExodusMint<SigmaMintId, SigmaMint>(insertF);
    }

    bool HasSigmaMint(const SigmaMintId& id);
    SigmaMint GetSigmaMint(const SigmaMintId& id);

public:
    void SetSigmaMintUsedTransaction(SigmaMintId const &id, uint256 const &tx);

protected:
    void SetSigmaMintChainState(const SigmaMintId& id, const SigmaMintChainState& state);

private:
    boost::optional<SigmaMint> GetSpendableSigmaMint(PropertyId property, SigmaDenomination denomination);

private:
    void OnMintAdded(
        PropertyId property,
        SigmaDenomination denomination,
        SigmaMintGroup group,
        SigmaMintIndex idx,
        const SigmaPublicKey& pubKey,
        int block);

    void OnMintRemoved(PropertyId property, SigmaDenomination denomination, const SigmaPublicKey& pubKey);

private:
    std::string walletFile;
    std::forward_list<boost::signals2::scoped_connection> eventConnections;
};

extern Wallet *wallet;

}

#endif // ZCOIN_EXODUS_WALLET_H
