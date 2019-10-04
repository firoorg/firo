#ifndef ZCOIN_EXODUS_WALLET_H
#define ZCOIN_EXODUS_WALLET_H

#include "exodus.h"
#include "property.h"
#include "sigmaprimitives.h"
#include "sigmawallet.h"
#include "sp.h"
#include "walletmodels.h"

#include "../uint256.h"

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
    void ReloadMasterKey();

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

    void SetSigmaMintCreatedTransaction(const SigmaMintId& id, const uint256& tx);
    void SetSigmaMintUsedTransaction(const SigmaMintId& id, const uint256& tx);

    void ClearAllChainState();

    SigmaSpend CreateSigmaSpend(PropertyId property, SigmaDenomination denomination);
    void DeleteUnconfirmedSigmaMint(SigmaMintId const &id);

public:
    template<class OutputIt>
    void ListSigmaMints(OutputIt it)
    {
        mintWallet.ListMints(it);
    }

    SigmaMint GetSigmaMint(const SigmaMintId& id);
    SigmaPrivateKey GetKey(const SigmaMint &mint);
    bool HasSigmaMint(const SigmaMintId& id);
    bool HasSigmaMint(const secp_primitives::Scalar &serial);

protected:
    boost::optional<SigmaMint> GetSpendableSigmaMint(
        PropertyId property, SigmaDenomination denomination);
    void SetSigmaMintChainState(const SigmaMintId &id, const SigmaMintChainState &state);

private:
    void OnSpendAdded(
        PropertyId property,
        SigmaDenomination denomination,
        const secp_primitives::Scalar &serial,
        const uint256 &tx);

    void OnSpendRemoved(
        PropertyId property,
        SigmaDenomination denomination,
        const secp_primitives::Scalar &serial);

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
    SigmaWallet mintWallet;
};

extern Wallet *wallet;

} // namespace exodus

#endif // ZCOIN_EXODUS_WALLET_H
