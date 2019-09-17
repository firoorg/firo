#ifndef ZCOIN_EXODUS_WALLET_H
#define ZCOIN_EXODUS_WALLET_H

#include "exodus.h"
#include "sigma.h"
#include "sigmadb.h"
#include "sp.h"
#include "walletmodels.h"
#include "hdmint/sigmawallet.h"

#include "../wallet/wallet.h"

#include <boost/optional.hpp>

#include <forward_list>
#include <string>

namespace exodus {

class Wallet
{
public:
    Wallet(const std::string& walletFile, SigmaDatabase& sigmaDb);
    virtual ~Wallet();

public:
    SigmaMintId CreateSigmaMint(PropertyId property, DenominationId denomination);

    template<class Denomination, class Output>
    Output CreateSigmaMints(PropertyId property, Denomination begin, Denomination end, Output output)
    {
        LOCK(pwalletMain->cs_wallet);

        for (auto it = begin; it != end; it++) {
            *output++ = CreateSigmaMint(property, *it);
        }

        return output;
    }
    void ResetState();

    template<class OutputIt>
    void ListSigmaMints(OutputIt it)
    {
        LOCK(pwalletMain->cs_wallet);

        auto mintWallet = this->mintWallet;
        mintWallet.ListHDMints([&](HDMint &mint) {

            *it++ = mint;
        }, false, false);
    }

    bool HasSigmaMint(const SigmaMintId& id);
    HDMint GetSigmaMint(const SigmaMintId& id);
    boost::optional<HDMint> GetSpendableSigmaMint(PropertyId property, DenominationId denomination);
    SigmaPrivateKey GetKey(const HDMint &mint);

    void SetSigmaMintUsedTransaction(const SigmaMintId &id, const uint256 &tx);

protected:
    void SetSigmaMintChainState(const SigmaMintId &id, const SigmaMintChainState &state);
    bool HasSigmaSpend(const secp_primitives::Scalar &serial, HDMint &mint);

private:
    void OnSpendAdded(
        PropertyId property,
        DenominationId denomination,
        const secp_primitives::Scalar &serial,
        const uint256 &tx);

    void OnSpendRemoved(
        PropertyId property,
        DenominationId denomination,
        const secp_primitives::Scalar &serial);

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
    HDMintWallet mintWallet;
};

extern Wallet *wallet;

}

#endif // ZCOIN_EXODUS_WALLET_H
