#ifndef ZCOIN_EXODUS_WALLET_H
#define ZCOIN_EXODUS_WALLET_H

#include "exodus.h"
#include "sigma.h"
#include "sigmadb.h"
#include "sp.h"
#include "walletmodels.h"
#include "hdmint/wallet.h"

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

    template<class OutputIt>
    void ListSigmaMints(OutputIt it)
    {
        LOCK(pwalletMain->cs_wallet);

        auto mintWallet = this->mintWallet;

        CWalletDB(walletFile).ListExodusHDMints<uint256, HDMint>(
            [&mintWallet, &it](HDMint const &mint){
                SigmaMint entry;
                mintWallet.RegenerateMint(mint, entry);
                *it++ = std::move(entry);
            }
        );
    }

    template<class OutputIt>
    void ListSigmaMints(uint32_t propertyId, OutputIt it)
    {
        LOCK(pwalletMain->cs_wallet);

        auto mintWallet = this->mintWallet;

        CWalletDB(walletFile).ListExodusHDMints<uint256, HDMint>(
            [&mintWallet, &it, propertyId](HDMint const &mint){
                if (mint.GetPropertyId() == propertyId) {
                    SigmaMint entry;
                    mintWallet.RegenerateMint(mint, entry);
                    *it++ = std::move(entry);
                }
            }
        );
    }

    bool HasSigmaMint(const SigmaMintId& id);
    SigmaMint GetSigmaMint(const SigmaMintId& id);
    boost::optional<SigmaMint> GetSpendableSigmaMint(PropertyId property, DenominationId denomination);

    void SetSigmaMintUsedTransaction(SigmaMintId const &id, uint256 const &tx);

protected:
    void SetSigmaMintChainState(const SigmaMintId& id, const SigmaMintChainState& state);
    bool HasSigmaSpend(const secp_primitives::Scalar& serial, MintMeta &meta);

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
