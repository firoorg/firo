#ifndef ZCOIN_ELYSIUM_WALLET_H
#define ZCOIN_ELYSIUM_WALLET_H

#include "elysium.h"
#include "property.h"
#include "lelantuswallet.h"
#include "sigmaprimitives.h"
#include "sigmawalletv0.h"
#include "sigmawalletv1.h"
#include "sp.h"
#include "walletmodels.h"

#include "../uint256.h"

#include "../wallet/walletdb.h"

#include <boost/optional.hpp>

#include <forward_list>
#include <string>

namespace elysium {

class Wallet
{
protected:
    enum class SigmaMintVersion : uint8_t
    {
        V0,
        V1
    };

public:
    Wallet(const std::string& walletFile);
    virtual ~Wallet();

public:
    void ReloadMasterKey();

public:
    SigmaMintId CreateSigmaMint(PropertyId property, SigmaDenomination denomination);
    LelantusWallet::MintReservation CreateLelantusMint(PropertyId property, LelantusAmount amount);

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
    void SetLelantusMintUsedTransaction(const MintEntryId& id, const uint256& tx);

    void ClearAllChainState();

    void SyncWithChain();

    SigmaSpend CreateSigmaSpendV0(PropertyId property, SigmaDenomination denomination, bool fPadding);
    SigmaSpend CreateSigmaSpendV1(PropertyId property, SigmaDenomination denomination, bool fPadding);
    lelantus::JoinSplit CreateLelantusJoinSplit(
        PropertyId property,
        CAmount amountToSpend,
        uint256 const &metadata,
        std::vector<SpendableCoin> &spendables,
        boost::optional<LelantusWallet::MintReservation> &changeMint,
        LelantusAmount &changeValue);

    void DeleteUnconfirmedSigmaMint(SigmaMintId const &id);

public:
    template<class OutputIt>
    void ListSigmaMintsV0(OutputIt it)
    {
        mintWalletV0.ListMints(it);
    }

    template<class OutputIt>
    void ListSigmaMintsV1(OutputIt it)
    {
        mintWalletV1.ListMints(it);
    }

    template<class OutputIt>
    void ListLelantusMints(OutputIt it)
    {
        lelantusWallet.ListMints(it);
    }

    SigmaMint GetSigmaMint(const SigmaMintId& id);
    CKey GetSigmaSignatureKey(const SigmaMintId &id);
    SigmaPrivateKey GetKey(const SigmaMint &mint);

    bool HasSigmaMint(const SigmaMintId& id);
    bool HasSigmaMint(const secp_primitives::Scalar &serial);

    bool HasLelantusMint(const MintEntryId& id);
    bool HasLelantusMint(const secp_primitives::Scalar &serial);

protected:
    boost::optional<SigmaMint> GetSpendableSigmaMint(
        PropertyId property, SigmaDenomination denomination, SigmaMintVersion version);
    void SetSigmaMintChainState(const SigmaMintId &id, const SigmaMintChainState &state);

    void SetLelantusMintChainState(const MintEntryId &id, const LelantusMintChainState &state);

    SigmaWallet& GetMintWallet(SigmaMintVersion version);
    SigmaWallet& GetMintWallet(SigmaMintId const &id);

    boost::optional<SigmaMintVersion> GetSigmaMintVersion(const SigmaMintId& id);
    boost::optional<SigmaMintVersion> GetSigmaMintVersion(const secp_primitives::Scalar &scalar);

    SigmaSpend CreateSigmaSpend(PropertyId property, SigmaDenomination denomination, bool fPadding, SigmaMintVersion version);

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

    void OnLelantusMintAdded(
        PropertyId property,
        MintEntryId id,
        LelantusGroup group,
        LelantusIndex idx,
        boost::optional<LelantusAmount> amount,
        int block);

    void OnLelantusMintRemoved(
        PropertyId property,
        MintEntryId id);

private:
    std::string walletFile;
    std::forward_list<boost::signals2::scoped_connection> eventConnections;
    SigmaWalletV0 mintWalletV0;
    SigmaWalletV1 mintWalletV1;
    LelantusWallet lelantusWallet;
};

extern Wallet *wallet;

} // namespace elysium

#endif // ZCOIN_ELYSIUM_WALLET_H
