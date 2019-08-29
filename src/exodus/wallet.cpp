#include "wallet.h"

#include "../wallet/wallet.h"
#include "../wallet/walletdb.h"

#include <boost/function_output_iterator.hpp>

#include <functional>

namespace exodus {

Wallet *wallet;

Wallet::Wallet(const std::string& walletFile, CMPMintList& sigmaDb) : walletFile(walletFile)
{
    using std::placeholders::_1;
    using std::placeholders::_2;
    using std::placeholders::_3;
    using std::placeholders::_4;
    using std::placeholders::_5;
    using std::placeholders::_6;

    // Subscribe to events.
    {
        auto h = std::bind(&Wallet::OnMintAdded, this, _1, _2, _3, _4, _5, _6);
        eventConnections.emplace_front(sigmaDb.MintAdded.connect(h));
    }
    {
        auto h = std::bind(&Wallet::OnMintRemoved, this, _1, _2, _3);
        eventConnections.emplace_front(sigmaDb.MintRemoved.connect(h));
    }
}

Wallet::~Wallet()
{
}

SigmaMintId Wallet::CreateSigmaMint(PropertyId property, DenominationId denomination)
{
    SigmaMint mint(property, denomination);
    SigmaMintId id(mint);

    {
        LOCK(pwalletMain->cs_wallet);
        CWalletDB(walletFile).WriteExodusMint(id, mint);
    }

    return id;
}

bool Wallet::HasSigmaMint(const SigmaMintId& id)
{
    LOCK(pwalletMain->cs_wallet);
    return CWalletDB(walletFile).HasExodusMint(id);
}

SigmaMint Wallet::GetSigmaMint(const SigmaMintId& id)
{
    SigmaMint mint;

    LOCK(pwalletMain->cs_wallet);

    if (!CWalletDB(walletFile).ReadExodusMint(id, mint)) {
        throw std::invalid_argument("sigma mint not found");
    }

    return mint;
}

boost::optional<SigmaMint> Wallet::GetSpendableSigmaMint(PropertyId property, DenominationId denomination)
{
    std::vector<SigmaMint> spendable;

    // Get all spendable mints.
    ListSigmaMints(property, boost::make_function_output_iterator([&] (const SigmaMint& m) {
        if (m.denomination != denomination || m.chainState.block < 0 || !m.spentTx.IsNull()) {
            return;
        }
        spendable.push_back(m);
    }));

    if (spendable.empty()) {
        return boost::none;
    }

    // Pick the oldest mint.
    auto oldest = std::min_element(spendable.begin(), spendable.end(), [] (const SigmaMint& a, const SigmaMint& b) {
        if (a.chainState.group < b.chainState.group) {
            return true;
        } else if (a.chainState.group > b.chainState.group) {
            return false;
        }

        return a.chainState.index < b.chainState.index;
    });

    return *oldest;
}

void Wallet::SetSigmaMintUsedTransaction(SigmaMintId const &id, uint256 const &tx)
{
    LOCK(pwalletMain->cs_wallet);

    auto mint = GetSigmaMint(id);

    mint.spentTx = tx;

    if (!CWalletDB(walletFile).WriteExodusMint(id, mint)) {
        throw std::runtime_error("set used flag for mint on db fail");
    }
}

void Wallet::SetSigmaMintChainState(const SigmaMintId& id, const SigmaMintChainState& state)
{
    LOCK(pwalletMain->cs_wallet);

    auto mint = GetSigmaMint(id);

    mint.chainState = state;

    if (!CWalletDB(walletFile).WriteExodusMint(id, mint)) {
        throw std::runtime_error("update mint on db fail");
    }
}

void Wallet::OnMintAdded(
    PropertyId property,
    DenominationId denomination,
    MintGroupId group,
    MintGroupIndex idx,
    const SigmaPublicKey& pubKey,
    int block)
{
    SigmaMintId id(property, denomination, pubKey);

    LOCK(pwalletMain->cs_wallet); // Prevent race condition in the gap between a call to HasSigmaEntry and UpdateSigmaMint.

    if (!HasSigmaMint(id)) {
        return;
    }

    SetSigmaMintChainState(id, SigmaMintChainState(block, group, idx));
}

void Wallet::OnMintRemoved(PropertyId property, DenominationId denomination, const SigmaPublicKey& pubKey)
{
    SigmaMintId id(property, denomination, pubKey);

    LOCK(pwalletMain->cs_wallet); // Prevent race condition in the gap between a call to HasSigmaEntry and ClearSigmaMintChainState.

    if (!HasSigmaMint(id)) {
        return;
    }

    SetSigmaMintChainState(id, SigmaMintChainState());
}

}
