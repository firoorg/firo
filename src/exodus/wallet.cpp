#include "wallet.h"

#include "sigma.h"

#include "../main.h"
#include "../sync.h"
#include "../util.h"

#include "../wallet/walletdb.h"
#include "../wallet/walletexcept.h"

#include <boost/function_output_iterator.hpp>

#include <functional>

namespace exodus {

Wallet *wallet;

Wallet::Wallet(const std::string& walletFile) : walletFile(walletFile)
{
    using std::placeholders::_1;
    using std::placeholders::_2;
    using std::placeholders::_3;
    using std::placeholders::_4;
    using std::placeholders::_5;
    using std::placeholders::_6;

    // Subscribe to events.
    LOCK(cs_main);

    {
        auto h = std::bind(&Wallet::OnMintAdded, this, _1, _2, _3, _4, _5, _6);
        eventConnections.emplace_front(sigmaDb->MintAdded.connect(h));
    }
    {
        auto h = std::bind(&Wallet::OnMintRemoved, this, _1, _2, _3);
        eventConnections.emplace_front(sigmaDb->MintRemoved.connect(h));
    }
}

Wallet::~Wallet()
{
}

SigmaMintId Wallet::CreateSigmaMint(PropertyId property, SigmaDenomination denomination)
{
    SigmaMint mint(property, denomination);
    SigmaMintId id(mint, DefaultSigmaParams);

    CWalletDB(walletFile).WriteExodusMint(id, mint);

    return id;
}

SigmaSpend Wallet::CreateSigmaSpend(PropertyId property, SigmaDenomination denomination)
{
    LOCK(cs_main);

    auto mint = GetSpendableSigmaMint(property, denomination);
    if (!mint) {
        throw InsufficientFunds(_("No available mint to spend"));
    }

    // Get anonimity set for spend.
    std::vector<SigmaPublicKey> anonimitySet;

    sigmaDb->GetAnonimityGroup(
        mint->property,
        mint->denomination,
        mint->chainState.group,
        std::back_inserter(anonimitySet)
    );

    if (anonimitySet.size() < 2) {
        throw WalletError(_("Amount of coins in anonimity set is not enough to spend"));
    }

    // Create spend.
    SigmaProof proof(DefaultSigmaParams, mint->key, anonimitySet.begin(), anonimitySet.end());

    if (!VerifySigmaSpend(mint->property, mint->denomination, mint->chainState.group, anonimitySet.size(), proof)) {
        throw WalletError(_("Failed to create spendable spend"));
    }

    return SigmaSpend(SigmaMintId(*mint, DefaultSigmaParams), mint->chainState.group, anonimitySet.size(), proof);
}

bool Wallet::EraseSigmaMint(const SigmaMintId &id)
{
    return CWalletDB(walletFile).EraseExodusMint(id);
}

bool Wallet::HasSigmaMint(const SigmaMintId& id)
{
    return CWalletDB(walletFile).HasExodusMint(id);
}

SigmaMint Wallet::GetSigmaMint(const SigmaMintId& id)
{
    SigmaMint mint;

    if (!CWalletDB(walletFile).ReadExodusMint(id, mint)) {
        throw std::invalid_argument("Mint with specified identifier is not exists");
    }

    return mint;
}

void Wallet::SetSigmaMintUsedTransaction(SigmaMintId const &id, uint256 const &tx)
{
    auto mint = GetSigmaMint(id);

    mint.spentTx = tx;

    if (!CWalletDB(walletFile).WriteExodusMint(id, mint)) {
        throw std::runtime_error("Failed to write " + walletFile);
    }
}

void Wallet::SetSigmaMintChainState(const SigmaMintId& id, const SigmaMintChainState& state)
{
    auto mint = GetSigmaMint(id);

    mint.chainState = state;

    if (!CWalletDB(walletFile).WriteExodusMint(id, mint)) {
        throw std::runtime_error("Failed to write " + walletFile);
    }
}

boost::optional<SigmaMint> Wallet::GetSpendableSigmaMint(PropertyId property, SigmaDenomination denomination)
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

void Wallet::OnMintAdded(
    PropertyId property,
    SigmaDenomination denomination,
    SigmaMintGroup group,
    SigmaMintIndex idx,
    const SigmaPublicKey& pubKey,
    int block)
{
    SigmaMintId id(property, denomination, pubKey);

    if (!HasSigmaMint(id)) {
        return;
    }

    SetSigmaMintChainState(id, SigmaMintChainState(block, group, idx));
}

void Wallet::OnMintRemoved(PropertyId property, SigmaDenomination denomination, const SigmaPublicKey& pubKey)
{
    SigmaMintId id(property, denomination, pubKey);

    if (!HasSigmaMint(id)) {
        return;
    }

    SetSigmaMintChainState(id, SigmaMintChainState());
}

} // namespace exodus
