#include "wallet.h"

#include "sigma.h"

#include "../main.h"
#include "../sync.h"
#include "../util.h"

#include "../wallet/walletdb.h"
#include "../wallet/walletexcept.h"

#include <boost/function_output_iterator.hpp>

#include <functional>
#include <utility>

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
    {
        auto h = std::bind(&Wallet::OnSpendAdded, this, _1, _2, _3, _4);
        eventConnections.emplace_front(sigmaDb->SpendAdded.connect(h));
    }
    {
        auto h = std::bind(&Wallet::OnSpendRemoved, this, _1, _2, _3);
        eventConnections.emplace_front(sigmaDb->SpendRemoved.connect(h));
    }
}

Wallet::~Wallet()
{
}

void Wallet::ReloadMasterKey()
{
    mintWalletV0.ReloadMasterKey();
    mintWalletV1.ReloadMasterKey();
}

SigmaMintId Wallet::CreateSigmaMint(PropertyId property, SigmaDenomination denomination)
{
    return mintWalletV1.GenerateMint(property, denomination);
}

void Wallet::SetSigmaMintCreatedTransaction(const SigmaMintId& id, const uint256& tx)
{
    auto &wallet = GetMintWallet(id);
    wallet.UpdateMintCreatedTx(id, tx);
}

void Wallet::SetSigmaMintUsedTransaction(const SigmaMintId& id, const uint256& tx)
{
    auto &wallet = GetMintWallet(id);
    wallet.UpdateMintSpendTx(id, tx);
}

void Wallet::ClearAllChainState()
{
    mintWalletV0.ClearMintsChainState();
    mintWalletV1.ClearMintsChainState();
}

SigmaSpend Wallet::CreateSigmaSpend(PropertyId property, SigmaDenomination denomination, bool fPadding)
{
    return CreateSigmaSpend(property, denomination, fPadding, CoinVersion::SigmaV1);
}

SigmaSpend Wallet::CreateLegacySigmaSpend(PropertyId property, SigmaDenomination denomination, bool fPadding)
{
    return CreateSigmaSpend(property, denomination, fPadding, CoinVersion::SigmaV0);
}

SigmaSpend Wallet::CreateSigmaSpend(PropertyId property, SigmaDenomination denomination, bool fPadding, CoinVersion version)
{
    LOCK(cs_main);

    auto mint = GetSpendableSigmaMint(property, denomination, version);
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
    auto key = GetKey(mint.get());
    SigmaProof proof(DefaultSigmaParams, key, anonimitySet.begin(), anonimitySet.end(), fPadding);

    if (!VerifySigmaSpend(mint->property, mint->denomination, mint->chainState.group, anonimitySet.size(), proof, fPadding)) {
        throw WalletError(_("Failed to create spendable spend"));
    }

    return SigmaSpend(SigmaMintId(mint->property, mint->denomination, SigmaPublicKey(key, DefaultSigmaParams)),
        mint->chainState.group, anonimitySet.size(), proof);
}

void Wallet::DeleteUnconfirmedSigmaMint(const SigmaMintId &id)
{
    auto &wallet = GetMintWallet(id);
    wallet.DeleteUnconfirmedMint(id);
}

bool Wallet::HasSigmaMint(const SigmaMintId& id)
{
    CoinVersion version;
    return HasSigmaMint(id, version);
}

bool Wallet::HasSigmaMint(const secp_primitives::Scalar& serial)
{
    CoinVersion version;
    return HasSigmaMint(serial, version);
}

SigmaMint Wallet::GetSigmaMint(const SigmaMintId& id)
{
    auto &wallet = GetMintWallet(id);
    return wallet.GetMint(id);
}

CoinSigner Wallet::GetSigmaSigner(const SigmaMintId &id)
{
    return mintWalletV1.GetSigner(id);
}

boost::optional<SigmaMint> Wallet::GetSpendableSigmaMint(PropertyId property, SigmaDenomination denomination, CoinVersion version)
{
    // Get all spendable mints.
    std::vector<SigmaMint> spendables;

    auto &mintWallet = GetMintWallet(version);
    mintWallet.ListMints(boost::make_function_output_iterator([&] (const std::pair<SigmaMintId, SigmaMint>& m) {
        if (m.second.property != property || m.second.denomination != denomination) {
            return;
        }

        if (m.second.IsSpent() || !m.second.IsOnChain()) {
            return;
        }

        spendables.push_back(m.second);
    }));

    if (spendables.empty()) {
        return boost::none;
    }

    // Pick the oldest mint.
    auto oldest = std::min_element(
        spendables.begin(),
        spendables.end(),
        [](const SigmaMint& a, const SigmaMint& b) -> bool {

            if (a.chainState.group == b.chainState.group) {
                return a.chainState.index < b.chainState.index;
            }

            return a.chainState.group < b.chainState.group;
        }
    );

    return *oldest;
}

SigmaPrivateKey Wallet::GetKey(const SigmaMint &mint)
{
    // Try all mint wallets
    try {
        return mintWalletV1.GeneratePrivateKey(mint.seedId);
    } catch (...) {
        return mintWalletV0.GeneratePrivateKey(mint.seedId);
    }
}

void Wallet::SetSigmaMintChainState(const SigmaMintId& id, const SigmaMintChainState& state)
{
    auto &mintWallet = GetMintWallet(id);
    mintWallet.UpdateMintChainstate(id, state);
}

SigmaWallet& Wallet::GetMintWallet(CoinVersion version)
{
    switch (version) {
    case CoinVersion::SigmaV0:
        return mintWalletV0;
    case CoinVersion::SigmaV1:
        return mintWalletV1;
    default:
        throw new std::runtime_error("Coin version is not found.");
    }
}

SigmaWallet& Wallet::GetMintWallet(SigmaMintId const &id)
{
    CoinVersion version;
    if (HasSigmaMint(id, version)) {
        return GetMintWallet(version);
    }

    throw std::runtime_error("Sigma Mint Id is not found.");
}

bool Wallet::HasSigmaMint(const SigmaMintId& id, CoinVersion &version)
{
    if (mintWalletV0.HasMint(id)) {
        version = CoinVersion::SigmaV0;
        return true;
    } else if (mintWalletV1.HasMint(id)) {
        version = CoinVersion::SigmaV1;
        return true;
    }

    return false;
}

bool Wallet::HasSigmaMint(const secp_primitives::Scalar &scalar, CoinVersion &version)
{
    if (mintWalletV0.HasMint(scalar)) {
        version = CoinVersion::SigmaV0;
        return true;
    } else if (mintWalletV1.HasMint(scalar)) {
        version = CoinVersion::SigmaV1;
        return true;
    }

    return false;
}

void Wallet::OnSpendAdded(
    PropertyId property,
    SigmaDenomination denomination,
    const secp_primitives::Scalar &serial,
    const uint256 &tx)
{
    CoinVersion version;
    if (!HasSigmaMint(serial, version)) {
        // the serial is not in wallet.
        return;
    }

    SigmaMintId id;
    auto &mintWallet = GetMintWallet(version);
    try {
        id = mintWallet.GetMintId(serial);
    } catch (std::runtime_error const &e) {
        LogPrintf("%s : fail to get mint id when spend added have been triggered, %s\n", e.what());
        throw;
    }
    SetSigmaMintUsedTransaction(id, tx);
}

void Wallet::OnSpendRemoved(
    PropertyId property,
    SigmaDenomination denomination,
    const secp_primitives::Scalar &serial)
{
    CoinVersion version;
    if (!HasSigmaMint(serial, version)) {
        // the serial is not in wallet.
        return;
    }

    auto &mintWallet = GetMintWallet(version);
    try {
        auto id = mintWallet.GetMintId(serial);
        SetSigmaMintUsedTransaction(id, uint256());
    } catch (std::runtime_error const &e) {
        LogPrintf("%s : fail to get mint id when spend removed have been triggered, %s\n", e.what());
        throw;
    }
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

    if (HasSigmaMint(id)) {

        // 1. is in wallet then update state
        SetSigmaMintChainState(id, SigmaMintChainState(block, group, idx));
    } else {

        // 2. try to recover new mint
        SigmaMintChainState chainState(block, group, idx);
        if (mintWalletV0.TryRecoverMint(id, chainState)) {
            LogPrintf("%s : Found new legacy mint when try to recover\n", __func__);
        }

        if (mintWalletV1.TryRecoverMint(id, chainState)) {
            LogPrintf("%s : Found new mint when try to recover\n", __func__);
        }
    }
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
