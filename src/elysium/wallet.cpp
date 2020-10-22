#include "wallet.h"

#include "lelantusdb.h"

#include "sigma.h"

#include "../validation.h"
#include "../sync.h"
#include "../util.h"

#include "../wallet/walletdb.h"
#include "../wallet/walletexcept.h"

#include <boost/function_output_iterator.hpp>

#include <functional>
#include <utility>

namespace elysium {

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
    {
        auto h = std::bind(&Wallet::OnLelantusMintAdded, this, _1, _2, _3, _4, _5, _6);
        eventConnections.emplace_front(lelantusDb->MintAdded.connect(h));
    }
    {
        auto h = std::bind(&Wallet::OnLelantusMintRemoved, this, _1, _2);
        eventConnections.emplace_front(lelantusDb->MintRemoved.connect(h));
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

LelantusWallet::MintReservation Wallet::CreateLelantusMint(PropertyId property, LelantusAmount amount)
{
    return lelantusWallet.GenerateMint(property, amount);
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

void Wallet::SetLelantusMintUsedTransaction(const MintEntryId& id, const uint256& tx)
{
    lelantusWallet.UpdateMintSpendTx(id, tx);
}

void Wallet::ClearAllChainState()
{
    mintWalletV0.ClearMintsChainState();
    mintWalletV1.ClearMintsChainState();
}

bool Wallet::SyncWithChain()
{
    return lelantusWallet.SyncWithChain();
}

SigmaSpend Wallet::CreateSigmaSpendV0(PropertyId property, SigmaDenomination denomination, bool fPadding)
{
    return CreateSigmaSpend(property, denomination, fPadding, SigmaMintVersion::V0);
}

SigmaSpend Wallet::CreateSigmaSpendV1(PropertyId property, SigmaDenomination denomination, bool fPadding)
{
    return CreateSigmaSpend(property, denomination, fPadding, SigmaMintVersion::V1);
}

lelantus::JoinSplit Wallet::CreateLelantusJoinSplit(
    PropertyId property,
    CAmount amountToSpend,
    uint256 const &metadata,
    std::vector<SpendableCoin> &spendables,
    boost::optional<LelantusWallet::MintReservation> &changeMint,
    LelantusAmount &changeValue)
{
    return lelantusWallet.CreateJoinSplit(property, amountToSpend, metadata, spendables, changeMint, changeValue);
}

SigmaSpend Wallet::CreateSigmaSpend(PropertyId property, SigmaDenomination denomination, bool fPadding, SigmaMintVersion version)
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

    if (!VerifySigmaSpend(mint->property, mint->denomination, mint->chainState.group, anonimitySet.size(), proof, key.serial, fPadding)) {
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
    return GetSigmaMintVersion(id) != boost::none;
}

bool Wallet::HasSigmaMint(const secp_primitives::Scalar& serial)
{
    return GetSigmaMintVersion(serial) != boost::none;
}

bool Wallet::HasLelantusMint(const MintEntryId& id)
{
    return lelantusWallet.HasMint(id);
}

bool Wallet::HasLelantusMint(const secp_primitives::Scalar &serial)
{
    return lelantusWallet.HasMint(serial);
}

SigmaMint Wallet::GetSigmaMint(const SigmaMintId& id)
{
    auto &wallet = GetMintWallet(id);
    return wallet.GetMint(id);
}

CKey Wallet::GetSigmaSignatureKey(const SigmaMintId &id)
{
    return mintWalletV1.GetSignatureKey(id);
}

boost::optional<SigmaMint> Wallet::GetSpendableSigmaMint(PropertyId property, SigmaDenomination denomination, SigmaMintVersion version)
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

void Wallet::SetLelantusMintChainState(const MintEntryId &id, const LelantusMintChainState &state)
{
    lelantusWallet.UpdateMintChainstate(id, state);
}

SigmaWallet& Wallet::GetMintWallet(SigmaMintVersion version)
{
    switch (version) {
    case SigmaMintVersion::V0:
        return mintWalletV0;
    case SigmaMintVersion::V1:
        return mintWalletV1;
    default:
        throw new std::invalid_argument("Coin version is not found.");
    }
}

SigmaWallet& Wallet::GetMintWallet(SigmaMintId const &id)
{
    auto version = GetSigmaMintVersion(id);
    if (version) {
        return GetMintWallet(version.get());
    }

    throw std::invalid_argument("Sigma Mint Id is not found.");
}

boost::optional<Wallet::SigmaMintVersion> Wallet::GetSigmaMintVersion(const SigmaMintId& id)
{
    if (mintWalletV0.HasMint(id)) {
        return SigmaMintVersion::V0;
    } else if (mintWalletV1.HasMint(id)) {
        return SigmaMintVersion::V1;
    }

    return boost::none;
}

boost::optional<Wallet::SigmaMintVersion> Wallet::GetSigmaMintVersion(const secp_primitives::Scalar &scalar)
{
    if (mintWalletV0.HasMint(scalar)) {
        return SigmaMintVersion::V0;
    } else if (mintWalletV1.HasMint(scalar)) {
        return SigmaMintVersion::V1;
    }

    return boost::none;
}

void Wallet::OnSpendAdded(
    PropertyId property,
    SigmaDenomination denomination,
    const secp_primitives::Scalar &serial,
    const uint256 &tx)
{
    auto version = GetSigmaMintVersion(serial);
    if (!version) {
        // the serial is not in wallet.
        return;
    }

    SigmaMintId id;
    auto &mintWallet = GetMintWallet(version.get());
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
    auto version = GetSigmaMintVersion(serial);
    if (!version) {
        // the serial is not in wallet.
        return;
    }

    auto &mintWallet = GetMintWallet(version.get());
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

        if (mintWalletV1.TryRecoverMint(id, chainState)) {
            LogPrintf("%s : Found new mint when try to recover\n", __func__);
        } else if (mintWalletV0.TryRecoverMint(id, chainState)) {
            LogPrintf("%s : Found new legacy mint when try to recover\n", __func__);
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

void Wallet::OnLelantusMintAdded(
    PropertyId property,
    MintEntryId id,
    LelantusGroup group,
    LelantusIndex idx,
    boost::optional<LelantusAmount> amount,
    int block)
{
    LogPrintf("%s : Mint added = block : %d, group : %d, idx : %d\n", __func__, block, group, idx);
    if (HasLelantusMint(id)) {

        // 1. is in wallet then update state
        SetLelantusMintChainState(id, {block, group, idx});
    } else {

        // 2. try to recover new mint
        LelantusMintChainState state(block, group, idx);
        if (lelantusWallet.TryRecoverMint(id, state, property, amount.get())) {
            LogPrintf("%s : Found new mint when try to recover\n", __func__);
        }
    }
}

void Wallet::OnLelantusMintRemoved(
    PropertyId property,
    MintEntryId id)
{
    if (!HasLelantusMint(id)) {
        return;
    }

    SetLelantusMintChainState(id, {});
}

} // namespace elysium
