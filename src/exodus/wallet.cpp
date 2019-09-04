#include "wallet.h"

#include "../wallet/wallet.h"
#include "../wallet/walletdb.h"

#include <boost/function_output_iterator.hpp>

#include <functional>

namespace exodus {

Wallet *wallet;

Wallet::Wallet(const std::string& walletFile, CMPMintList& sigmaDb)
    : walletFile(walletFile), mintWallet(walletFile)
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
    {
        auto h = std::bind(&Wallet::OnSpendAdded, this, _1, _2, _3, _4);
        eventConnections.emplace_front(sigmaDb.SpendAdded.connect(h));
    }
    {
        auto h = std::bind(&Wallet::OnSpendRemoved, this, _1, _2, _3);
        eventConnections.emplace_front(sigmaDb.SpendRemoved.connect(h));
    }
}

Wallet::~Wallet()
{
}

SigmaMintId Wallet::CreateSigmaMint(PropertyId property, DenominationId denomination)
{
    SigmaPrivateKey key;
    HDMint mint;
    LOCK(pwalletMain->cs_wallet);
    if (!mintWallet.GenerateMint(property, denomination, key, mint)) {
        throw std::runtime_error("fail to generate mint");
    }

    mintWallet.GetTracker().Add(mint, true);

    return SigmaMintId(property, denomination, SigmaPublicKey(key));
}

bool Wallet::HasSigmaMint(const SigmaMintId& id)
{
    LOCK(pwalletMain->cs_wallet);
    auto pubcoinHash = primitives::GetPubCoinValueHash(id.key.GetCommitment());
    return mintWallet.GetTracker().HasPubcoinHash(pubcoinHash);
}

bool Wallet::HasSigmaSpend(const secp_primitives::Scalar& serial, MintMeta &meta)
{
    auto serialHash = primitives::GetSerialHash(serial);
    return mintWallet.GetTracker().GetMetaFromSerial(serialHash, meta);
}

SigmaMint Wallet::GetSigmaMint(const SigmaMintId& id)
{
    HDMint mint;
    SigmaMint entry;

    LOCK(pwalletMain->cs_wallet);
    auto pubCoinHash = primitives::GetPubCoinValueHash(id.key.GetCommitment());

    CWalletDB walletdb(walletFile);
    if (!walletdb.ReadExodusHDMint(pubCoinHash, mint)) {
        throw std::invalid_argument("sigma mint not found");
    }

    if (!mintWallet.RegenerateMint(mint, entry)) {
        throw std::runtime_error("fail to regenerate mint");
    }

    return entry;
}

boost::optional<SigmaMint> Wallet::GetSpendableSigmaMint(PropertyId property, DenominationId denomination)
{
    // Get all spendable mints.
    LOCK(pwalletMain->cs_wallet);
    auto spendables = mintWallet.GetTracker().ListMetas(true, true, false);

    auto eraseFrom = std::remove_if(spendables.begin(), spendables.end(), [denomination](MintMeta const &meta) -> bool {
        return denomination != meta.denomination;
    });
    spendables.erase(eraseFrom, spendables.end());

    if (spendables.empty()) {
        return boost::none;
    }

    // Pick the oldest mint.
    auto oldest = std::min_element(spendables.begin(), spendables.end(),
        [](const MintMeta& a, const MintMeta& b) {
            if (a.chainState.group == b.chainState.group) {
                return a.chainState.index < b.chainState.index;
            }

            return a.chainState.group < b.chainState.group;
        }
    );

    SigmaMint entry;
    CWalletDB walletdb(walletFile);
    HDMint mint;

    if (!walletdb.ReadExodusHDMint(oldest->GetPubCoinValueHash(), mint)) {
        throw std::runtime_error("fail to get mint data");
    }

    if (!mintWallet.RegenerateMint(mint, entry)) {
        throw std::runtime_error("fail to regenerate mint");
    }

    return entry;
}

void Wallet::SetSigmaMintUsedTransaction(SigmaMintId const &id, uint256 const &tx)
{
    mintWallet.GetTracker().SetMintSpendTx(
        primitives::GetPubCoinValueHash(id.key.GetCommitment()), tx);
}

void Wallet::SetSigmaMintChainState(const SigmaMintId& id, const SigmaMintChainState& state)
{
    mintWallet.GetTracker().SetChainState(
        primitives::GetPubCoinValueHash(id.key.GetCommitment()), state);
}

void Wallet::OnSpendAdded(
    PropertyId property,
    DenominationId denomination,
    const secp_primitives::Scalar &serial,
    const uint256 &tx)
{
    auto serialHash = primitives::GetSerialHash(serial);

    MintMeta meta;
    if (!HasSigmaSpend(serial, meta)) {
        // the serial is not in wallet.
        return;
    }

    SigmaPublicKey pubKey;
    pubKey.SetCommitment(meta.GetPubCoinValue());
    SigmaMintId id(property, denomination, pubKey);

    SetSigmaMintUsedTransaction(id, tx);
}

void Wallet::OnSpendRemoved(
    PropertyId property,
    DenominationId denomination,
    const secp_primitives::Scalar &serial)
{
    auto serialHash = primitives::GetSerialHash(serial);

    MintMeta meta;
    if (!HasSigmaSpend(serial, meta)) {
        // the serial is not in wallet.
        return;
    }

    SigmaPublicKey pubKey;
    pubKey.SetCommitment(meta.GetPubCoinValue());
    SigmaMintId id(property, denomination, pubKey);
    SetSigmaMintUsedTransaction(id, uint256());
}

void Wallet::OnMintAdded(
    PropertyId property,
    DenominationId denomination,
    MintGroupId group,
    MintGroupIndex idx,
    const SigmaPublicKey& pubKey,
    int block)
{
    LOCK(pwalletMain->cs_wallet); // Prevent race condition in the gap between a call to HasSigmaEntry and UpdateSigmaMint.

    // Try to catch unseen
    auto pubCoinHash = primitives::GetPubCoinValueHash(pubKey.GetCommitment());
    if (mintWallet.GetMintPool().count(pubCoinHash)) {
        auto entry = mintWallet.GetMintPool().at(pubCoinHash);
        mintWallet.SetMintSeedSeen(
            {pubCoinHash, entry}, property, denomination, SigmaMintChainState(block, group, idx));
    }

    SigmaMintId id(property, denomination, pubKey);

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
