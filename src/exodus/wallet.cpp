#include "wallet.h"

#include "walletdb.h"

#include "../wallet/wallet.h"
#include "../wallet/walletdb.h"

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

SigmaMintId Wallet::CreateSigmaMint(
    uint32_t propertyId,
    uint8_t denomination)
{
    SigmaPrivateKey key;

    key.Generate();

    SigmaEntry e;
    e.propertyId = propertyId;
    e.denomination = denomination;
    e.privateKey = key;

    {
        LOCK(pwalletMain->cs_wallet);
        CWalletDB(walletFile).WriteExodusMint(e.GetId(), e);
    }

    return e.GetId();
}

SigmaMintChainState Wallet::GetSigmaMintChainState(const SigmaMintId& id)
{
    LOCK(pwalletMain->cs_wallet);

    return GetSigmaEntry(id).chainState;
}

boost::optional<SigmaEntry> Wallet::GetSpendableSigmaMint(uint32_t propertyId, uint8_t denomination)
{
    AssertLockHeld(pwalletMain->cs_wallet);
    std::list<SigmaEntry> allCoins;
    ListSigmaEntries(propertyId, std::back_inserter(allCoins));

    auto last = std::remove_if(allCoins.begin(), allCoins.end(), [denomination](SigmaEntry const &entry) -> bool {
        return entry.denomination != denomination
            || entry.chainState.block < 0
            || !entry.tx.IsNull();
    });
    allCoins.erase(last, allCoins.end());

    if (allCoins.empty()) {
        return boost::none;
    }

    auto chosenCoin = std::min_element(allCoins.begin(), allCoins.end(),
        [](SigmaEntry const &a, SigmaEntry const &b) -> bool {
            return a.chainState.index < b.chainState.index;
        }
    );

    return *chosenCoin;
}

void Wallet::SetSigmaMintChainState(const SigmaMintId& id, const SigmaMintChainState& state)
{
    LOCK(pwalletMain->cs_wallet);

    auto e = GetSigmaEntry(id);

    if (!e.tx.IsNull()) {
        throw std::logic_error("the mint have been spend");
    }

    e.chainState = state;

    if (!CWalletDB(walletFile).WriteExodusMint(e.GetId(), e)) {
        throw std::runtime_error("update mint on db fail");
    }
}

void Wallet::SetSigmaMintUsedTransaction(SigmaMintId const &id, uint256 const &tx)
{
    LOCK(pwalletMain->cs_wallet);

    auto e = GetSigmaEntry(id);
    e.tx = tx;

    if (!CWalletDB(walletFile).WriteExodusMint(e.GetId(), e)) {
        throw std::runtime_error("set used flag for mint on db fail");
    }
}

SigmaEntry Wallet::GetSigmaEntry(const SigmaMintId& id)
{
    LOCK(pwalletMain->cs_wallet);

    SigmaEntry e;
    if (!CWalletDB(walletFile).ReadExodusMint(id, e)) {
        throw std::runtime_error("sigma mint not found");
    }
    return e;
}

bool Wallet::HasSigmaEntry(const SigmaMintId& id)
{
    LOCK(pwalletMain->cs_wallet);
    return CWalletDB(walletFile).HasExodusMint(id);
}

void Wallet::OnMintAdded(
    PropertyId property,
    DenominationId denomination,
    MintGroupId group,
    MintGroupIndex idx,
    const SigmaPublicKey& pubKey,
    int block)
{
    SigmaMintId id(pubKey, property, denomination);

    LOCK(pwalletMain->cs_wallet); // Prevent race condition in the gap between a call to HasSigmaEntry and UpdateSigmaMint.

    if (!HasSigmaEntry(id)) {
        return;
    }

    SetSigmaMintChainState(id, SigmaMintChainState(block, group, idx));
}

void Wallet::OnMintRemoved(PropertyId property, DenominationId denomination, const SigmaPublicKey& pubKey)
{
    SigmaMintId id(pubKey, property, denomination);

    LOCK(pwalletMain->cs_wallet); // Prevent race condition in the gap between a call to HasSigmaEntry and ClearSigmaMintChainState.

    if (!HasSigmaEntry(id)) {
        return;
    }

    SetSigmaMintChainState(id, SigmaMintChainState());
}

}
