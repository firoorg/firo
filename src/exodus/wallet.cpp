#include "wallet.h"
#include "walletdb.h"

#include "../wallet/wallet.h"
#include "../wallet/walletdb.h"

namespace exodus {

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

void Wallet::UpdateSigmaMint(
    const SigmaMintId& id,
    uint32_t groupId,
    uint16_t index,
    int32_t block)
{
    LOCK(pwalletMain->cs_wallet);

    auto e = GetSigmaEntry(id);
    e.groupId = groupId;
    e.index = index;
    e.block = block;
    e.isUsed = false;

    if (!CWalletDB(walletFile).WriteExodusMint(e.GetId(), e)) {
        throw std::runtime_error("update mint on db fail");
    }
}

void Wallet::ClearSigmaMintChainState(
    const SigmaMintId& id)
{
    LOCK(pwalletMain->cs_wallet);

    auto e = GetSigmaEntry(id);
    e.groupId = 0;
    e.index = 0;
    e.block = -1;
    e.isUsed = false;

    if (!CWalletDB(walletFile).WriteExodusMint(e.GetId(), e)) {
        throw std::runtime_error("clear mint on db fail");
    }
}

void Wallet::SetSigmaMintUsedStatus(const SigmaMintId& id, bool isUsed)
{
    LOCK(pwalletMain->cs_wallet);

    auto e = GetSigmaEntry(id);
    e.isUsed = isUsed;

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

}