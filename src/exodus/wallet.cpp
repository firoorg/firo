#include "wallet.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "walletdb.h"

namespace exodus {

SigmaPublicKey Wallet::CreateSigmaMint(
    uint32_t propertyId,
    uint8_t denomination)
{
    SigmaPrivateKey key;

    do {
        key.Generate();
    } while (!key.IsValid());

    SigmaEntry e;
    e.SetNull();
    e.propertyId = propertyId;
    e.denomination = denomination;
    e.randomness = key.GetRandomness();
    e.serialNumber = key.GetSerial();

    {
        LOCK(pwalletMain->cs_wallet);
        CWalletDB(walletFile).WriteExodusMint(e.GetId(), e);
    }

    return e.getPublicKey();
}

bool Wallet::UpdateSigmaMint(
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

    return CWalletDB(walletFile).WriteExodusMint(e.GetId(), e);
}

bool Wallet::ClearSigmaMintChainState(
    const SigmaMintId& id)
{
    LOCK(pwalletMain->cs_wallet);

    auto e = GetSigmaEntry(id);
    e.groupId = 0;
    e.index = 0;
    e.block = -1;
    e.isUsed = false;

    return CWalletDB(walletFile).WriteExodusMint(e.GetId(), e);
}

bool Wallet::SetSigmaMintUsedStatus(const SigmaMintId& id, bool isUsed)
{
    LOCK(pwalletMain->cs_wallet);

    auto e = GetSigmaEntry(id);
    e.isUsed = isUsed;

    return CWalletDB(walletFile).WriteExodusMint(e.GetId(), e);
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
    return CWalletDB(walletFile).HasExodusMint(id);
}

}