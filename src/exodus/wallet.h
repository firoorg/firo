#ifndef EXODUS_WALLET_H
#define EXODUS_WALLET_H

#include <string>

#include "sigma.h"
#include "walletdb.h"
#include <wallet/wallet.h>

extern CWallet* pwalletMain;

namespace exodus {

class Wallet
{
public:
    Wallet(const std::string& walletFile)
        : walletFile(walletFile)
    {
    }

    SigmaPublicKey CreateSigmaMint(
        uint32_t propertyId,
        uint8_t denomination
    );

    bool UpdateSigmaMint(
        const SigmaMintId& id,
        uint32_t groupId,
        uint16_t index,
        int32_t block
    );

    bool ClearSigmaMintChainState(const SigmaMintId& id);
    bool SetSigmaMintUsedStatus(const SigmaMintId& id, bool isUsed);

protected:
    template<class OutputIt>
    void ListSigmaEntries(OutputIt it)
    {
        LOCK(pwalletMain->cs_wallet);

        auto insertF = [&it] (exodus::SigmaEntry& entry) {
            *it++ = std::move(entry);
        };
        CWalletDB(walletFile).ListExodusMint<SigmaMintId, exodus::SigmaEntry>(insertF);
    }
    template<class OutputIt>
    void ListSigmaEntries(uint32_t propertyId, OutputIt it)
    {
        LOCK(pwalletMain->cs_wallet);

        auto insertF = [propertyId, &it](exodus::SigmaEntry& entry) {
            if (entry.propertyId == propertyId) {
                *it++ = std::move(entry);
            }
        };

        CWalletDB(walletFile).ListExodusMint<SigmaMintId, exodus::SigmaEntry>(insertF);
    }

    bool HasSigmaEntry(const SigmaMintId& id);
    SigmaEntry GetSigmaEntry(const SigmaMintId& id);

private:
    std::string walletFile;
};

}

#endif // EXODUS_WALLET_H
