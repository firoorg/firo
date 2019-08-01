#ifndef EXODUS_WALLET_H
#define EXODUS_WALLET_H

#include <string>

#include "sigma.h"
#include "walletdb.h"

namespace exodus {

class ExodusWallet
{
public:
    ExodusWallet() {}

    ExodusWallet(const std::string& strWalletFileIn)
    {
        SetNull();

        strWalletFile = strWalletFileIn;
    }

    SigmaPrivateKey CreateSigmaPrivateKey();

    CSigmaEntry RecordSigmaKey(
        uint32_t propertyID,
        uint32_t denomination,
        const SigmaPrivateKey& key
    );

    bool UpdateSigma(
        const secp_primitives::GroupElement& val,
        uint32_t groupID,
        uint32_t index,
        int nBlock
    );

    bool DeleteFromChain(const secp_primitives::GroupElement& key);
    bool SetUsedStatus(const secp_primitives::GroupElement& val, bool isUsed);
    CSigmaEntry GetSigmaEntry(const secp_primitives::GroupElement& key);

    void ListSigmaEntries(std::list<CSigmaEntry>& listSigma);
    void ListSigmaEntries(uint32_t propertyID, std::list<CSigmaEntry>& listSigma);

    bool HasSigmaEntry(const secp_primitives::GroupElement& val);

private:
    std::string strWalletFile;

    void SetNull()
    {
    }
};

}

#endif // EXODUS_WALLET_H
