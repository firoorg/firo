#include "wallet.h"
#include "wallet/walletdb.h"
#include "walletdb.h"

namespace exodus {

SigmaPrivateKey ExodusWallet::CreateSigmaPrivateKey()
{
    SigmaPrivateKey key;

    do {
        key.Generate();
    } while (!key.IsValid());

    return key;
}

CSigmaEntry ExodusWallet::RecordSigmaKey(
    uint32_t propertyID,
    uint32_t denomination,
    const SigmaPrivateKey& key)
{
    CSigmaEntry e;
    e.propertyID = propertyID;
    e.denomination = denomination;

    e.value = SigmaPublicKey(key).GetCommitment();
    e.randomness = e.randomness;
    e.serialNumber = e.serialNumber;
    e.isUsed = false;

    CWalletDB(strWalletFile).WriteExodusEntry(e.value, e);

    return e;
}

bool ExodusWallet::UpdateSigma(
    const secp_primitives::GroupElement& val,
    uint32_t groupID,
    uint32_t index,
    int nBlock)
{
    auto e = GetSigmaEntry(val);
    e.groupID = groupID;
    e.index = index;
    e.nBlock = nBlock;
    e.isUsed = false;

    return CWalletDB(strWalletFile).WriteExodusEntry(e.value, e);
}

bool ExodusWallet::DeleteFromChain(
    const secp_primitives::GroupElement& val)
{
    auto e = GetSigmaEntry(val);
    e.groupID = 0;
    e.index = 0;
    e.nBlock = -1;
    e.isUsed = false;

    return CWalletDB(strWalletFile).WriteExodusEntry(e.value, e);
}

bool ExodusWallet::SetUsedStatus(const secp_primitives::GroupElement& val, bool isUsed)
{
    auto e = GetSigmaEntry(val);
    e.isUsed = isUsed;

    return CWalletDB(strWalletFile).WriteExodusEntry(e.value, e);
}

CSigmaEntry ExodusWallet::GetSigmaEntry(const secp_primitives::GroupElement& key)
{
    CSigmaEntry e;
    CWalletDB(strWalletFile).ReadExodusEntry(key, e);
    return e;
}

void ExodusWallet::ListSigmaEntries(std::list<CSigmaEntry>& listSigma)
{
    CWalletDB(strWalletFile).
        ListExodusEntries<secp_primitives::GroupElement>(listSigma);
}

void ExodusWallet::ListSigmaEntries(
    uint32_t propertyID, std::list<CSigmaEntry>& listSigma)
{
    ListSigmaEntries(listSigma);
    listSigma.erase(
        std::remove_if(listSigma.begin(), listSigma.end(),
            [propertyID] (const CSigmaEntry& e) -> bool {
                return e.propertyID != propertyID;
            }
        ), listSigma.end());
}

bool ExodusWallet::HasSigmaEntry(const secp_primitives::GroupElement& val)
{
    return CWalletDB(strWalletFile).HasExodusEntry(val);
}

}