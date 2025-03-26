#ifndef FIRO_WALLET_TXBUILDER_H
#define FIRO_WALLET_TXBUILDER_H

#include "wallet.h"

#include "../amount.h"
#include "../script/script.h"
#include "../primitives/transaction.h"
#include "../uint256.h"

#include <memory>
#include <vector>

#include <inttypes.h>

class SigmaTxBuilderInputSigner
{
public:
    COutPoint output;
    uint32_t sequence;

public:
    SigmaTxBuilderInputSigner();
    explicit SigmaTxBuilderInputSigner(const COutPoint& output, uint32_t seq = CTxIn::SEQUENCE_FINAL);
    virtual ~SigmaTxBuilderInputSigner();

    virtual CScript Sign(const CMutableTransaction& tx, const uint256& sig) = 0;
};

// This is only used for legacy Sigma code. Don't bother editing anything in it.
class SigmaTxBuilderSuperclass
{
public:
    CWallet& wallet;
    const CCoinControl *coinControl;

public:
    explicit SigmaTxBuilderSuperclass(CWallet& wallet) noexcept;
    virtual ~SigmaTxBuilderSuperclass();

    CWalletTx Build(const std::vector<CRecipient>& recipients, CAmount& fee,  bool& fChangeAddedToFee, CWalletDB& walletdb);

protected:
    virtual CAmount GetInputs(std::vector<std::unique_ptr<SigmaTxBuilderInputSigner>>& signers, CAmount required) = 0;
    virtual CAmount GetChanges(std::vector<CTxOut>& outputs, CAmount amount, CWalletDB& walletdb) = 0;
    virtual CAmount AdjustFee(CAmount needed, unsigned txSize);
};

#endif
