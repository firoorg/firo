#ifndef ZCOIN_WALLET_TXBUILDER_H
#define ZCOIN_WALLET_TXBUILDER_H

#include "wallet.h"

#include "../amount.h"
#include "../primitives/transaction.h"

#include <vector>

class TxBuilder
{
public:
    virtual ~TxBuilder();

    CWalletTx Build(const std::vector<CRecipient>& recipients, CAmount& fee) const;

protected:
    TxBuilder(CWallet& wallet) noexcept;

    virtual CAmount SetupInputs(CMutableTransaction& tx, CAmount required) const = 0;
    virtual CAmount AdjustFee(CAmount needed, unsigned txSize) const;

    CWallet& wallet;
};

class SigmaSpendBuilder : public TxBuilder
{
public:
    SigmaSpendBuilder(CWallet& wallet, std::vector<CZerocoinEntryV3>& selected);
    ~SigmaSpendBuilder() override;

protected:
    CAmount SetupInputs(CMutableTransaction& tx, CAmount required) const override;

private:
    std::vector<CZerocoinEntryV3>& selected;
};

#endif
