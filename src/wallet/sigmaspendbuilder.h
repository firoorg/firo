#ifndef ZCOIN_WALLET_SIGMASPENDBUILDER_H
#define ZCOIN_WALLET_SIGMASPENDBUILDER_H

#include "txbuilder.h"

#include <vector>

class SigmaSpendBuilder : public TxBuilder
{
public:
    std::vector<CSigmaEntry> selected;
    std::vector<CSigmaEntry> changes;
    std::vector<sigma::CoinDenomination> denomChanges;

public:
    SigmaSpendBuilder(CWallet& wallet, const CCoinControl *coinControl = NULL);
    ~SigmaSpendBuilder() override;

protected:
    CAmount GetInputs(std::vector<std::unique_ptr<InputSigner>>& signers, CAmount required) override;
    CAmount GetChanges(std::vector<CTxOut>& outputs, CAmount amount) override;
};

#endif
