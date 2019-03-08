#ifndef ZCOIN_WALLET_SIGMASPENDBUILDER_H
#define ZCOIN_WALLET_SIGMASPENDBUILDER_H

#include "txbuilder.h"

#include <vector>

class SigmaSpendBuilder : public TxBuilder
{
public:
    std::vector<CZerocoinEntryV3> selected;
    std::vector<CZerocoinEntryV3> changes;
    std::vector<sigma::CoinDenominationV3> denomChanges;

public:
    SigmaSpendBuilder(CWallet& wallet);
    ~SigmaSpendBuilder() override;

protected:
    CAmount GetInputs(std::vector<std::unique_ptr<InputSigner>>& signers, CAmount required) override;
    CAmount GetChanges(std::vector<CTxOut>& outputs, CAmount amount) override;
};

#endif
