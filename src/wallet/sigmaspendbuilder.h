#ifndef ZCOIN_WALLET_SIGMASPENDBUILDER_H
#define ZCOIN_WALLET_SIGMASPENDBUILDER_H

#include "txbuilder.h"

#include "../hdmint/wallet.h"

#include <vector>

class SigmaSpendBuilder : public TxBuilder
{
public:
    std::vector<CSigmaEntry> selected;
    std::vector<CHDMint> changes;
    std::vector<sigma::CoinDenomination> denomChanges;

public:
    SigmaSpendBuilder(CWallet& wallet, CHDMintWallet& mintWallet, const CCoinControl *coinControl = nullptr);
    ~SigmaSpendBuilder() override;

protected:
    CAmount GetInputs(std::vector<std::unique_ptr<InputSigner>>& signers, CAmount required) override;
    // remint change
    CAmount GetChanges(std::vector<CTxOut>& outputs, CAmount amount) override;

private:
    CHDMintWallet& mintWallet;
};

#endif
