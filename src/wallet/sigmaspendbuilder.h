#ifndef FIRO_WALLET_SIGMASPENDBUILDER_H
#define FIRO_WALLET_SIGMASPENDBUILDER_H

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
    SigmaSpendBuilder(CWallet& walletParam, CHDMintWallet& mintWallet, const CCoinControl *coinControlParam = nullptr);
    ~SigmaSpendBuilder() override;

protected:
    CAmount GetInputs(std::vector<std::unique_ptr<InputSigner>>& signers, CAmount required) override;
    // remint change
    CAmount GetChanges(std::vector<CTxOut>& outputs, CAmount amount, CWalletDB& walletdb) override;

private:
    CHDMintWallet& mintWallet;
};

#endif
