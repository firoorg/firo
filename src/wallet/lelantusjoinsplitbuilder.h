#ifndef ZCOIN_WALLET_LELANTUSJOINSPLITBUILDER_H
#define ZCOIN_WALLET_LELANTUSJOINSPLITBUILDER_H

#include "wallet.h"

#include "../amount.h"
#include "../script/script.h"
#include "../primitives/transaction.h"

#include "../hdmint/wallet.h"


class LelantusJoinSplitBuilder {
public:
    LelantusJoinSplitBuilder(CWallet& wallet, CHDMintWallet& mintWallet, const CCoinControl *coinControl = nullptr);
    ~LelantusJoinSplitBuilder();

    CWalletTx Build(const std::vector<CRecipient>& recipients, const std::vector<CAmount>& newMints);

public:
    std::vector<CLelantusEntry> spendCoins;
    std::vector<CHDMint>  mintCoins;

    CWallet& wallet;
    const CCoinControl *coinControl;

private:
    CHDMintWallet& mintWallet;
};


#endif //ZCOIN_WALLET_LELANTUSJOINSPLITBUILDER_H
