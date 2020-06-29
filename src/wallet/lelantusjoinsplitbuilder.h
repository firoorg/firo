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

private:
    void GenerateMints(const std::vector<CAmount>& newMints, const CAmount& changeToMint, std::vector<lelantus::PrivateCoin>& Cout, std::vector<CTxOut>& outputs);
    void CreateJoinSplit(
            const uint256& txHash,
            const std::vector<lelantus::PrivateCoin>& Cout,
            const uint64_t& Vout,
            const uint64_t& fee,
            CMutableTransaction& tx);

public:
    std::vector<CLelantusEntry> spendCoins;
    std::vector<CSigmaEntry> sigmaSpendCoins;
    std::vector<CHDMint>  mintCoins;

    CWallet& wallet;
    const CCoinControl *coinControl;

    bool isSigmaToLelantusJoinSplit = false;

private:
    CHDMintWallet& mintWallet;
};


#endif //ZCOIN_WALLET_LELANTUSJOINSPLITBUILDER_H
