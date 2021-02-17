#ifndef FIRO_WALLET_LELANTUSJOINSPLITBUILDER_H
#define FIRO_WALLET_LELANTUSJOINSPLITBUILDER_H

#include "wallet.h"

#include "../amount.h"
#include "../script/script.h"
#include "../primitives/transaction.h"

#include "../hdmint/wallet.h"


class LelantusJoinSplitBuilder {
public:
    LelantusJoinSplitBuilder(CWallet& wallet, CHDMintWallet& mintWallet, const CCoinControl *coinControl = nullptr);
    ~LelantusJoinSplitBuilder();

    CWalletTx Build(
        const std::vector<CRecipient>& recipients,
        CAmount &fee,
        const std::vector<CAmount>& newMintss,
        std::function<void(CTxOut & , LelantusJoinSplitBuilder const &)> outModifier = nullptr);

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
    CAmount fee = 0;

private:
    CHDMintWallet& mintWallet;
};


#endif //FIRO_WALLET_LELANTUSJOINSPLITBUILDER_H
