#ifndef ZCOIN_WALLET_TXBUILDER_H
#define ZCOIN_WALLET_TXBUILDER_H

#include "wallet.h"

#include "../amount.h"
#include "../script/script.h"
#include "../primitives/transaction.h"
#include "../uint256.h"

#include <memory>
#include <vector>

#include <inttypes.h>

class InputSigner
{
public:
    COutPoint output;
    uint32_t sequence;

public:
    virtual ~InputSigner() {}

    virtual CScript Sign(const CMutableTransaction& tx, const uint256& sig) = 0;
};

class TxBuilder
{
public:
    CWallet& wallet;

public:
    TxBuilder(CWallet& wallet) noexcept;
    virtual ~TxBuilder();

    CWalletTx Build(const std::vector<CRecipient>& recipients, CAmount& fee);

protected:
    virtual CAmount GetInputs(std::vector<std::unique_ptr<InputSigner>>& signers, CAmount required) = 0;
    virtual CAmount GetChanges(std::vector<CTxOut>& outputs, CAmount amount) = 0;
    virtual CAmount AdjustFee(CAmount needed, unsigned txSize);
};

#endif
