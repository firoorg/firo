// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef FIRO_WALLET_SPARKSPENDBATCH_H
#define FIRO_WALLET_SPARKSPENDBATCH_H

#include "amount.h"
#include "wallet/coincontrol.h"
#include "wallet/wallet.h"

#include <vector>

namespace sparkspendbatch {

constexpr size_t MAX_SINGLE_INPUT_SPARK_TRANSACTIONS = 50;

std::vector<CWalletTx> SpendAndStoreSingleInputBatches(
    CWallet& wallet,
    const std::vector<CRecipient>& recipients,
    const std::vector<std::pair<spark::OutputCoinData, bool>>& privateRecipients,
    CAmount& totalFee,
    const CCoinControl* coinControl = nullptr);

} // namespace sparkspendbatch

#endif // FIRO_WALLET_SPARKSPENDBATCH_H
