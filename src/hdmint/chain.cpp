// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "hdmint/chain.h"
#include "main.h"
#include "txdb.h"
#include "ui_interface.h"
#include "zerocoin_v3.h"
#include "wallet/wallet.h"
#include "sigma/coin.h"

// 6 comes from OPCODE (1) + vch.size() (1) + BIGNUM size (4)
#define SCRIPT_OFFSET 6
// For Script size (BIGNUM/Uint256 size)
#define BIGNUM_SIZE   4

bool IsSerialInBlockchain(const Scalar& bnSerial, int& nHeightTx)
{
    uint256 txHash;
    txHash.SetNull();
    // if not in zerocoinState then its not in the blockchain
    
    if (!sigma::CSigmaState::GetState()->IsUsedCoinSerial(bnSerial))
        return false;

    return IsTransactionInChain(txHash, nHeightTx);
}

