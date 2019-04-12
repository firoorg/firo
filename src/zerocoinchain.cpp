// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zerocoinchain.h"
#include "main.h"
#include "init.h"
#include "txdb.h"
#include "ui_interface.h"
#include "zerocoin.h"
#include "wallet/wallet.h"

// 6 comes from OPCODE (1) + vch.size() (1) + BIGNUM size (4)
#define SCRIPT_OFFSET 6
// For Script size (BIGNUM/Uint256 size)
#define BIGNUM_SIZE   4

bool IsSerialInBlockchain(const CBigNum& bnSerial, int& nHeightTx)
{
    uint256 txHash;
    txHash.SetNull();
    // if not in zerocoinState then its not in the blockchain
    if (!CZerocoinState::GetZerocoinState()->IsUsedCoinSerial(bnSerial))
        return false;

    return IsTransactionInChain(txHash, nHeightTx);
}

bool IsSerialInBlockchain(const uint256& hashSerial, int& nHeightTx, uint256& txidSpend, CTransaction& tx)
{
    txidSpend.SetNull();
    CMintMeta mMeta;
    Bignum bnSerial;
    if (!CZerocoinState::GetZerocoinState()->IsUsedCoinSerialHash(bnSerial, hashSerial))
        return false;

    if(!pwalletMain->zerocoinTracker->Get(hashSerial, mMeta))
        return false;

    txidSpend = mMeta.txid;

    return IsTransactionInChain(txidSpend, nHeightTx, tx);
}

bool TxOutToPublicCoin(const CTxOut& txout, libzerocoin::PublicCoin& pubCoin, CValidationState& state)
{
    CBigNum publicZerocoin;
    vector<unsigned char> vchZeroMint;
    vchZeroMint.insert(vchZeroMint.end(), txout.scriptPubKey.begin() + SCRIPT_OFFSET,
                       txout.scriptPubKey.begin() + txout.scriptPubKey.size());
    publicZerocoin.setvch(vchZeroMint);

    libzerocoin::CoinDenomination denomination = libzerocoin::AmountToZerocoinDenomination(txout.nValue);
    LogPrint("zero", "%s ZCPRINT denomination %d pubcoin %s\n", __func__, denomination, publicZerocoin.GetHex());
    if (denomination == libzerocoin::ZQ_ERROR)
        return state.DoS(100, error("TxOutToPublicCoin : txout.nValue is not correct"));

    libzerocoin::PublicCoin checkPubCoin(ZCParamsV2, publicZerocoin, denomination);
    pubCoin = checkPubCoin;

    return true;
}
