// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "hdmint/chain.h"
#include "main.h"
#include "init.h"
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
    if (!CZerocoinStateV3::GetZerocoinState()->IsUsedCoinSerial(bnSerial))
        return false;

    return IsTransactionInChain(txHash, nHeightTx);
}

bool IsSerialInBlockchain(const uint256& hashSerial, int& nHeightTx, uint256& txidSpend, CTransaction& tx)
{
    txidSpend.SetNull();
    CMintMeta mMeta;
    Scalar bnSerial;
    if (!CZerocoinStateV3::GetZerocoinState()->IsUsedCoinSerialHash(bnSerial, hashSerial))
        return false;

    if(!pwalletMain->hdMintTracker->Get(hashSerial, mMeta))
        return false;

    txidSpend = mMeta.txid;

    return IsTransactionInChain(txidSpend, nHeightTx, tx);
}

bool TxOutToPublicCoin(const CTxOut& txout, sigma::PublicCoinV3& pubCoin, CValidationState& state)
{
    // If you wonder why +1, go to file wallet.cpp and read the comments in function
    // CWallet::CreateZerocoinMintModelV3 around "scriptSerializedCoin << OP_ZEROCOINMINTV3";
    vector<unsigned char> coin_serialised(txout.scriptPubKey.begin() + 1,
                                          txout.scriptPubKey.end());
    secp_primitives::GroupElement publicZerocoin;
    publicZerocoin.deserialize(&coin_serialised[0]);

    sigma::CoinDenominationV3 denomination;
    IntegerToDenomination(txout.nValue, denomination);
    LogPrint("zero", "%s ZCPRINT denomination %d pubcoin %s\n", __func__, denomination, publicZerocoin.GetHex());
    if (denomination == CoinDenominationV3::SIGMA_ERROR)
        return state.DoS(100, error("TxOutToPublicCoin : txout.nValue is not correct"));

    sigma::PublicCoinV3 checkPubCoin(publicZerocoin, denomination);
    pubCoin = checkPubCoin;

    return true;
}
