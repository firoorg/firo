// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RPCWALLET_H
#define BITCOIN_WALLET_RPCWALLET_H

#include "base58.h"

extern int64_t nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

class CRPCTable;
class JSONRPCRequest;

void RegisterWalletRPCCommands(CRPCTable &t);

CBitcoinAddress GetAccountAddress(CWallet * const pwallet, string strAccount, bool bForceNew=false);

vector<string> GetMyAccountNames();
/**
 * Figures out what wallet, if any, to use for a JSONRPCRequest.
 *
 * @param[in] request JSONRPCRequest that wishes to access a wallet
 * @return NULL if no wallet should be used, or a pointer to the CWallet
 */
CWallet *GetWalletForJSONRPCRequest(const JSONRPCRequest&);

std::string HelpRequiringPassphrase(CWallet *);
void EnsureWalletIsUnlocked(CWallet *);
bool EnsureWalletIsAvailable(CWallet *, bool avoidException);

#endif //BITCOIN_WALLET_RPCWALLET_H
