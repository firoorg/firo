// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RPCWALLET_H
#define BITCOIN_WALLET_RPCWALLET_H

extern int64_t nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

class CRPCTable;

void RegisterWalletRPCCommands(CRPCTable &tableRPC);

bool EnsureWalletIsAvailable(bool avoidException);

void EnsureWalletIsUnlocked();

vector<string> GetMyAccountNames();

#endif //BITCOIN_WALLET_RPCWALLET_H
