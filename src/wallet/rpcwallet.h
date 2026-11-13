// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RPCWALLET_H
#define BITCOIN_WALLET_RPCWALLET_H

#include <string>
#include <utility>
#include <vector>

class CRPCTable;
class CWallet;
class JSONRPCRequest;
class UniValue;
struct CRecipient;
namespace spark { struct OutputCoinData; }

void RegisterWalletRPCCommands(CRPCTable &t);

/**
 * Figures out what wallet, if any, to use for a JSONRPCRequest.
 *
 * @param[in] request JSONRPCRequest that wishes to access a wallet
 * @return NULL if no wallet should be used, or a pointer to the CWallet
 */
CWallet *GetWalletForJSONRPCRequest(const JSONRPCRequest& request);

std::string HelpRequiringPassphrase(CWallet *);
void EnsureWalletIsUnlocked(CWallet *);
bool EnsureWalletIsAvailable(CWallet *, bool avoidException);
void EnsureSparkWalletIsAvailable();

/**
 * Parse the recipients argument of the Spark spend RPCs: an object, or a string
 * holding one, that maps each address to its amount, memo and subtractFee flag.
 * @param[out] recipients Transparent recipients.
 * @param[out] privateRecipients Spark recipients and whether each pays the fee.
 */
void ParseSparkSpendRecipients(
        const UniValue& value,
        std::vector<CRecipient>& recipients,
        std::vector<std::pair<spark::OutputCoinData, bool>>& privateRecipients);

#endif //BITCOIN_WALLET_RPCWALLET_H
