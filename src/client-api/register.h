// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_APIREGISTER_H
#define BITCOIN_APIREGISTER_H

/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/client-api/ */
class CAPITable;

/** Register misc API commands */
void RegisterMiscAPICommands(CAPITable &tableAPI);

/** Register wallet API commands */
void RegisterWalletAPICommands(CAPITable &tableAPI);

/** Register blockchain API commands */
void RegisterBlockchainAPICommands(CAPITable &tableAPI);

/** Register send API commands */
void RegisterSendAPICommands(CAPITable &tableAPI);

/** Register znode API commands */
void RegisterZnodeAPICommands(CAPITable &tableAPI);

/** Register zerocoin API commands */
void RegisterZerocoinAPICommands(CAPITable &tableAPI);

static inline void RegisterAllCoreAPICommands(CAPITable &tableAPI)
{
    RegisterMiscAPICommands(tableAPI);
    RegisterWalletAPICommands(tableAPI);
    RegisterBlockchainAPICommands(tableAPI);
    RegisterSendAPICommands(tableAPI);
    RegisterZnodeAPICommands(tableAPI);
    RegisterZerocoinAPICommands(tableAPI);
}

#endif
